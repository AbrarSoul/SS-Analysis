"""Execute the explicitly authorized allocation sequentially from run 2.

Run 1 is launched separately and must already pass the offline evidence audit.
This is not a partial-episode resume tool. Any error stops the allocation, with
all artifacts and consumed calls preserved. Credential values are never logged.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from audit_cd_pilot_20261014 import ALLOCATION, ROOT, read, sha, check_run

AUDIT = Path(__file__).parent
OUT = AUDIT / 'CD_Pilot_Allocation_20261014_v1'


def now():
    return datetime.now(timezone.utc).isoformat()


def event(kind, **fields):
    item = {'time_utc': now(), 'kind': kind, **fields}
    with (AUDIT / 'events.jsonl').open('a') as handle:
        handle.write(json.dumps(item) + '\n')
    print(json.dumps(item), flush=True)


def status(state, completed, **fields):
    value = read(OUT / 'Execution_Status.json')
    value.update(recorded_utc=now(), status=state, blocker=None,
                 runs_completed=len(completed), model_calls_consumed=sum(r['counts']['generation_calls'] for r in completed),
                 verified_run_orders=[r['order'] for r in completed], **fields)
    target = OUT / 'Execution_Status.json'
    temporary = OUT / 'Execution_Status.json.tmp'
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(target)


def main():
    allocation = read(ALLOCATION)
    assert len(allocation['runs']) == 12 and allocation['max_model_calls'] == 864
    assert read(OUT / 'Execution_Status.json')['authorized_max_model_calls'] == 864
    completed = [check_run(allocation['runs'][0], allocation)]
    checkpoints = OUT / 'checkpoints'
    checkpoints.mkdir(exist_ok=True)
    first_path = checkpoints / 'run_01.json'
    if first_path.exists():
        assert read(first_path) == completed[0]
    else:
        with first_path.open('x') as handle:
            json.dump(completed[0], handle, indent=2)
    env = os.environ.copy()
    env['GPTLAB_API_KEY'] = (Path.home() / '.config/ss-research/gptlab_api_key').read_text().strip()
    assert env['GPTLAB_API_KEY'] and env.get('OPENAI_API_KEY'), 'Required credential missing'
    for run in allocation['runs'][1:]:
        assert all(sha(ROOT / name) == value for name, value in allocation['input_sha256'].items()), 'Pinned input drift'
        folder = ROOT / run['output']
        assert not folder.exists(), 'Output already exists; automatic resume prohibited'
        console_path = OUT / f"run_{run['order']:02d}_launcher.log"
        status('AUTHORIZED_RUNNING', completed, active_run_order=run['order'])
        event('cd_pilot_run_launch', order=run['order'], model=run['model'], condition=run['condition'], repeat=run['repeat'])
        failure = None
        with console_path.open('x') as console:
            proc = subprocess.Popen(run['argv'], cwd=ROOT, env=env, stdout=console, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            last_progress = time.monotonic()
            while proc.poll() is None:
                time.sleep(1)
                captures = list(folder.glob('raw*/diagnostic/*.json'))
                for path in captures:
                    try:
                        captured = read(path)
                    except json.JSONDecodeError:
                        continue  # Writer has not closed this capture yet.
                    if captured.get('error'):
                        failure = {'reason': 'provider_error', 'capture': str(path.relative_to(ROOT)),
                                   'error_type': captured['error'].get('type')}
                        break
                if len(captures) > run['max_calls']:
                    failure = {'reason': 'call_budget_guard'}
                if failure:
                    # A following call may already be in flight. Do not erase its budget:
                    # record the uncertainty and require manual recovery accounting.
                    os.killpg(proc.pid, signal.SIGINT)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.wait(timeout=10)
                    break
                if time.monotonic() - last_progress >= 30:
                    event('cd_pilot_progress', order=run['order'], completed_episodes=len(list(folder.glob('CASE-*/episode.json'))),
                          recorded_calls=len(captures))
                    last_progress = time.monotonic()
        captures = list(folder.glob('raw*/diagnostic/*.json'))
        if failure or proc.returncode:
            status('AUTHORIZED_PAUSED_EXECUTION_ERROR', completed, active_run_order=run['order'],
                   active_run_recorded_calls=len(captures), possible_unrecorded_inflight_call=bool(failure),
                   execution_failure=failure or {'reason': 'nonzero_exit', 'exit_code': proc.returncode})
            event('cd_pilot_execution_paused', order=run['order'], recorded_calls=len(captures),
                  failure=failure, exit_code=proc.returncode)
            raise SystemExit(1)
        try:
            checked = check_run(run, allocation)
        except Exception as exc:
            status('AUTHORIZED_PAUSED_VERIFICATION_ERROR', completed, active_run_order=run['order'],
                   active_run_recorded_calls=len(captures), verification_error_type=type(exc).__name__)
            event('cd_pilot_verification_paused', order=run['order'], error_type=type(exc).__name__)
            raise
        with (checkpoints / f"run_{run['order']:02d}.json").open('x') as handle:
            json.dump(checked, handle, indent=2)
            handle.write('\n')
        completed.append(checked)
        assert sum(r['counts']['generation_calls'] for r in completed) <= 864
        status('AUTHORIZED_RUNNING', completed, active_run_order=None)
        event('cd_pilot_run_verified', order=run['order'], complete_success=checked['counts']['iterative_complete_success'],
              generation_calls=checked['counts']['generation_calls'])
    status('COMPLETED_VERIFIED', completed, active_run_order=None)
    event('cd_pilot_execution_completed', runs=12, model_calls=sum(r['counts']['generation_calls'] for r in completed))


if __name__ == '__main__':
    main()
