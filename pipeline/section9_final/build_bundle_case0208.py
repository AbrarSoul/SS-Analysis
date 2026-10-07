"""
Section 9 ground-truth test bundle: CASE-0208
(keylime/keylime, keylime/cloud_verifier_tornado.py notify_error,
CVE-2025-13609, CWE-694).

Core vulnerable mechanism: when the "agent" notifier is configured,
`notify_error` runs `session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()`
with no exception handling. `notify_error` is `await`ed directly (not
fire-and-forget) from three call sites inside `process_agent`'s revocation
handling. If the query raises (a transient DB error, a locked/corrupted
sqlite file, a lost connection -- exactly the kind of fault most likely
*during* an incident that is triggering a revocation notification in the
first place), the exception propagates out of `notify_error` uncaught,
aborting: (a) the webhook/zeromq notifications already sent are fine, but no
agent-to-agent notification happens for THIS call, and (b) whatever
`process_agent` was doing when it awaited `notify_error` is also aborted by
the same exception, so a single flaky query kills the entire agent-processing
task rather than just the agent-notification step. The upstream fix wraps the
query in try/except, logs, and returns early so the rest of the caller's
control flow is unaffected by a DB hiccup in this one notification path.

Verification: `notify_error` is extracted verbatim from each full file and
exec'd in a module namespace with stand-in `revocation_notifier`,
`cloud_verifier_common`, `config`, `VerfierMain`, `session_context`, `logger`,
and `_from_db_obj`/`web_util`/`invoke_notify_error` symbols (the real
`asyncio`, `functools`, `concurrent.futures.ThreadPoolExecutor` are used
as-is). `session_context()` is stubbed to yield a fake session whose
`.query(...)` raises `SQLAlchemyError("connection lost")`, with only the
"agent" notifier configured, and run with `asyncio.run`.

Every variant is the FULL real file. notify_error is called by name (via
`await notify_error(...)`) from three sites elsewhere in the file, so its name
and signature are never renamed; the renamed variant renames locals instead.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0208"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

s = original.index("async def notify_error(")
e = original.index("\n\nasync def process_agent(")
FUNC = original[s:e]
assert original.count(FUNC) == 1
assert original.count("await notify_error(") == 3


def build(new_func):
    assert new_func != FUNC
    return original[:s] + new_func + original[e:]


# --- Variant 1: renamed vulnerable variant ---
V1 = '''async def notify_error(
    agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None, timeout: float = 60.0
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        vid = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        with session_context() as db_session:
            agent_rows = db_session.query(VerfierMain).filter_by(verifier_id=vid).all()
            pending = []
            event_loop = asyncio.get_event_loop()
            # Notify all agents asynchronously through a thread pool
            with ThreadPoolExecutor() as executor:
                for row in agent_rows:
                    if row.agent_id != agent["agent_id"]:
                        agent = _from_db_obj(row)
                        if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                            agent["ssl_context"] = web_util.generate_agent_tls_context(
                                "verifier", agent["mtls_cert"], logger=logger
                            )
                    func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                    pending.append(await event_loop.run_in_executor(executor, func))
                # Wait for all tasks complete in 60 seconds
                try:
                    for f in asyncio.as_completed(pending, timeout=60):
                        await f
                except asyncio.TimeoutError as e:
                    logger.error("Timeout during notifying error to agents: %s", e)'''
v1 = build(V1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The query moves into a helper function, still with no exception handling.
V2 = '''def _fetch_agents_to_notify(verifier_id: str):
    with session_context() as session:
        return session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()


async def notify_error(
    agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None, timeout: float = 60.0
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        agents = _fetch_agents_to_notify(verifier_id)
        futures = []
        loop = asyncio.get_event_loop()
        # Notify all agents asynchronously through a thread pool
        with ThreadPoolExecutor() as pool:
            for agent_db_obj in agents:
                if agent_db_obj.agent_id != agent["agent_id"]:
                    agent = _from_db_obj(agent_db_obj)
                    if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                        agent["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent["mtls_cert"], logger=logger
                        )
                func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                futures.append(await loop.run_in_executor(pool, func))
            # Wait for all tasks complete in 60 seconds
            try:
                for f in asyncio.as_completed(futures, timeout=60):
                    await f
            except asyncio.TimeoutError as e:
                logger.error("Timeout during notifying error to agents: %s", e)'''
v2 = build(V2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The query is moved into a helper that returns None on failure (logging the
# error itself), and the caller checks for None -- upstream instead wraps the
# query inline in try/except at the original call site.
V3 = '''def _fetch_agents_to_notify(verifier_id: str) -> Optional[List[Any]]:
    try:
        with session_context() as session:
            return session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
    except Exception as e:
        logger.error("An issue happened querying the verifier for the list of agents to notify: %s", e)
        return None


async def notify_error(
    agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None, timeout: float = 60.0
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        agents = _fetch_agents_to_notify(verifier_id)
        if agents is None:
            return
        futures = []
        loop = asyncio.get_event_loop()
        # Notify all agents asynchronously through a thread pool
        with ThreadPoolExecutor() as pool:
            for agent_db_obj in agents:
                if agent_db_obj.agent_id != agent["agent_id"]:
                    agent = _from_db_obj(agent_db_obj)
                    if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                        agent["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent["mtls_cert"], logger=logger
                        )
                func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                futures.append(await loop.run_in_executor(pool, func))
            # Wait for all tasks complete in 60 seconds
            try:
                for f in asyncio.as_completed(futures, timeout=60):
                    await f
            except asyncio.TimeoutError as e:
                logger.error("Timeout during notifying error to agents: %s", e)'''
v3 = build(V3)
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign look-alike ---
BENIGN = '''"""Standalone example of the same shape as the fixed notify_error: wrap a
call that can fail in try/except, log, and return early -- for an unrelated,
non-persistence operation with no crash-propagation bug to introduce."""
import logging

logger = logging.getLogger("example")


def _format_summary(items):
    try:
        return ", ".join(str(i) for i in items)
    except Exception as e:
        logger.error("An issue happened formatting the summary: %s", e)
        return None


def print_summary(items):
    summary = _format_summary(items)
    if summary is None:
        return
    print(f"Summary: {summary}")
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
