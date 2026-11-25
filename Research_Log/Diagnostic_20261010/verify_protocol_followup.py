"""Read-only source-review evidence and network-free CASE-0222 reproduction.

Prints diffs of the eleven newly reviewed restructuring variants and captures
Requests' final send settings using the actual request expression/helper ASTs.
No benchmark code is edited and Session.send is mocked: no network requests occur.
"""
import ast
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).parent
CASES = ['0323', '0276', '0221', '0136', '0340', '0124', '0222', '0171', '0298', '0231', '0081']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    hashes, diffs = {}, {}
    for case in CASES:
        folder = ROOT / 'benchmark/cases' / ('CASE-' + case)
        a, b = next(folder.glob('vulnerable_source.*')), next(folder.glob('variant_vulnerable_02.*'))
        diffs[case] = ''.join(difflib.unified_diff(
            a.read_text().splitlines(True), b.read_text().splitlines(True),
            fromfile=str(a.relative_to(ROOT)), tofile=str(b.relative_to(ROOT))))
        for p in [a, b]:
            hashes[str(p.relative_to(ROOT))] = sha(p)

    folder = ROOT / 'benchmark/cases/CASE-0222'
    original = ast.parse((folder / 'vulnerable_source.py').read_text())
    variant = ast.parse((folder / 'variant_vulnerable_02.py').read_text())
    calls = [n for n in ast.walk(original) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
             and n.func.value.id == 'requests' and n.func.attr == 'post'
             and any(k.arg == 'verify' and isinstance(k.value, ast.Constant)
                     and k.value.value is False for k in n.keywords)]
    assert len(calls) == 1
    helper = next(n for n in ast.walk(variant) if isinstance(n, ast.FunctionDef) and n.name == '_post_login')
    namespace = {'requests': requests}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), '<retained CASE-0222 helper>', 'exec'), namespace)
    original_code = compile(ast.Expression(body=calls[0]), '<retained CASE-0222 expression>', 'eval')
    bindings = {'self': SimpleNamespace(base_url='https://example.invalid'),
                'headers': {'Content-Type': 'application/json'}, 'data': '{}', 'requests': requests}
    scenarios = []
    for env_key in [None, 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE']:
        captured = []

        def fake_send(session, request, **kwargs):
            captured.append({'verify': kwargs['verify'], 'url': request.url,
                             'method': request.method, 'body': request.body})
            return object()

        # This path is only a marker: send is mocked, so no certificate file is read.
        env = {} if env_key is None else {env_key: '/review/fake-ca-bundle.pem'}
        with patch.dict(os.environ, env, clear=True), patch.object(requests.Session, 'send', fake_send):
            eval(original_code, bindings)
            namespace['_post_login'](bindings['self'], bindings['headers'], bindings['data'])
        assert len(captured) == 2 and captured[0]['verify'] is False
        assert captured[1]['verify'] == (False if env_key is None else '/review/fake-ca-bundle.pem')
        assert all(captured[0][k] == captured[1][k] for k in ['url', 'method', 'body'])
        scenarios.append({'environment_override': env_key, 'original': captured[0], 'variant': captured[1]})

    for p in [AUDIT / 'Controlled_2x2_Protocol_Draft_20261012.md',
              AUDIT / 'Bounded_Investigation_Tracking.md', ROOT / 'Research_Log/Correction_Log.md',
              ROOT / 'pipeline/diagnostic_v2.py', ROOT / 'pipeline/typed_rule.py',
              ROOT / 'pipeline/tests/test_typed_rule.py',
              ROOT / 'pipeline/tests/test_diagnostic_regressions.py', Path(__file__)]:
        hashes[str(p.relative_to(ROOT))] = sha(p)
    print(json.dumps({'time_utc': datetime.now(timezone.utc).isoformat(),
                      'requests_version': requests.__version__, 'source_diffs': diffs,
                      'case_0222_send_settings': scenarios, 'reviewed_sha256': hashes,
                      'model_calls': 0, 'semgrep_scans': 0, 'network_requests': 0}, indent=2))


if __name__ == '__main__':
    main()
