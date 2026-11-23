from app.parser import parse_files
from app.main import parse_repo
from fastapi import HTTPException

def test_npm_lock():
    comps, edges, warnings, manifests = parse_files({'package-lock.json':'{"lockfileVersion":3,"packages":{"":{"dependencies":{"foo":"^1"}},"node_modules/foo":{"version":"1.2.3"}}}'})
    assert len(comps) == 1 and comps[0]['version'] == '1.2.3' and comps[0]['direct']

def test_unpinned_is_not_resolved():
    comps, _, warnings, _ = parse_files({'package.json':'{"dependencies":{"foo":"^1.0"}}'})
    assert comps[0]['version'] == '' and warnings

def test_python_pins():
    comps, _, _, _ = parse_files({'requirements.txt':'requests==2.31.0\nflask>=2\n'})
    assert next(c for c in comps if c['name']=='requests')['version'] == '2.31.0'
    assert next(c for c in comps if c['name']=='flask')['version'] == ''

def test_repo_validation():
    assert parse_repo('https://github.com/expressjs/express') == ('expressjs','express')
    try: parse_repo('https://example.com/evil')
    except HTTPException: pass
    else: assert False
