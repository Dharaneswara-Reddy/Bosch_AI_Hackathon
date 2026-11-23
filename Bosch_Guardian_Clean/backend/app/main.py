"""Bosch Guardian API. Public GitHub repositories only; advisory matches are not exploitability proof."""
import asyncio
import json
import os
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from .parser import parse_files, SUPPORTED

app = FastAPI(title='Bosch Guardian API', version='0.2.0')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'], allow_methods=['GET','POST'], allow_headers=['*'])
SCANS = {}
MAX_FILES = 80
MAX_BYTES = 1_500_000

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=400)
    ref: str = Field(default='', max_length=120)
    check_vulnerabilities: bool = True

def parse_repo(url):
    u = urlparse(url.strip())
    if u.scheme != 'https' or u.hostname != 'github.com' or u.port or u.username or u.password or u.query or u.fragment:
        raise HTTPException(422, 'Enter a public https://github.com/owner/repository URL')
    parts = [p for p in u.path.strip('/').split('/') if p]
    if len(parts) != 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) for p in parts):
        raise HTTPException(422, 'Use a repository URL without a subpath')
    return parts[0], parts[1].removesuffix('.git')

async def github_json(client, url):
    response = await client.get(url)
    if response.status_code == 404: raise ValueError('Repository or ref not found, or repository is private')
    if response.status_code in (403, 429): raise ValueError('GitHub API rate limit reached; try again later or set GITHUB_TOKEN')
    response.raise_for_status()
    return response.json()

async def fetch_repo(owner, repo, ref):
    headers = {'Accept':'application/vnd.github+json', 'User-Agent':'Bosch-Guardian-educational-scanner'}
    if os.getenv('GITHUB_TOKEN'): headers['Authorization'] = f'Bearer {os.environ["GITHUB_TOKEN"]}'
    async with httpx.AsyncClient(timeout=25, headers=headers, follow_redirects=False) as client:
        metadata = await github_json(client, f'https://api.github.com/repos/{owner}/{repo}')
        if metadata.get('private'): raise ValueError('Private repositories are not supported')
        chosen = ref or metadata['default_branch']
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', chosen) or '..' in chosen or chosen.startswith(('/', '-')):
            raise ValueError('Invalid Git ref')
        commit = await github_json(client, f'https://api.github.com/repos/{owner}/{repo}/commits/{chosen}')
        sha = commit['sha']
        tree = await github_json(client, f'https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}?recursive=1')
        if tree.get('truncated'): raise ValueError('Repository tree was truncated by GitHub; cannot claim complete inventory')
        paths = [item['path'] for item in tree.get('tree', []) if item.get('type') == 'blob' and item['path'].rsplit('/',1)[-1] in SUPPORTED and item.get('size', 0) <= MAX_BYTES]
        if len(paths) > MAX_FILES: raise ValueError(f'Too many manifests ({len(paths)}); maximum supported is {MAX_FILES}')
        async def get_file(path):
            # Only retrieve known manifest paths from the pinned Git tree, never arbitrary user-supplied URLs.
            from urllib.parse import quote
            encoded = quote(path, safe='/')
            r = await client.get(f'https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{encoded}')
            r.raise_for_status()
            if len(r.content) > MAX_BYTES: raise ValueError(f'{path} exceeds size limit')
            return path, r.text
        pairs = await asyncio.gather(*(get_file(path) for path in paths))
        return sha, dict(pairs)

async def query_osv(components):
    eligible = [c for c in components if c['version'] and c['ecosystem'] in ('npm','PyPI')]
    if not eligible: return [], []
    # OSV batch API returns vulnerability IDs; fetch individual records for severity/fixed version details.
    queries = [{'package':{'name':c['name'], 'ecosystem':c['ecosystem']}, 'version':c['version']} for c in eligible]
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post('https://api.osv.dev/v1/querybatch', json={'queries':queries})
            response.raise_for_status()
            rows = response.json().get('results', [])
            findings = []
            for c, row in zip(eligible, rows):
                for v in row.get('vulns', []):
                    findings.append({'package_id':c['id'], 'package':c['name'], 'version':c['version'], 'osv_id':v['id'], 'modified':v.get('modified'), 'source':'OSV', 'status':'advisory_match'})
            return findings, []
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return [], [f'OSV lookup failed ({type(exc).__name__}); vulnerability status is unknown, not safe']

async def run_scan(scan_id, owner, repo, ref, check_vulnerabilities):
    s = SCANS[scan_id]
    try:
        sha, files = await fetch_repo(owner, repo, ref)
        components, edges, warnings, manifests = parse_files(files)
        s.update(commit_sha=sha, components=components, edges=edges, warnings=warnings, manifests=manifests)
        findings, osv_warnings = await query_osv(components) if check_vulnerabilities else ([], ['OSV lookup disabled; vulnerability status unknown'])
        s['findings'] = findings
        s['warnings'].extend(osv_warnings)
        s['vulnerability_status'] = 'checked' if check_vulnerabilities and not osv_warnings else 'unknown'
        s['status'] = 'complete'
    except Exception as exc:
        s['status'] = 'failed'
        s['error'] = str(exc)[:400]

@app.get('/health')
def health(): return {'status':'ok','service':'bosch-guardian'}

@app.post('/scan', status_code=202)
async def start_scan(req: ScanRequest):
    owner, repo = parse_repo(req.url)
    scan_id = uuid.uuid4().hex
    SCANS[scan_id] = {'scan_id':scan_id, 'status':'running', 'repository_url':f'https://github.com/{owner}/{repo}', 'commit_sha':'', 'components':[], 'edges':[], 'findings':[], 'warnings':[], 'manifests':[], 'vulnerability_status':'unknown', 'error':None, 'created_at':datetime.now(timezone.utc).isoformat()}
    asyncio.create_task(run_scan(scan_id, owner, repo, req.ref, req.check_vulnerabilities))
    return {'scan_id':scan_id, 'status':'running'}

def get_scan(scan_id):
    if scan_id not in SCANS: raise HTTPException(404, 'Scan not found; scans are stored in memory and reset on server restart')
    return SCANS[scan_id]

@app.get('/scan/{scan_id}')
def scan_status(scan_id: str):
    s = get_scan(scan_id)
    return {k:s[k] for k in ('scan_id','status','repository_url','commit_sha','error','created_at','vulnerability_status')}

@app.get('/scan/{scan_id}/inventory')
def inventory(scan_id: str):
    s = get_scan(scan_id)
    if s['status'] != 'complete': raise HTTPException(409, 'Scan is not complete')
    return {k:s[k] for k in ('repository_url','commit_sha','components','edges','warnings','manifests','findings','vulnerability_status')}

@app.get('/scan/{scan_id}/graph')
def graph(scan_id: str):
    s = get_scan(scan_id)
    if s['status'] != 'complete': raise HTTPException(409, 'Scan is not complete')
    return {'nodes':[{'id':c['id'], 'label':c['name'], 'version':c['version'], 'direct':c['direct']} for c in s['components']], 'edges':s['edges']}

@app.get('/scan/{scan_id}/sbom')
def sbom(scan_id: str):
    s = get_scan(scan_id)
    if s['status'] != 'complete': raise HTTPException(409, 'Scan is not complete')
    components = [{'type':'library','name':c['name'], **({'version':c['version']} if c['version'] else {}), 'bom-ref':c['id'], 'purl':c['purl']} for c in s['components']]
    dependencies = [{'ref':c['id'], 'dependsOn':[e['target'] for e in s['edges'] if e['source'] == c['id']]} for c in s['components']]
    return JSONResponse({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'component':{'type':'application','name':s['repository_url']},'properties':[{'name':'guardian:commit','value':s['commit_sha']}]},'components':components,'dependencies':dependencies}, headers={'Content-Disposition':'attachment; filename="sbom.json"'})

@app.get('/scan/{scan_id}/recommendations')
def recommendations(scan_id: str):
    s = get_scan(scan_id)
    if s['status'] != 'complete': raise HTTPException(409, 'Scan is not complete')
    # Deliberately not claiming LLM agent or automated safe upgrades.
    return {'mode':'evidence_based_rules', 'agent_enabled':False, 'recommendations':[
        {'title':f'Review {f["package"]} advisory {f["osv_id"]}', 'reason':'OSV reports a vulnerability match for the resolved package version', 'action':'Review the advisory, identify a patched version, test dependency resolution and regression tests before upgrading', 'evidence':f['osv_id']}
        for f in s['findings'][:30]], 'limitations':['No reachability analysis','No autonomous upgrade execution','No LLM agent is enabled in this build']}
