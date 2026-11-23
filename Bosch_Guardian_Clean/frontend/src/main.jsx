import React, {useEffect, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {ShieldCheck, Search, GitBranch, AlertTriangle, LoaderCircle, ChevronRight, LayoutDashboard, FlaskConical} from 'lucide-react';
import {Badge, Results} from './results.jsx';
import './style.css';

const API = '/api';

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(API + path, options);
  } catch {
    throw Error('Cannot reach the backend. Start FastAPI on port 8000.');
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status})`);
  return data;
}

const STAGES = {queued: 'Queued', fetching: 'Fetching manifests from GitHub', preparing: 'Preparing lockfiles',
  scanning: 'Running Guardian scanners (SBOM, Grype, OSV, detectors)'};

function useScan(scanId, onError) {
  const [status, setStatus] = useState(null);
  const [result, setResult] = useState(null);
  const [graph, setGraph] = useState(null);
  useEffect(() => {
    if (!scanId) return undefined;
    let cancelled = false;
    let timer;
    async function poll() {
      try {
        const s = await request(`/scan/${scanId}`);
        if (cancelled) return;
        setStatus(s);
        if (s.status === 'running') { timer = setTimeout(poll, 2000); return; }
        const [r, g] = await Promise.all([request(`/scan/${scanId}/result`).catch(() => null),
          request(`/scan/${scanId}/graph`).catch(() => null)]);
        if (cancelled) return;
        if (r) { setResult(r); setGraph(g); } else onError(s.error || 'Scan failed without results');
      } catch (e) { if (!cancelled) onError(e.message); }
    }
    poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [scanId]);
  return {status, result, graph, reset: () => { setStatus(null); setResult(null); setGraph(null); }};
}

function App() {
  const [url, setUrl] = useState('https://github.com/juice-shop/juice-shop');
  const [ref, setRef] = useState('');
  const [scanId, setScanId] = useState('');
  const [injectFake, setInjectFake] = useState(false);
  const [error, setError] = useState('');
  const [health, setHealth] = useState(false);
  const [ai, setAi] = useState('off');
  const {status, result, graph, reset} = useScan(scanId, setError);
  useEffect(() => { request('/health').then(h => { setHealth(true); setAi(h.ai || 'off'); }).catch(() => setHealth(false)); }, []);
  const busy = Boolean(scanId) && (!status || status.status === 'running');

  async function start(body) {
    setError(''); reset(); setScanId('');
    try {
      const started = await request('/scan', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({...body, inject_fake_claim: injectFake})});
      setScanId(started.scan_id);
    } catch (e) { setError(e.message); }
  }

  function scan(event) { event.preventDefault(); start({url, ref}); }

  return <div className="shell"><aside className="sidebar">
    <div className="brand"><div className="brandmark"><ShieldCheck size={23} strokeWidth={2.2}/></div><div><strong>Guardian</strong><span>SOFTWARE SECURITY</span></div></div>
    <div className="side-heading">WORKSPACE</div>
    <div className="nav-item active"><LayoutDashboard size={17}/> Repository analysis</div>
    <div className="side-bottom"><div className="server"><i className={health ? 'on' : ''}/>{health ? 'Backend connected' : 'Backend offline'}</div>
      {health && <div className="server"><i className={ai !== 'off' ? 'on' : ''}/>{ai !== 'off' ? `AI agents: ${ai}` : 'AI agents off (no key)'}</div>}
      <p>Scans run the team Guardian pipeline on the manifests fetched from GitHub.</p></div></aside>
    <main className="main"><header className="topbar"><div className="breadcrumbs">Workspace <ChevronRight size={14}/> <b>Repository analysis</b></div>
      <div className="top-right"><Badge tone="green">Local workspace</Badge></div></header>
      <div className="content">
        <div className="heading"><div><h1>Repository security, made clear.</h1>
          <p>Enter a public GitHub repository. Guardian fetches only dependency files, then runs its scan pipeline.</p></div></div>
        <section className="panel scan-panel"><form onSubmit={scan} className="scan-form">
          <label className="url-field">Repository URL<input required type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repository"/></label>
          <label className="ref-field">Branch, tag or commit <span>(optional)</span><input value={ref} onChange={e => setRef(e.target.value)} placeholder="Default branch"/></label>
          <button disabled={busy} className="primary" type="submit">{busy ? <LoaderCircle className="spin" size={17}/> : <Search size={17}/>} {busy ? 'Scanning…' : 'Scan repository'}</button>
        </form>
        <div className="demo-row"><button type="button" disabled={busy} className="outline" onClick={() => start({demo: true})}>
          <FlaskConical size={16}/> Scan the built-in demo app</button>
          <span>Local, deliberately vulnerable app with a synthetic malicious package. No network, nothing is installed or run.</span></div>
        <label className="option"><input type="checkbox" checked={injectFake} onChange={e => setInjectFake(e.target.checked)}/>
          Hallucination test: inject a fabricated CVE claim and show the validator rejecting it</label></section>
        {error && <div className="notice error"><AlertTriangle size={19}/><div><strong>Scan problem</strong><p>{error}</p></div><button onClick={() => setError('')} aria-label="Dismiss">×</button></div>}
        {busy && <div className="notice progress"><LoaderCircle className="spin" size={19}/><div><strong>Analyzing repository</strong><p>{STAGES[status?.stage] || 'Starting'}… this can take a few minutes.</p></div></div>}
        {result && status ? <Results scanId={scanId} status={status} result={result} graph={graph}/> :
          !busy && <section className="empty-panel"><div className="empty-illustration"><GitBranch size={30}/></div><h2>Start with a repository.</h2><p>Results show vulnerabilities with dependency paths, anomalies and detector coverage.</p></section>}
      </div></main></div>;
}

createRoot(document.getElementById('root')).render(<App/>);
