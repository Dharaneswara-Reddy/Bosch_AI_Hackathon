import React, {useMemo, useState} from 'react';
import {ReactFlow, Background, Controls, MiniMap, MarkerType} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {Download, ExternalLink, FileText} from 'lucide-react';

const API = '/api';
const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];
const RISK_TONE = {critical: 'red', high: 'red', medium: 'amber', low: 'green', unknown: 'neutral'};

export function Badge({children, tone = 'neutral'}) {
  return <span className={'badge ' + tone}>{children}</span>;
}

function componentLabel(componentId, nodes) {
  const node = nodes.get(componentId);
  return node ? `${node.name}@${node.version}` : componentId;
}

function EvidenceLink({finding, evidence}) {
  const first = finding.evidence_ids.map(id => evidence.get(id)).find(Boolean);
  if (!first) return <span>none</span>;
  const text = `${first.file}${first.pointer ? ' ' + first.pointer : ''}`;
  if (!first.url) return <code>{text}</code>;
  return <a href={first.url} target="_blank" rel="noreferrer">{text} <ExternalLink size={12}/></a>;
}

const RELEVANCE_ORDER = {relevant: 0, likely_relevant: 1, unknown: 2, low_relevance: 3};
const RELEVANCE_TONE = {relevant: 'red', likely_relevant: 'amber', unknown: 'neutral', low_relevance: 'green'};
const RISK_RANK = {critical: 0, high: 1, medium: 2, low: 3, unknown: 4};

function relevanceRank(f) {
  return f.relevance ? RELEVANCE_ORDER[f.relevance.verdict] : 4;
}

export function rankFindings(findings) {
  return [...findings].sort((a, b) => relevanceRank(a) - relevanceRank(b)
    || (RISK_RANK[a.risk_level] ?? 4) - (RISK_RANK[b.risk_level] ?? 4)
    || a.finding_id.localeCompare(b.finding_id));
}

function signal(f, name) {
  return f.relevance?.signals.find(s => s.name === name)?.value || 'unknown';
}

function RelevanceBadge({finding}) {
  const verdict = finding.relevance?.verdict || 'unknown';
  return <Badge tone={RELEVANCE_TONE[verdict]}>{verdict.replace('_', ' ')}</Badge>;
}

function SignalsRow({finding, onShowPath}) {
  const r = finding.relevance;
  return <tr className="signals-row"><td colSpan={8}>
    {r ? <><p className="signals-summary">{r.summary}</p>
      <table className="signals"><tbody>{r.signals.map(s => <tr key={s.name}>
        <th>{s.name.replaceAll('_', ' ')}</th><td><strong>{s.value}</strong></td><td>{s.detail}</td>
        <td><code>{s.evidence_ids.map(id => id.slice(0, 10)).join(', ')}</code></td></tr>)}</tbody></table></>
      : <p className="signals-summary">Relevance was not assessed for this finding.</p>}
    {finding.dependency_path.length > 0 &&
      <button className="outline small" onClick={() => onShowPath(finding)}>Show this path in the dependency graph</button>}
  </td></tr>;
}

function FindingsTable({findings, evidence, nodes, selectedId, onSelect, onShowPath}) {
  if (!findings.length) {
    return <div className="empty-state"><strong>No vulnerability findings reported</strong>
      <p>This is not proof the repository is safe. Check the coverage tab for gaps.</p></div>;
  }
  return <div className="table-scroll"><p className="footnote">Ranked by relevance, then risk. Click a row to see why.</p>
    <table><thead><tr>
    <th>RELEVANCE</th><th>ADVISORY</th><th>PACKAGE</th><th>INTRODUCED BY</th><th>RISK</th>
    <th>REACHABILITY · SCOPE</th><th>FIXED IN</th><th>DEPENDENCY PATH</th></tr></thead><tbody>
    {rankFindings(findings).map(f => <React.Fragment key={f.finding_id}>
      <tr className={'clickable' + (selectedId === f.finding_id ? ' selected-row' : '')} onClick={() => onSelect(selectedId === f.finding_id ? null : f.finding_id)}>
        <td><RelevanceBadge finding={f}/></td>
        <td><strong>{f.advisory_id}</strong><br/><EvidenceLink finding={f} evidence={evidence}/></td>
        <td><code>{componentLabel(f.component_id, nodes) === f.component_id ? f.purl : componentLabel(f.component_id, nodes)}</code></td>
        <td>{f.relevance?.introduced_by || 'unknown'}</td>
        <td><Badge tone={RISK_TONE[f.risk_level]}>{f.risk_level}</Badge> <small>{f.risk_rule_id}</small></td>
        <td>{signal(f, 'reachability')} · {signal(f, 'dependency_scope')}</td>
        <td>{f.fixed_versions.join(', ') || 'unknown'}</td>
        <td className="source">{f.dependency_path.length ? f.dependency_path.map(id => componentLabel(id, nodes)).join(' → ') : 'unknown'}</td>
      </tr>
      {selectedId === f.finding_id && <SignalsRow finding={f} onShowPath={onShowPath}/>}
    </React.Fragment>)}</tbody></table></div>;
}

function AnomalyTable({anomalies, evidence}) {
  if (!anomalies.length) return <div className="empty-state"><strong>No anomalies reported</strong></div>;
  return <div className="table-scroll"><table><thead><tr>
    <th>TYPE</th><th>PACKAGE / FILE</th><th>RISK</th><th>NOTE</th></tr></thead><tbody>
    {anomalies.map(f => {
      const ev = f.evidence_ids.map(id => evidence.get(id)).find(Boolean);
      return <tr key={f.finding_id}>
        <td><strong>{f.anomaly_type}</strong></td>
        <td className="source">{ev ? ev.file : f.purl}</td>
        <td><Badge tone={RISK_TONE[f.risk_level]}>{f.risk_level}</Badge> <small>{f.risk_rule_id}</small></td>
        <td className="source">{f.risk_note || ''}</td></tr>;
    })}</tbody></table></div>;
}

const AGENT_LABELS = {
  triage: 'Triage', relevance: 'Relevance', evidence_validator: 'Evidence validator',
  risk_critic: 'Risk critic', remediation_candidates: 'Remediation candidates',
  injected: 'Injected test claim', vuln_analyst: 'Vulnerability analyst', change_analyst: 'Change analyst',
  analyst_revision: 'Analyst revision', remediation_planner: 'Remediation planner', report_writer: 'Report writer',
};
const AI_GROUPS = [
  ['Summary', ['report_writer']],
  ['Fix proposals (need human approval)', ['remediation_planner']],
  ['Analysis', ['vuln_analyst', 'change_analyst', 'analyst_revision']],
  ['Hallucination test', ['injected']],
];

function claimStatus(c) {
  if (!c.validated) return ['rejected', 'red'];
  if (c.step === 'remediation_planner') return ['proposed', 'green'];
  return c.kind === 'inference' ? ['AI inference', 'amber'] : ['accepted', 'green'];
}

function AgentTraceTable({trace}) {
  if (!trace.length) return null;
  return <div className="ai-group"><h3>Agent trace (who handed what to whom)</h3><div className="table-scroll"><table><thead><tr>
    <th>#</th><th>AGENT</th><th>CONSUMED</th><th>PRODUCED</th><th>ACCEPTED</th><th>REJECTED</th><th>LLM CALLS</th><th>NOTE</th></tr></thead><tbody>
    {trace.map((t, i) => <tr key={i}><td>{i + 1}</td><td><strong>{AGENT_LABELS[t.agent] || t.agent.replaceAll('_', ' ')}</strong></td>
      <td>{t.consumed.length}</td><td>{t.produced.length}</td><td>{t.accepted}</td><td>{t.rejected}</td><td>{t.llm_calls}</td>
      <td className="source">{t.error || ''}</td></tr>)}</tbody></table></div></div>;
}

function AIReview({claims, llmStatus, trace}) {
  if (!claims.length && !trace.length) {
    return <div className="empty-state"><strong>No AI output for this scan</strong>
      <p>LLM status: {llmStatus}. Set GUARDIAN_LLM_PROVIDER and GUARDIAN_LLM_API_KEY in .env, or tick the
        hallucination test to see the validator reject a fabricated CVE without a key.</p></div>;
  }
  return <><AgentTraceTable trace={trace}/>{AI_GROUPS.map(([title, steps]) => {
    const rows = claims.filter(c => steps.includes(c.step));
    if (!rows.length) return null;
    return <div className="ai-group" key={title}><h3>{title}</h3><div className="table-scroll"><table><thead><tr>
      <th>AGENT</th><th>STATUS</th><th>CLAIM</th><th>EVIDENCE</th><th>WHY</th></tr></thead><tbody>
      {rows.map(c => { const [label, tone] = claimStatus(c); return <tr key={c.claim_id + c.step}>
        <td><strong>{AGENT_LABELS[c.step] || c.step}</strong></td>
        <td><Badge tone={tone}>{label}</Badge></td>
        <td className="claim-text">{c.text}</td>
        <td className="source"><code>{c.evidence_ids.join(', ') || 'none'}</code></td>
        <td className="source">{c.rejected_reason || c.uncertainty || ''}</td></tr>; })}
    </tbody></table></div></div>;
  })}</>;
}

function CoverageTable({coverage}) {
  return <div className="table-scroll"><table><thead><tr>
    <th>DETECTOR</th><th>ECOSYSTEM</th><th>STATUS</th><th>REASON</th></tr></thead><tbody>
    {coverage.rows.map((r, i) => <tr key={i}>
      <td><strong>{r.detector}</strong></td><td>{r.ecosystem}</td>
      <td><Badge tone={r.status === 'error' || r.status === 'not_covered' ? 'red' : r.status === 'finding' ? 'amber' : 'green'}>{r.status}</Badge></td>
      <td className="source">{r.reason}</td></tr>)}</tbody></table>
    {coverage.warnings.map((w, i) => <p className="footnote" key={i}>{w}</p>)}</div>;
}

function GraphView({graph, nodes, vulnerable, path}) {
  const flow = useMemo(() => {
    const onPath = new Set(path);
    const ordered = [...path.map(id => graph.nodes.find(n => n.component_id === id)).filter(Boolean),
      ...graph.nodes.filter(n => !onPath.has(n.component_id))];
    const shown = ordered.slice(0, 130);
    const ids = new Set(shown.map(n => n.component_id));
    const pathEdges = new Set(path.slice(1).map((id, i) => `${path[i]}>${id}`));
    return {
      nodes: shown.map((n, i) => {
        const hot = onPath.has(n.component_id);
        const k = i - onPath.size;
        const left = onPath.size ? 260 : 0;
        const position = hot ? {x: 0, y: path.indexOf(n.component_id) * 120}
          : {x: left + (k % 6) * 190, y: Math.floor(k / 6) * 110};
        return {
          id: n.component_id, position,
          data: {label: <div className="node-label"><strong>{n.name}</strong><small>{n.version}{n.dev ? ' · dev' : ''}</small></div>},
          style: {border: (hot ? '2px solid #c2410c' : '1px solid ' + (vulnerable.has(n.component_id) ? '#e6a69e' : '#b8d9c6')),
            borderRadius: 9, background: hot ? '#fff1e6' : vulnerable.has(n.component_id) ? '#fff3f1' : '#ffffff',
            fontSize: 11, width: 164, padding: 8},
        };
      }),
      edges: graph.edges.filter(e => ids.has(e.parent_id) && ids.has(e.child_id)).map((e, i) => {
        const hot = pathEdges.has(`${e.parent_id}>${e.child_id}`);
        return {id: `edge-${i}`, source: e.parent_id, target: e.child_id, animated: hot,
          label: hot ? e.edge_source : undefined,
          markerEnd: {type: MarkerType.ArrowClosed, color: hot ? '#c2410c' : '#a3b5aa'},
          style: {stroke: hot ? '#c2410c' : '#b6c8bd', strokeWidth: hot ? 2.5 : 1}};
      }),
    };
  }, [graph, vulnerable, path]);
  const chain = path.map(id => componentLabel(id, nodes)).join(' → ');
  return <div className="graph-content"><div className="graph-top"><div><strong>Dependency graph</strong>
    <p>{path.length ? <>Highlighted: how the selected vulnerability enters the app: <code>{chain}</code></>
      : <>Showing up to 130 of {nodes.size} components. Select a finding and choose "Show this path" to highlight how it enters the app.</>}</p></div></div>
    <div className="graph-frame"><ReactFlow fitView nodes={flow.nodes} edges={flow.edges}>
      <Background color="#e7eee9" gap={20}/><Controls showInteractive={false}/><MiniMap pannable zoomable nodeColor="#7bb999"/>
    </ReactFlow></div></div>;
}

export function Results({scanId, status, result, graph}) {
  const [tab, setTab] = useState('findings');
  const [selectedId, setSelectedId] = useState(null);
  const [path, setPath] = useState([]);
  const showPath = f => { setPath(f.dependency_path); setTab('graph'); };
  const evidence = useMemo(() => new Map(result.evidence.map(e => [e.evidence_id, e])), [result]);
  const nodes = useMemo(() => new Map((graph?.nodes || []).map(n => [n.component_id, n])), [graph]);
  const vulns = result.findings.filter(f => f.kind !== 'anomaly');
  const anomalies = result.findings.filter(f => f.kind === 'anomaly');
  const vulnerable = useMemo(() => new Set(vulns.map(f => f.component_id)), [result]);
  const claims = result.claims || [];
  const tabs = [['findings', `Findings (${vulns.length})`], ['anomalies', `Anomalies (${anomalies.length})`],
    ['ai', `AI review (${claims.length})`], ['coverage', 'Coverage'], ['graph', 'Dependency graph']];
  const generated = result.fetch.files.filter(f => f.source === 'generated').map(f => f.path);
  return <>
    <div className="results-heading"><div><h2>Guardian results</h2>
      <p>{status.repository_url} <span className="separator">/</span> <code>{result.fetch.commit_sha.slice(0, 10)}</code></p></div>
      <div className="actions">
        <a className="outline" href={`${API}/scan/${scanId}/report`} target="_blank" rel="noreferrer"><FileText size={16}/> Open full report</a>
        <a className="outline" href={`${API}/scan/${scanId}/sbom`} download="sbom.cdx.json"><Download size={16}/> Download SBOM</a>
      </div></div>
    <div className="summary-grid card"><div><span>Scan status</span><strong>{result.scan.status}</strong></div>
      <div><span>LLM status</span><strong>{result.scan.llm_status}</strong></div>
      <div><span>Resolution</span><strong>{result.scan.resolution}</strong></div>
      <div><span>Files fetched</span><strong>{result.fetch.files.length}{generated.length ? ` (generated lockfiles: ${generated.join(', ')})` : ''}</strong></div></div>
    <div className="risk-counts">{RISK_ORDER.map(level => <div className="metric" key={level}>
      <div className="metric-top">{level.toUpperCase()}</div><strong>{result.counts_by_risk[level] || 0}</strong></div>)}</div>
    {Object.entries({...result.scan.errors, ...result.fetch.errors}).map(([k, v]) =>
      <div className="notice warning" key={k}><div><strong>{k}</strong><p>{v}</p></div></div>)}
    {result.fetch.skipped.map(s => <div className="notice warning" key={s}><div><strong>Skipped file</strong><p>{s}</p></div></div>)}
    <section className="panel data-panel">
      <div className="tabs">{tabs.map(([key, label]) =>
        <button key={key} className={tab === key ? 'tab selected' : 'tab'} onClick={() => setTab(key)}>{label}</button>)}</div>
      <div className="tab-content">
        {tab === 'findings' && <FindingsTable findings={vulns} evidence={evidence} nodes={nodes}
          selectedId={selectedId} onSelect={setSelectedId} onShowPath={showPath}/>}
        {tab === 'anomalies' && <AnomalyTable anomalies={anomalies} evidence={evidence}/>}
        {tab === 'ai' && <AIReview claims={claims} llmStatus={result.scan.llm_status} trace={result.agent_trace || []}/>}
        {tab === 'coverage' && <CoverageTable coverage={result.coverage}/>}
        {tab === 'graph' && (graph ? <GraphView graph={graph} nodes={nodes} vulnerable={vulnerable} path={path}/> : <div className="empty-state"><strong>No graph produced</strong></div>)}
      </div></section>
  </>;
}
