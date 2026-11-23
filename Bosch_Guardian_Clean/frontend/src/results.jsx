import React, {useMemo, useState} from 'react';
import {ReactFlow, Background, Controls, MarkerType} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {layoutSubgraph, selectSubgraph} from './graph-layout.js';
import {Download, ExternalLink, FileText} from 'lucide-react';
import {FixPanel} from './fixes.jsx';

const API = '/api';
const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];
const RISK_TONE = {critical: 'red', high: 'red', medium: 'amber', low: 'green', unknown: 'neutral'};

export function Badge({children, tone = 'neutral'}) {
  return <span className={'badge ' + tone}>{children}</span>;
}

function componentLabel(componentId, nodes) {
  const node = nodes.get(componentId);
  if (!node) return componentId;
  return node.version && node.version !== 'UNKNOWN' ? `${node.name}@${node.version}` : node.name;
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

const DECISION_LABEL = {act: 'Act', attend: 'Attend', track_star: 'Track*', track: 'Track'};

function ConfidenceCell({finding}) {
  const score = finding.confidence_score;
  return <td className="nowrap">
    {score == null ? 'n/a' : score.toFixed(2)}
    {finding.review_required && <><br/><Badge tone="red">needs review</Badge></>}
  </td>;
}

function AdjustedBadge({finding}) {
  return finding.ai_adjusted ? <><br/><Badge tone="amber">AI adjusted</Badge></> : null;
}

function RiskReasons({finding}) {
  if (!finding.risk_reasons?.length && !finding.review_required) return null;
  return <div className="risk-reasons">
    {finding.ai_adjusted && <p className="signals-summary">
      <strong>AI adjusted:</strong> {finding.engine_risk_level} → {finding.risk_level}. {finding.ai_adjustment_reason}</p>}
    {finding.ssvc_decision && <p className="signals-summary">
      <strong>{DECISION_LABEL[finding.ssvc_decision]}</strong>
      {finding.risk_score != null && ` · score ${finding.risk_score}/100`}
      {finding.confidence_score != null && ` · confidence ${finding.confidence_score.toFixed(2)}`}</p>}
    <ul>{finding.risk_reasons.map(reason => <li key={reason}>{reason}</li>)}</ul>
    {finding.review_required && <p className="signals-summary"><strong>Needs human review:</strong> {finding.review_reasons.join('; ')}</p>}
  </div>;
}

function SignalsRow({finding, onShowPath}) {
  const r = finding.relevance;
  return <tr className="signals-row"><td colSpan={9}>
    <RiskReasons finding={finding}/>
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
  const assessed = findings.some(f => f.relevance && f.relevance.verdict !== 'unknown');
  return <div className="table-scroll"><p className="footnote">{assessed
    ? 'Ranked by relevance, then risk. Click a row to see why.'
    : 'Ranked by risk. Relevance and reachability could not be assessed: a URL scan fetches only manifest files, not the application source. Click a row for details.'}</p>
    <table><thead><tr>
    {assessed && <th>RELEVANCE</th>}<th>RISK</th><th>ADVISORY</th><th>PACKAGE</th><th>INTRODUCED BY</th>
    {assessed && <th>REACHABILITY · SCOPE</th>}<th>CONFIDENCE</th><th>FIXED IN</th><th>DEPENDENCY PATH</th></tr></thead><tbody>
    {rankFindings(findings).map(f => <React.Fragment key={f.finding_id}>
      <tr className={'clickable' + (selectedId === f.finding_id ? ' selected-row' : '')} onClick={() => onSelect(selectedId === f.finding_id ? null : f.finding_id)}>
        {assessed && <td><RelevanceBadge finding={f}/></td>}
        <td className="nowrap"><Badge tone={RISK_TONE[f.risk_level]}>{f.risk_level}</Badge><AdjustedBadge finding={f}/><br/><small>{f.risk_rule_id}{f.risk_score != null && ` · ${f.risk_score}`}</small></td>
        <td><strong>{f.advisory_id}</strong><br/><EvidenceLink finding={f} evidence={evidence}/></td>
        <td><code>{componentLabel(f.component_id, nodes) === f.component_id ? f.purl : componentLabel(f.component_id, nodes)}</code></td>
        <td>{f.relevance?.introduced_by || 'unknown'}</td>
        {assessed && <td>{signal(f, 'reachability')} · {signal(f, 'dependency_scope')}</td>}
        <ConfidenceCell finding={f}/>
        <td>{f.fixed_versions.join(', ') || 'none listed'}</td>
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

function AdjustmentsTable({adjustments, agreement}) {
  if (!adjustments.length) return null;
  return <div className="ai-group"><h3>Risk adjustments</h3><div className="table-scroll"><table><thead><tr>
    <th>FINDING</th><th>CHANGE</th><th>STATUS</th><th>CRITIC</th><th>REASON</th></tr></thead><tbody>
    {adjustments.map(a => <tr key={a.finding_id + a.to_level + a.status}>
      <td><code>{a.finding_id}</code></td><td>{a.from_level} → {a.to_level}</td>
      <td><Badge tone={a.status === 'accepted' ? 'green' : 'red'}>{a.status}</Badge></td>
      <td>{a.finding_id in agreement ? (agreement[a.finding_id] ? 'agrees' : 'disagrees') : 'not reviewed'}</td>
      <td className="source">{a.status === 'rejected' ? a.rejected_reason : a.reason}</td></tr>)}
    </tbody></table></div></div>;
}

function AIReview({claims, llmStatus, trace, adjustments, agreement}) {
  if (!claims.length && !trace.length && !adjustments.length) {
    return <div className="empty-state"><strong>No AI output for this scan</strong>
      <p>LLM status: {llmStatus}. Set GUARDIAN_LLM_PROVIDER and GUARDIAN_LLM_API_KEY in .env, or tick the
        hallucination test to see the validator reject a fabricated CVE without a key.</p></div>;
  }
  return <><AgentTraceTable trace={trace}/><AdjustmentsTable adjustments={adjustments} agreement={agreement}/>{AI_GROUPS.map(([title, steps]) => {
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

function nodeStyle(id, {vulnerable, focus, onPath}) {
  const hot = id === focus || onPath.has(id);
  const bad = vulnerable.has(id);
  return {border: hot ? '2px solid #c2410c' : `1px solid ${bad ? '#e08a7e' : '#b8d9c6'}`, borderRadius: 9,
    background: hot ? '#fff1e6' : bad ? '#fff3f1' : '#ffffff', fontSize: 11, width: 190, padding: '6px 8px'};
}

function GraphView({graph, nodes, vulnerable, path, onClearPath}) {
  const [all, setAll] = useState(false);
  const [focus, setFocus] = useState(null);
  const [query, setQuery] = useState('');
  const labels = useMemo(() => new Map(graph.nodes.map(n => [componentLabel(n.component_id, nodes), n.component_id])), [graph, nodes]);
  const view = path.length ? 'path' : focus ? 'focus' : all ? 'all' : 'vulnerable';
  const reset = () => { onClearPath(); setFocus(null); setQuery(''); };
  const flow = useMemo(() => {
    const sub = selectSubgraph(graph, {all, path, focus, vulnerable});
    const positions = layoutSubgraph(sub);
    const onPath = new Set(path);
    return {
      count: sub.ids.size,
      nodes: [...sub.ids].map(id => {
        const n = nodes.get(id);
        return {id, position: positions.get(id) || {x: 0, y: 0}, sourcePosition: 'right', targetPosition: 'left',
          data: {label: <div className="node-label"><strong>{n?.name || id}</strong>
            <small>{n?.version}{n?.dev ? ' · dev' : ''}{vulnerable.has(id) ? ' · vulnerable' : ''}</small></div>},
          style: nodeStyle(id, {vulnerable, focus, onPath})};
      }),
      edges: sub.edges.map((e, i) => {
        const hot = view === 'path' || e.parent_id === focus || e.child_id === focus;
        const color = hot ? '#c2410c' : '#9fb5a8';
        return {id: `edge-${i}`, source: e.parent_id, target: e.child_id, animated: hot && view === 'path',
          markerEnd: {type: MarkerType.ArrowClosed, color},
          style: {stroke: color, strokeWidth: hot ? 2.2 : 1.2, opacity: view === 'all' ? 0.35 : 1}};
      }),
    };
  }, [graph, nodes, vulnerable, path, focus, all, view]);
  const describe = {
    path: <>How the selected vulnerability enters the app: <code>{path.map(id => componentLabel(id, nodes)).join(' → ')}</code></>,
    focus: <>How <code>{componentLabel(focus, nodes)}</code> enters the app, with its direct parents and dependencies.</>,
    all: <>All {flow.count} components, arranged left to right by depth from the manifest files.</>,
    vulnerable: flow.count ? <>Shortest route from a manifest file to each of the {vulnerable.size} vulnerable packages ({flow.count} components). Click any package to focus on it.</>
      : <>No vulnerable package is linked to a graph node. Switch to "All components".</>,
  }[view];
  return <div className="graph-content">
    <div className="graph-toolbar">
      <button className={view === 'vulnerable' ? 'small' : 'outline small'} onClick={() => { reset(); setAll(false); }}>Vulnerable paths</button>
      <button className={view === 'all' ? 'small' : 'outline small'} onClick={() => { reset(); setAll(true); }}>All components</button>
      <input className="graph-search" list="graph-components" placeholder={`Find a package (${nodes.size})`} value={query}
        onChange={e => { setQuery(e.target.value); const id = labels.get(e.target.value); if (id) { onClearPath(); setFocus(id); } }}/>
      <datalist id="graph-components">{[...labels.keys()].sort().map(l => <option key={l} value={l}/>)}</datalist>
      {(view === 'focus' || view === 'path') && <button className="outline small" onClick={reset}>Clear</button>}
    </div>
    <p className="graph-caption">{describe}</p>
    <div className="graph-frame"><ReactFlow key={`${view}|${focus}|${path.join()}`} fitView fitViewOptions={{padding: 0.15}}
      minZoom={0.05} nodes={flow.nodes} edges={flow.edges} nodesConnectable={false} onlyRenderVisibleElements
      onNodeClick={(_, n) => { onClearPath(); setFocus(n.id); setQuery(componentLabel(n.id, nodes)); }}>
      <Background color="#e7eee9" gap={20}/><Controls showInteractive={false}/>
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
    ['ai', `AI review (${claims.length})`], ['coverage', 'Coverage'], ['graph', 'Dependency graph'], ['fixes', 'Fixes']];
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
        {tab === 'ai' && <AIReview claims={claims} llmStatus={result.scan.llm_status} trace={result.agent_trace || []}
          adjustments={result.risk_adjustments || []} agreement={result.agreement || {}}/>}
        {tab === 'fixes' && <FixPanel scanId={scanId}/>}
        {tab === 'coverage' && <CoverageTable coverage={result.coverage}/>}
        {tab === 'graph' && (graph ? <GraphView graph={graph} nodes={nodes} vulnerable={vulnerable} path={path} onClearPath={() => setPath([])}/> : <div className="empty-state"><strong>No graph produced</strong></div>)}
      </div></section>
  </>;
}
