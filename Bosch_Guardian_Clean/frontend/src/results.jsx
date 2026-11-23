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

function FindingsTable({findings, evidence, nodes}) {
  if (!findings.length) {
    return <div className="empty-state"><strong>No vulnerability findings reported</strong>
      <p>This is not proof the repository is safe. Check the coverage tab for gaps.</p></div>;
  }
  return <div className="table-scroll"><table><thead><tr>
    <th>ADVISORY</th><th>PACKAGE</th><th>SEVERITY</th><th>RISK</th><th>CONFIRMED BY</th>
    <th>FIXED IN</th><th>DEPENDENCY PATH</th><th>EVIDENCE</th></tr></thead><tbody>
    {findings.map(f => <tr key={f.finding_id}>
      <td><strong>{f.advisory_id}</strong></td>
      <td><code>{componentLabel(f.component_id, nodes) === f.component_id ? f.purl : componentLabel(f.component_id, nodes)}</code></td>
      <td>{f.source_severity}</td>
      <td><Badge tone={RISK_TONE[f.risk_level]}>{f.risk_level}</Badge> <small>{f.risk_rule_id}</small></td>
      <td>{f.confirmed_by.join(', ')}</td>
      <td>{f.fixed_versions.join(', ') || 'unknown'}</td>
      <td className="source">{f.dependency_path.length ? f.dependency_path.map(id => componentLabel(id, nodes)).join(' → ') : 'unknown'}</td>
      <td className="source"><EvidenceLink finding={f} evidence={evidence}/></td>
    </tr>)}</tbody></table></div>;
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

function CoverageTable({coverage}) {
  return <div className="table-scroll"><table><thead><tr>
    <th>DETECTOR</th><th>ECOSYSTEM</th><th>STATUS</th><th>REASON</th></tr></thead><tbody>
    {coverage.rows.map((r, i) => <tr key={i}>
      <td><strong>{r.detector}</strong></td><td>{r.ecosystem}</td>
      <td><Badge tone={r.status === 'error' || r.status === 'not_covered' ? 'red' : r.status === 'finding' ? 'amber' : 'green'}>{r.status}</Badge></td>
      <td className="source">{r.reason}</td></tr>)}</tbody></table>
    {coverage.warnings.map((w, i) => <p className="footnote" key={i}>{w}</p>)}</div>;
}

function GraphView({graph, nodes, vulnerable}) {
  const flow = useMemo(() => {
    const shown = graph.nodes.slice(0, 130);
    const ids = new Set(shown.map(n => n.component_id));
    return {
      nodes: shown.map((n, i) => ({
        id: n.component_id, position: {x: (i % 7) * 190, y: Math.floor(i / 7) * 110},
        data: {label: <div className="node-label"><strong>{n.name}</strong><small>{n.version}</small></div>},
        style: {border: '1px solid ' + (vulnerable.has(n.component_id) ? '#e6a69e' : '#b8d9c6'), borderRadius: 9,
          background: vulnerable.has(n.component_id) ? '#fff3f1' : '#ffffff', fontSize: 11, width: 164, padding: 8},
      })),
      edges: graph.edges.filter(e => ids.has(e.parent_id) && ids.has(e.child_id)).map((e, i) => ({
        id: `edge-${i}`, source: e.parent_id, target: e.child_id,
        markerEnd: {type: MarkerType.ArrowClosed, color: '#a3b5aa'}, style: {stroke: '#b6c8bd'},
      })),
    };
  }, [graph, vulnerable]);
  return <div className="graph-content"><div className="graph-top"><div><strong>Dependency graph</strong>
    <p>Showing up to 130 of {nodes.size} components. Vulnerable packages are highlighted.</p></div></div>
    <div className="graph-frame"><ReactFlow fitView nodes={flow.nodes} edges={flow.edges}>
      <Background color="#e7eee9" gap={20}/><Controls showInteractive={false}/><MiniMap pannable zoomable nodeColor="#7bb999"/>
    </ReactFlow></div></div>;
}

export function Results({scanId, status, result, graph}) {
  const [tab, setTab] = useState('findings');
  const evidence = useMemo(() => new Map(result.evidence.map(e => [e.evidence_id, e])), [result]);
  const nodes = useMemo(() => new Map((graph?.nodes || []).map(n => [n.component_id, n])), [graph]);
  const vulns = result.findings.filter(f => f.kind !== 'anomaly');
  const anomalies = result.findings.filter(f => f.kind === 'anomaly');
  const vulnerable = useMemo(() => new Set(vulns.map(f => f.component_id)), [result]);
  const tabs = [['findings', `Findings (${vulns.length})`], ['anomalies', `Anomalies (${anomalies.length})`],
    ['coverage', 'Coverage'], ['graph', 'Dependency graph']];
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
        {tab === 'findings' && <FindingsTable findings={vulns} evidence={evidence} nodes={nodes}/>}
        {tab === 'anomalies' && <AnomalyTable anomalies={anomalies} evidence={evidence}/>}
        {tab === 'coverage' && <CoverageTable coverage={result.coverage}/>}
        {tab === 'graph' && (graph ? <GraphView graph={graph} nodes={nodes} vulnerable={vulnerable}/> : <div className="empty-state"><strong>No graph produced</strong></div>)}
      </div></section>
  </>;
}
