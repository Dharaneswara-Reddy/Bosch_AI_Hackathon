import React, {useCallback, useEffect, useState} from 'react';
import {Check, LoaderCircle, X} from 'lucide-react';
import {Badge} from './results.jsx';
import {buildDecision, compareReduction, expectedText, fixTitle, levelRows, needsPolling, primaryAction, statusLabel} from './fixes-logic.js';

const API = '/api';
const POLL_MS = 1500;
const STATUS_TONE = {verified: 'green', failed: 'red', rejected: 'amber', awaiting_approval: 'amber'};
const RESULT_TONE = {passed: 'green', failed: 'red'};

async function call(path, options) {
  const response = await fetch(API + path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status})`);
  return data;
}

const post = (path, body) => call(path, {method: 'POST', headers: {'Content-Type': 'application/json'},
  body: body ? JSON.stringify(body) : undefined});

function FindingList({title, refs}) {
  if (!refs.length) return null;
  return <div><strong>{title}</strong><ul className="fix-list">{refs.map(r => <li key={r.finding_id}>
    <code>{r.advisory_id || r.finding_id}</code> {r.package} {r.version} <Badge tone={r.risk_level === 'low' ? 'green' : 'amber'}>{r.risk_level}</Badge></li>)}</ul></div>;
}

function ExpectedVsActual({expected, diff}) {
  const comparison = compareReduction(expected, diff);
  if (!comparison) return null;
  return <p className="body-text">Expected to fix: <strong>{comparison.expected}</strong> · Actually fixed: <strong>{comparison.actual}</strong>{' '}
    <Badge tone={comparison.matches ? 'green' : 'amber'}>{comparison.matches ? 'as expected' : 'differs'}</Badge></p>;
}

function FixResult({run, expected}) {
  const diff = run.diff;
  return <div className="fix-result">
    {run.summary && <p className="signals-summary">{run.summary}</p>}
    {run.error && <div className="notice error"><div><strong>Fix did not complete</strong><p>{run.error}</p></div></div>}
    {diff && <>
      <ExpectedVsActual expected={expected} diff={diff}/>
      <div className="table-scroll"><table className="signals"><thead><tr><th>Risk level</th><th>Before</th><th>After</th></tr></thead>
        <tbody>{levelRows(diff).map(r => <tr key={r.level}><td>{r.level}</td><td>{r.before}</td>
          <td><strong>{r.after}</strong> {r.delta !== 0 && <small>({r.delta > 0 ? '+' : ''}{r.delta})</small>}</td></tr>)}</tbody></table></div>
      <div className="fix-columns">
        <FindingList title="Fixed findings" refs={diff.fixed}/>
        <FindingList title="New findings" refs={diff.introduced}/>
        {diff.level_changed.length > 0 && <div><strong>Risk level changed</strong><ul className="fix-list">{diff.level_changed.map(c =>
          <li key={c.advisory_id + c.package}><code>{c.advisory_id}</code> {c.package}: {c.from_level} → {c.to_level}</li>)}</ul></div>}
        {diff.version_changes.length > 0 && <div><strong>Package versions</strong><ul className="fix-list">{diff.version_changes.map(v =>
          <li key={v.package}>{v.package}: {v.before || 'absent'} → {v.after || 'removed'}</li>)}</ul></div>}
      </div></>}
    <div className="fix-checks">
      {run.build && <span>Build check <Badge tone={RESULT_TONE[run.build.status] || 'neutral'}>{run.build.status}</Badge> {run.build.detail}</span>}
      {run.tests && <span>Tests <Badge tone={RESULT_TONE[run.tests.status] || 'neutral'}>{run.tests.status.replace('_', ' ')}</Badge> {run.tests.reason}</span>}
    </div>
  </div>;
}

function FixCard({entry, busy, onDecide}) {
  const [note, setNote] = useState('');
  const {proposal, source, status, result} = entry;
  const action = primaryAction(entry);
  return <div className="card fix-card">
    <div className="fix-head"><strong>{fixTitle(entry)}</strong>
      <span><Badge tone={source === 'ai' ? 'green' : 'neutral'}>{source === 'ai' ? 'AI proposed' : 'Rule-based'}</Badge>{' '}
        <Badge tone={STATUS_TONE[status] || 'neutral'}>{statusLabel(status)}</Badge></span></div>
    <p className="body-text">{proposal.rationale}</p>
    <div className="summary-grid"><div><span>Rollback</span><strong>{proposal.rollback}</strong></div>
      <div><span>Breaking-change risk</span><strong>{proposal.breaking_change_risk}</strong></div></div>
    {entry.expected_reduction && <p className="body-text"><strong>{expectedText(entry.expected_reduction)}</strong></p>}
    {entry.unavailable_reason && <p className="fix-note">Not applied automatically: {entry.unavailable_reason}</p>}
    {action === 'decide' && <div className="fix-decision">
      <input value={note} onChange={e => setNote(e.target.value)} placeholder="Reviewer note (optional)" aria-label="Reviewer note"/>
      <button className="primary" disabled={busy} onClick={() => onDecide(entry, true, note)}><Check size={16}/> Approve and verify</button>
      <button className="outline" disabled={busy} onClick={() => onDecide(entry, false, note)}><X size={16}/> Reject</button></div>}
    {(action === 'wait' || busy) && <p className="notice progress"><LoaderCircle size={16} className="spin"/> Applying in a sandbox, resolving dependencies and rescanning…</p>}
    {result && status !== 'running' && <FixResult run={result} expected={entry.expected_reduction}/>}
  </div>;
}

export function FixPanel({scanId}) {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState('');
  const [reviewer, setReviewer] = useState('');
  const [busyId, setBusyId] = useState(null);
  const base = `/scan/${scanId}/fixes`;
  const load = useCallback(() => call(base).then(setEntries).catch(e => setError(e.message)), [base]);
  useEffect(() => { load(); }, [load]);
  const polling = entries ? needsPolling(entries) : false;
  useEffect(() => {
    if (!polling) return undefined;
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [polling, load]);
  async function decide(entry, approved, note) {
    const decision = buildDecision(approved, reviewer, note);
    if (decision.error) { setError(decision.error); return; }
    const id = entry.proposal.proposal_id;
    setBusyId(id); setError('');
    try {
      await post(`${base}/${id}/start`);
      await post(`${base}/${id}/decision`, decision.body);
    } catch (e) { setError(e.message); }
    await load();
    setBusyId(null);
  }
  if (!entries) return error ? <div className="notice error"><div><strong>Fixes unavailable</strong><p>{error}</p></div></div> : <div className="empty-state"><strong>Loading fixes…</strong></div>;
  return <div>
    <div className="table-heading"><div><h3>Proposed fixes</h3>
      <p>Nothing is changed until you approve. Approved fixes run in a throwaway sandbox copy, then the project is rescanned.</p></div>
      <label className="search-field"><input value={reviewer} onChange={e => setReviewer(e.target.value)} placeholder="Your name" aria-label="Reviewer name"/></label></div>
    {error && <div className="notice error"><div><strong>Fix request failed</strong><p>{error}</p></div><button onClick={() => setError('')} aria-label="Dismiss">×</button></div>}
    {entries.length === 0 && <div className="empty-state"><strong>No fixes proposed</strong><p>No finding has a known fixed version.</p></div>}
    {entries.map(entry => <FixCard key={entry.proposal.proposal_id} entry={entry}
      busy={busyId === entry.proposal.proposal_id} onDecide={decide}/>)}
  </div>;
}
