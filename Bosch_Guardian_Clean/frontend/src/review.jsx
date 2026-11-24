import React, {useCallback, useEffect, useState} from 'react';
import {Badge} from './results.jsx';
import {canSubmit, progressText, reasonChips, sortQueue} from './review-logic.js';

const API = '/api';
const RISK_TONE = {critical: 'red', high: 'red', medium: 'amber', low: 'green', unknown: 'neutral'};
const DECISIONS = [['confirmed', 'Confirm', 'primary'], ['dismissed', 'Dismiss', 'outline'], ['escalated', 'Escalate', 'outline']];
const DECISION_TONE = {confirmed: 'green', dismissed: 'neutral', escalated: 'red'};

async function send(path, options) {
  let response;
  try {
    response = await fetch(API + path, options);
  } catch {
    throw Error('Cannot reach the backend. Start FastAPI on port 8000.');
  }
  const data = await response.json().catch(() => ({}));
  if (response.ok) return data;
  const detail = Array.isArray(data.detail) ? data.detail.map(d => d.msg).join('; ') : data.detail;
  throw Error(typeof detail === 'string' ? detail : `Request failed (${response.status})`);
}

function ReviewCard({item, onDecide}) {
  const [note, setNote] = useState(item.decision?.note || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function decide(decision) {
    setBusy(true); setError('');
    try { await onDecide(item.finding_id, {decision, note}); } catch (e) { setError(e.message); }
    setBusy(false);
  }
  return <div className="card review-card">
    <div className="review-head">
      <strong>{item.package}</strong>
      <span>{item.advisory_id || item.anomaly_type}</span>
      <Badge tone={RISK_TONE[item.risk_level]}>{item.risk_level}</Badge>
      <small>confidence {item.confidence_score == null ? 'n/a' : item.confidence_score.toFixed(2)}</small>
      {item.decision && <Badge tone={DECISION_TONE[item.decision.decision]}>{item.decision.decision}</Badge>}
    </div>
    <div className="review-chips">{reasonChips(item.review_reasons).map(r => <Badge key={r} tone="amber">{r}</Badge>)}</div>
    <textarea className="review-note" maxLength={500} rows={2} value={note} onChange={e => setNote(e.target.value)}
      placeholder="Note (required to dismiss)" aria-label={`Note for ${item.package}`}/>
    <div className="actions">{DECISIONS.map(([key, label, style]) =>
      <button key={key} className={style} disabled={busy || !canSubmit(key, note)} onClick={() => decide(key)}>{label}</button>)}</div>
    {error && <div className="notice error"><p>{error}</p></div>}
  </div>;
}

export function ReviewQueue({scanId, onDecided}) {
  const [queue, setQueue] = useState(null);
  const [error, setError] = useState('');
  const load = useCallback(() => send(`/scan/${scanId}/review`).then(setQueue).catch(e => setError(e.message)), [scanId]);
  useEffect(() => { load(); }, [load]);
  async function decide(findingId, body) {
    await send(`/scan/${scanId}/review/${findingId}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    await load();
    onDecided();
  }
  if (error) return <div className="notice error"><div><strong>Review queue problem</strong><p>{error}</p></div></div>;
  if (!queue) return <p className="footnote">Loading review queue…</p>;
  if (!queue.items.length) return <div className="empty-state"><strong>Nothing needs human review</strong></div>;
  return <div>
    <p className="signals-summary review-progress">{progressText(queue.counts)}</p>
    {sortQueue(queue.items).map(item => <ReviewCard key={item.finding_id} item={item} onDecide={decide}/>)}
  </div>;
}
