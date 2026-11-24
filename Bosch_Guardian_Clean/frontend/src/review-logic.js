const RISK_RANK = {critical: 0, high: 1, medium: 2, low: 3, unknown: 4};

export function sortQueue(items) {
  return [...items].sort((a, b) => Boolean(a.decision) - Boolean(b.decision)
    || (RISK_RANK[a.risk_level] ?? 4) - (RISK_RANK[b.risk_level] ?? 4)
    || (a.confidence_score ?? 1) - (b.confidence_score ?? 1)
    || a.finding_id.localeCompare(b.finding_id));
}

export function progressText({pending, confirmed, dismissed, escalated}) {
  const reviewed = confirmed + dismissed + escalated;
  return `${reviewed} of ${reviewed + pending} reviewed`;
}

export function pendingLabel({pending}) {
  return `Review queue (${pending} pending)`;
}

export function canSubmit(decision, note) {
  return decision !== 'dismissed' || note.trim().length > 0;
}

export function reasonChips(reasons) {
  return reasons.filter(Boolean).map(r => r.charAt(0).toUpperCase() + r.slice(1));
}
