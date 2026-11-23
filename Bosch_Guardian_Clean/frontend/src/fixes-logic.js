const LEVELS = ['critical', 'high', 'medium', 'low', 'unknown'];
const LABELS = {proposed: 'Proposed', awaiting_approval: 'Awaiting approval', rejected: 'Rejected',
  running: 'Running', verified: 'Verified', failed: 'Failed'};

export const statusLabel = status => LABELS[status] || status;

export function fixTitle(entry) {
  const t = entry.target;
  return t ? `${t.package} ${t.from_version} → ${t.to_version}` : entry.proposal.action.replaceAll('_', ' ');
}

export function levelRows(diff) {
  return LEVELS.map(level => {
    const before = diff.counts_before[level] || 0;
    const after = diff.counts_after[level] || 0;
    return {level, before, after, delta: after - before};
  }).filter(row => row.level !== 'unknown' || row.before || row.after);
}

export function primaryAction(entry) {
  if (entry.unavailable_reason) return 'none';
  if (entry.status === 'running') return 'wait';
  return ['proposed', 'awaiting_approval', 'failed'].includes(entry.status) ? 'decide' : 'none';
}

export const needsPolling = entries => entries.some(entry => entry.status === 'running');

export function buildDecision(approved, reviewer, note) {
  const name = reviewer.trim();
  if (!name) return {error: 'Enter your name so the decision is recorded.'};
  return {body: {approved, reviewer: name, note: note.trim()}};
}
