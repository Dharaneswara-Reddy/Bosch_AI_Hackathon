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

export function stepCounts(step) {
  if (step.total == null || step.passed == null) return '';
  return `${step.passed} of ${step.total} passed` + (step.failed ? `, ${step.failed} failed` : '');
}

export function appRunText(app) {
  if (app.status !== 'passed') return app.reason;
  const answered = `answered ${new URL(app.health_url).pathname} with ${app.http_status}`;
  if (!app.image_vulns) return `${answered}. Image scan unavailable: ${app.image_error}`;
  const {critical = 0, high = 0} = app.image_vulns;
  return `${answered}. Image scan: ${critical} critical, ${high} high (${app.image_only_serious} from the base image)`;
}

const levelText = counts => LEVELS.filter(l => counts[l]).map(l => `${counts[l]} ${l[0].toUpperCase()}${l.slice(1)}`).join(', ');

export function expectedText(reduction) {
  if (!reduction) return '';
  const levels = levelText(reduction.fixes) || 'no findings';
  const count = reduction.advisories.length;
  const advisories = count ? ` (${count} ${count === 1 ? 'advisory' : 'advisories'})` : '';
  return `Expected: fixes ${levels}${advisories}`;
}

export function compareReduction(reduction, diff) {
  if (!reduction || !diff) return null;
  const actual = {};
  diff.fixed.forEach(ref => { actual[ref.risk_level] = (actual[ref.risk_level] || 0) + 1; });
  const sameCounts = LEVELS.every(l => (reduction.fixes[l] || 0) === (actual[l] || 0));
  const total = counts => LEVELS.reduce((sum, l) => sum + (counts[l] || 0), 0);
  const label = sameCounts ? 'as expected'
    : total(actual) > total(reduction.fixes) ? 'more than expected' : 'less than expected';
  return {expected: levelText(reduction.fixes) || 'nothing', actual: levelText(actual) || 'nothing', matches: sameCounts, label};
}
