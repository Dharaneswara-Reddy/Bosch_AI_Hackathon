const DECISION = {act: 'Act', attend: 'Attend', track_star: 'Track*', track: 'Track'};
const EXPOSURE = {open: 'Production dependency, reachable',
  limited: 'Production dependency, reachability unconfirmed', small: 'Dev-only dependency'};
const AUTOMATABLE = {yes: 'Network-attackable, no user interaction',
  no: 'Needs local access or user interaction', unknown: 'Attack vector unknown'};
const IMPACT = {total: 'High impact', partial: 'Limited impact'};

const capitalize = text => text.charAt(0).toUpperCase() + text.slice(1);

function epssText(epss) {
  if (epss == null) return null;
  const percent = Math.round(epss * 100);
  return percent < 1 ? '<1%' : `${percent}%`;
}

function exploitationStep(finding) {
  const epss = epssText(finding.epss);
  switch (finding.exploitation) {
    case 'active': return 'Actively exploited (listed in CISA KEV)';
    case 'likely': return `Likely exploited (EPSS ${epss})`;
    case 'none': return `Not exploited (no KEV, EPSS ${epss})`;
    default: return 'Exploitation unknown (no EPSS data)';
  }
}

function adjustmentText(finding) {
  if (!finding.ai_adjusted) return null;
  const evidence = finding.ai_adjustment_evidence_ids.length
    ? ` (evidence: ${finding.ai_adjustment_evidence_ids.join(', ')})` : '';
  return `AI adjusted ${capitalize(finding.engine_risk_level)} → ${capitalize(finding.risk_level)}: `
    + `${finding.ai_adjustment_reason}${evidence}`;
}

export function buildWhy(finding) {
  if (!finding.ssvc_decision) return null;
  const level = finding.engine_risk_level || finding.risk_level;
  return {
    steps: [exploitationStep(finding), EXPOSURE[finding.exposure], AUTOMATABLE[finding.automatable],
      IMPACT[finding.technical_impact]].filter(Boolean),
    outcome: `${DECISION[finding.ssvc_decision]} = ${capitalize(level)}`,
    adjustment: adjustmentText(finding),
    confidence: finding.confidence_score == null ? null : `Confidence ${finding.confidence_score.toFixed(2)}`,
    review: finding.review_required ? finding.review_reasons : [],
  };
}

function callsByProvider(trace) {
  const calls = new Map();
  for (const row of trace) {
    if (row.provider) calls.set(row.provider, (calls.get(row.provider) || 0) + row.llm_calls);
  }
  return calls;
}

function plannerNote(trace) {
  const error = trace.find(row => row.agent === 'remediation_planner')?.error || '';
  return error.startsWith('AI planner unavailable') ? error.split('. ')[0] : null;
}

export function providerLine(trace) {
  const chain = trace.find(row => row.agent === 'llm_providers');
  const calls = callsByProvider(trace);
  if (!chain && !calls.size) return null;
  const answered = [...calls].map(([name, n]) => `${name} (${n} ${n === 1 ? 'call' : 'calls'})`);
  const notes = (chain?.error || '').split('; ').filter(Boolean)
    .map(note => (answered.length && note.includes(' failed:') ? `${note} → fell back` : note));
  const head = answered.length ? `Answered by: ${answered.join(', ')}` : 'No AI provider answered';
  return [head, ...notes, plannerNote(trace)].filter(Boolean).join(' · ');
}
