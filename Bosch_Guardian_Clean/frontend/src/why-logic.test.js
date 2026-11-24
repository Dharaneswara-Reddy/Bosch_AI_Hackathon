import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildWhy, providerLine} from './why-logic.js';

const base = {
  ssvc_decision: 'attend', exploitation: 'none', exposure: 'open', automatable: 'yes',
  technical_impact: 'total', known_exploited: false, epss: 0.02, risk_level: 'high',
  engine_risk_level: 'high', ai_adjusted: false, ai_adjustment_evidence_ids: [],
  confidence_score: 0.82, review_required: false, review_reasons: [],
};

test('the SSVC decision becomes a plain-words chain ending in the decision and level', () => {
  const why = buildWhy(base);
  assert.deepEqual(why.steps, [
    'Not exploited (no KEV, EPSS 2%)',
    'Production dependency, reachable',
    'Network-attackable, no user interaction',
    'High impact',
  ]);
  assert.equal(why.outcome, 'Attend = High');
  assert.equal(why.adjustment, null);
  assert.equal(why.confidence, 'Confidence 0.82');
});

test('exploitation, exposure and impact variants use their own wording', () => {
  const why = buildWhy({...base, exploitation: 'active', known_exploited: true, exposure: 'small',
    automatable: 'no', technical_impact: 'partial', ssvc_decision: 'track_star', risk_level: 'medium',
    engine_risk_level: 'medium'});
  assert.deepEqual(why.steps, [
    'Actively exploited (listed in CISA KEV)',
    'Dev-only dependency',
    'Needs local access or user interaction',
    'Limited impact',
  ]);
  assert.equal(why.outcome, 'Track* = Medium');
  assert.equal(buildWhy({...base, exploitation: 'likely', epss: 0.314}).steps[0],
    'Likely exploited (EPSS 31%)');
  assert.equal(buildWhy({...base, exploitation: 'unknown', epss: null}).steps[0],
    'Exploitation unknown (no EPSS data)');
  assert.equal(buildWhy({...base, epss: 0.001}).steps[0], 'Not exploited (no KEV, EPSS <1%)');
});

test('an AI adjustment shows the engine level, the new level, the reason and evidence', () => {
  const why = buildWhy({...base, ai_adjusted: true, risk_level: 'medium',
    ai_adjustment_reason: 'Only the legacy parser is affected.', ai_adjustment_evidence_ids: ['e1', 'e2']});
  assert.equal(why.outcome, 'Attend = High');
  assert.equal(why.adjustment,
    'AI adjusted High → Medium: Only the legacy parser is affected. (evidence: e1, e2)');
});

test('review reasons are listed only when review is required', () => {
  assert.deepEqual(buildWhy(base).review, []);
  assert.deepEqual(buildWhy({...base, review_required: true, review_reasons: ['critics disagree']}).review,
    ['critics disagree']);
});

test('a finding without an SSVC decision has no chain', () => {
  assert.equal(buildWhy({...base, ssvc_decision: null}), null);
});

const row = (agent, extra) => ({agent, llm_calls: 0, error: null, provider: null, produced: [], ...extra});

test('provider line names the answering provider, call count and fall-back reasons', () => {
  const line = providerLine([
    row('triage', {provider: 'gemini:gemini-2.5-flash', llm_calls: 5}),
    row('relevance', {provider: 'gemini:gemini-2.5-flash', llm_calls: 7}),
    row('llm_providers', {produced: ['groq:llama', 'gemini:gemini-2.5-flash'],
      error: 'groq:llama failed: 429 rate limited'}),
  ]);
  assert.equal(line,
    'Answered by: gemini:gemini-2.5-flash (12 calls) · groq:llama failed: 429 rate limited → fell back');
});

test('provider line without failures is just the answering provider; singular call', () => {
  assert.equal(providerLine([row('triage', {provider: 'groq:llama', llm_calls: 1}),
    row('llm_providers', {produced: ['groq:llama']})]), 'Answered by: groq:llama (1 call)');
});

test('provider line reports when nothing answered, and nothing when no provider data exists', () => {
  assert.equal(providerLine([row('llm_providers', {produced: ['groq:llama'],
    error: 'groq:llama failed: bad key'})]), 'No AI provider answered · groq:llama failed: bad key');
  assert.equal(providerLine([row('triage')]), null);
  assert.equal(providerLine([]), null);
});

test('provider line states plainly when the AI planner was unavailable', () => {
  const planner = row('remediation_planner', {
    error: 'AI planner unavailable (rate limited) — rule-based fixes shown. Provider returned HTTP 429.'});
  assert.equal(providerLine([row('triage', {provider: 'groq:llama', llm_calls: 1}), planner]),
    'Answered by: groq:llama (1 call) · AI planner unavailable (rate limited) — rule-based fixes shown');
  assert.equal(providerLine([row('triage', {provider: 'groq:llama', llm_calls: 1}),
    row('remediation_planner', {error: 'no input'})]), 'Answered by: groq:llama (1 call)');
});
