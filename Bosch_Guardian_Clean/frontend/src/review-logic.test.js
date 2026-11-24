import {test} from 'node:test';
import assert from 'node:assert/strict';
import {sortQueue, progressText, canSubmit, reasonChips, pendingLabel} from './review-logic.js';

const item = (finding_id, risk_level, confidence_score, decision = null) =>
  ({finding_id, risk_level, confidence_score, decision});

test('pending items come first, then highest risk, then lowest confidence', () => {
  const sorted = sortQueue([
    item('done', 'critical', 0.1, {decision: 'confirmed'}),
    item('low', 'low', 0.2),
    item('high-sure', 'high', 0.9),
    item('high-unsure', 'high', 0.3),
    item('none', 'high', null),
  ]);
  assert.deepEqual(sorted.map(i => i.finding_id), ['high-unsure', 'high-sure', 'none', 'low', 'done']);
});

test('sorting does not mutate the input', () => {
  const input = [item('b', 'low', 0.5), item('a', 'high', 0.5)];
  sortQueue(input);
  assert.equal(input[0].finding_id, 'b');
});

test('progress line counts reviewed over total', () => {
  const counts = {pending: 72, confirmed: 8, dismissed: 3, escalated: 1};
  assert.equal(progressText(counts), '12 of 84 reviewed');
  assert.equal(pendingLabel(counts), 'Review queue (72 pending)');
});

test('dismiss needs a non-blank note, other decisions do not', () => {
  assert.equal(canSubmit('dismissed', '   '), false);
  assert.equal(canSubmit('dismissed', 'test-only code'), true);
  assert.equal(canSubmit('confirmed', ''), true);
  assert.equal(canSubmit('escalated', ''), true);
});

test('reason chips start with a capital letter and drop blanks', () => {
  assert.deepEqual(reasonChips(['low confidence', '', 'AI moved it']), ['Low confidence', 'AI moved it']);
});
