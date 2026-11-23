import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildDecision, fixTitle, levelRows, needsPolling, primaryAction, statusLabel} from './fixes-logic.js';

const entry = (status, extra = {}) => ({
  status, source: 'rule', unavailable_reason: null,
  target: {package: 'lodash', from_version: '4.17.4', to_version: '4.17.21'}, ...extra,
});

test('fixTitle shows package and version change, falling back to the proposal action', () => {
  assert.equal(fixTitle(entry('proposed')), 'lodash 4.17.4 → 4.17.21');
  assert.equal(fixTitle({target: null, proposal: {action: 'remove_dependency'}}), 'remove dependency');
});

test('levelRows lists risk levels in severity order with before, after and delta', () => {
  const rows = levelRows({counts_before: {critical: 0, high: 2, medium: 1, low: 0, unknown: 0},
    counts_after: {critical: 1, high: 0, medium: 1, low: 0, unknown: 0}});
  assert.deepEqual(rows.map(r => r.level), ['critical', 'high', 'medium', 'low']);
  assert.deepEqual(rows[1], {level: 'high', before: 2, after: 0, delta: -2});
  assert.equal(rows[0].delta, 1);
});

test('levelRows includes unknown only when it has findings', () => {
  const rows = levelRows({counts_before: {unknown: 1}, counts_after: {}});
  assert.equal(rows.at(-1).level, 'unknown');
  assert.equal(rows.at(-1).after, 0);
});

test('primaryAction depends on status and applicability', () => {
  assert.equal(primaryAction(entry('proposed')), 'decide');
  assert.equal(primaryAction(entry('failed')), 'decide');
  assert.equal(primaryAction(entry('awaiting_approval')), 'decide');
  assert.equal(primaryAction(entry('running')), 'wait');
  assert.equal(primaryAction(entry('verified')), 'none');
  assert.equal(primaryAction(entry('rejected')), 'none');
  assert.equal(primaryAction(entry('proposed', {unavailable_reason: 'manual'})), 'none');
});

test('needsPolling is true while any fix is running', () => {
  assert.equal(needsPolling([entry('proposed'), entry('running')]), true);
  assert.equal(needsPolling([entry('verified')]), false);
});

test('buildDecision requires a reviewer and trims input', () => {
  assert.deepEqual(buildDecision(true, '  ana ', ' ok '), {body: {approved: true, reviewer: 'ana', note: 'ok'}});
  assert.match(buildDecision(false, ' ', '').error, /name/i);
});

test('statusLabel is human readable', () => {
  assert.equal(statusLabel('awaiting_approval'), 'Awaiting approval');
  assert.equal(statusLabel('verified'), 'Verified');
});
