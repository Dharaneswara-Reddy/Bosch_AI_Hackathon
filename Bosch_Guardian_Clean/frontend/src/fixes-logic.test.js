import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildDecision, compareReduction, expectedText, fixTitle, stepCounts, levelRows, needsPolling, primaryAction, statusLabel} from './fixes-logic.js';

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

test('stepCounts shows passed of total and lists failing names, or nothing without counts', () => {
  assert.equal(stepCounts({status: 'passed', passed: 7, failed: 0, total: 7}), '7 of 7 passed');
  assert.equal(stepCounts({status: 'failed', passed: 3, failed: 4, total: 7}), '3 of 7 passed, 4 failed');
  assert.equal(stepCounts({status: 'not_run', reason: 'x'}), '');
});

const expected = {fixes: {high: 6, medium: 1}, finding_ids: ['a'], advisories: ['A', 'B', 'C'], remaining_on_package: 2};

test('expectedText summarises levels and advisory count before approval', () => {
  assert.equal(expectedText(expected), 'Expected: fixes 6 High, 1 Medium (3 advisories)');
  assert.equal(expectedText({...expected, advisories: ['A'], fixes: {low: 1}}), 'Expected: fixes 1 Low (1 advisory)');
  assert.equal(expectedText({...expected, fixes: {}, advisories: []}), 'Expected: fixes no findings');
  assert.equal(expectedText(null), '');
});

test('compareReduction sets expected beside the actual fixed findings', () => {
  const diff = {fixed: [{risk_level: 'high'}, {risk_level: 'high'}, {risk_level: 'medium'}]};
  assert.deepEqual(compareReduction(expected, diff), {
    expected: '6 High, 1 Medium', actual: '2 High, 1 Medium', matches: false});
  const same = {fixed: [...Array(6).fill({risk_level: 'high'}), {risk_level: 'medium'}]};
  assert.equal(compareReduction(expected, same).matches, true);
  assert.equal(compareReduction(null, same), null);
  assert.equal(compareReduction(expected, {fixed: []}).actual, 'nothing');
});

test('compareReduction labels a result that fixed more or fewer findings than expected', () => {
  const more = {fixed: [...Array(8).fill({risk_level: 'high'}), {risk_level: 'medium'}]};
  assert.equal(compareReduction(expected, more).label, 'more than expected');
  const fewer = {fixed: [{risk_level: 'high'}]};
  assert.equal(compareReduction(expected, fewer).label, 'less than expected');
  const same = {fixed: [...Array(6).fill({risk_level: 'high'}), {risk_level: 'medium'}]};
  assert.equal(compareReduction(expected, same).label, 'as expected');
});
