import {test} from 'node:test';
import assert from 'node:assert/strict';
import {changesHeadline} from './changes-logic.js';

const changes = {baseline_ref: 'v1.2.0', baseline_commit: 'abc1234def', added: [1, 2, 3], removed: [1],
  upgraded: [1, 2, 3, 4, 5], downgraded: [], new_findings: ['a', 'b'], resolved_findings: [1, 2, 3, 4]};

test('headline summarises every non-empty change with the short baseline commit', () => {
  assert.equal(changesHeadline(changes),
    'Since v1.2.0 (abc1234): 3 packages added, 1 removed, 5 upgraded, 2 new findings, 4 resolved');
});

test('headline uses singular nouns, includes downgrades and omits empty parts', () => {
  assert.equal(changesHeadline({...changes, added: [1], removed: [], upgraded: [], downgraded: [1, 2],
    new_findings: ['a'], resolved_findings: []}),
  'Since v1.2.0 (abc1234): 1 package added, 2 downgraded, 1 new finding');
});

test('headline says so when nothing changed and tolerates a missing commit', () => {
  assert.equal(changesHeadline({...changes, baseline_commit: '', added: [], removed: [], upgraded: [],
    new_findings: [], resolved_findings: []}), 'Since v1.2.0: no dependency or finding changes');
});
