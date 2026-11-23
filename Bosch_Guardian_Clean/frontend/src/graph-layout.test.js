import {test} from 'node:test';
import assert from 'node:assert/strict';
import {layoutSubgraph, selectSubgraph} from './graph-layout.js';

const node = id => ({component_id: id, name: id, version: '1'});
const edge = (parent_id, child_id) => ({parent_id, child_id, edge_source: 'resolver'});
const graph = {
  nodes: ['lock', 'rails', 'rack', 'json', 'other', 'leaf'].map(node),
  edges: [edge('lock', 'rails'), edge('rails', 'rack'), edge('rack', 'json'),
    edge('lock', 'other'), edge('other', 'leaf'), edge('json', 'rails')],
};
const ids = sub => [...sub.ids].sort();

test('vulnerable view keeps only the shortest route from a root to each vulnerable package', () => {
  const sub = selectSubgraph(graph, {vulnerable: new Set(['json'])});
  assert.deepEqual(ids(sub), ['json', 'lock', 'rack', 'rails']);
  assert.deepEqual(sub.edges.map(e => `${e.parent_id}>${e.child_id}`), ['lock>rails', 'rails>rack', 'rack>json']);
});

test('focus shows the route in plus direct parents and children', () => {
  const sub = selectSubgraph(graph, {focus: 'rack', vulnerable: new Set()});
  assert.deepEqual(ids(sub), ['json', 'lock', 'rack', 'rails']);
  const focusOther = selectSubgraph(graph, {focus: 'other', vulnerable: new Set()});
  assert.deepEqual(ids(focusOther), ['leaf', 'lock', 'other']);
});

test('a finding path shows exactly that chain', () => {
  const sub = selectSubgraph(graph, {path: ['lock', 'other', 'leaf'], vulnerable: new Set()});
  assert.deepEqual(ids(sub), ['leaf', 'lock', 'other']);
  assert.equal(sub.edges.length, 2);
});

test('all view keeps every node and edge', () => {
  const sub = selectSubgraph(graph, {all: true, vulnerable: new Set()});
  assert.equal(sub.ids.size, 6);
  assert.equal(sub.edges.length, 6);
});

test('layout puts each dependency one column right of its parent, even with a cycle', () => {
  const sub = selectSubgraph(graph, {all: true, vulnerable: new Set()});
  const pos = layoutSubgraph(sub);
  assert.equal(pos.get('lock').x, 0);
  assert.ok(pos.get('rails').x > pos.get('lock').x);
  assert.ok(pos.get('rack').x > pos.get('rails').x);
  assert.ok(pos.get('json').x > pos.get('rack').x);
  assert.equal(pos.get('other').x, pos.get('rails').x);
  assert.notEqual(pos.get('other').y, pos.get('rails').y);
});
