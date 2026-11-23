const test = require('node:test');
const assert = require('node:assert/strict');
const { summarize, topCustomers, lookup } = require('../src/stats');

const ORDERS = [
  { customer: 'acme', amount: 120 },
  { customer: 'globex', amount: 45 },
  { customer: 'acme', amount: 80 },
  { customer: 'initech', amount: 45 },
];

test('summarize groups orders per customer', () => {
  assert.deepEqual(summarize(ORDERS), {
    acme: { count: 2, total: 200 },
    globex: { count: 1, total: 45 },
    initech: { count: 1, total: 45 },
  });
});

test('topCustomers orders by total then name and honours the limit', () => {
  const names = topCustomers(ORDERS, 2).map((row) => row.customer);
  assert.deepEqual(names, ['acme', 'globex']);
});

test('lookup reads nested paths and falls back', () => {
  assert.equal(lookup({ a: { b: [{ c: 7 }] } }, 'a.b[0].c'), 7);
  assert.equal(lookup({}, 'a.b', 'none'), 'none');
});
