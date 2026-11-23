const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { createServer, DEMO_SECRET } = require('../src/server');
const { signToken } = require('../test-support/token');

function request(server, path, token) {
  const { port } = server.address();
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path, headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

async function withServer(run) {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await run(server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('health check needs no token', () => withServer(async (server) => {
  const res = await request(server, '/health');
  assert.equal(res.status, 200);
}));

test('a request without a token is rejected', () => withServer(async (server) => {
  const res = await request(server, '/summary');
  assert.equal(res.status, 401);
}));

test('a request with a token signed by another secret is rejected', () => withServer(async (server) => {
  const res = await request(server, '/summary', signToken({ sub: 'eve' }, 'wrong-secret'));
  assert.equal(res.status, 401);
}));

test('a valid token gets the order summary', () => withServer(async (server) => {
  const res = await request(server, '/summary', signToken({ sub: 'alice' }, DEMO_SECRET));
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body).acme, { count: 2, total: 200 });
}));
