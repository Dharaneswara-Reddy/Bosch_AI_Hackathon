// Deliberately vulnerable demo app for the Guardian. Do not deploy.
// It imports express-jwt, which pulls in an old jsonwebtoken (a reachable, transitive CVE).
// lodash (src/stats.js) is imported but only used for order statistics; minimist is dev-only.
const http = require('http');
const expressJwt = require('express-jwt');
const { summarize } = require('./stats');

const DEMO_SECRET = 'demo-only-not-a-real-secret';
const ORDERS = [
  { customer: 'acme', amount: 120 },
  { customer: 'acme', amount: 80 },
  { customer: 'globex', amount: 45 },
];

function respond(res, status, type, body) {
  res.writeHead(status, { 'Content-Type': type });
  res.end(body);
}

function createServer(secret = DEMO_SECRET) {
  const checkToken = expressJwt({ secret });
  return http.createServer((req, res) => {
    if (req.url === '/health') return respond(res, 200, 'text/plain', 'ok\n');
    return checkToken(req, res, (err) => {
      if (err) return respond(res, 401, 'text/plain', 'Unauthorized\n');
      if (req.url === '/summary') {
        return respond(res, 200, 'application/json', JSON.stringify(summarize(ORDERS)));
      }
      return respond(res, 200, 'text/plain', 'Hello from the Guardian demo app\n');
    });
  });
}

module.exports = { createServer, DEMO_SECRET };

if (require.main === module) {
  createServer().listen(Number(process.env.PORT || 3000), process.env.HOST || '127.0.0.1');
}
