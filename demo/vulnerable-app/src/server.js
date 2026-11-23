// Deliberately vulnerable demo app for the Guardian. Do not deploy.
// It imports express-jwt, which pulls in an old jsonwebtoken (a reachable, transitive CVE).
// lodash is declared but never imported here; minimist is a dev dependency only.
const http = require('http');
const expressJwt = require('express-jwt');

const checkToken = expressJwt({ secret: 'demo-only-not-a-real-secret' });

const server = http.createServer((req, res) => {
  checkToken(req, res, (err) => {
    res.writeHead(err ? 401 : 200, { 'Content-Type': 'text/plain' });
    res.end(err ? 'Unauthorized\n' : 'Hello from the Guardian demo app\n');
  });
});

server.listen(3000, '127.0.0.1');
