const crypto = require('crypto');

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

function signToken(payload, secret) {
  const body = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`;
  const signature = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
}

module.exports = { signToken };
