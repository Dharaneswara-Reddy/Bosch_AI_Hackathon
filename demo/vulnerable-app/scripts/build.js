const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const srcDir = path.join(__dirname, '..', 'src');
const files = fs.readdirSync(srcDir).filter((name) => name.endsWith('.js'));

for (const name of files) {
  const check = spawnSync(process.execPath, ['--check', path.join(srcDir, name)], { encoding: 'utf8' });
  if (check.status !== 0) {
    process.stderr.write(`syntax error in src/${name}\n${check.stderr}`);
    process.exit(1);
  }
}

const { createServer } = require(path.join(srcDir, 'server.js'));
if (typeof createServer !== 'function') {
  process.stderr.write('src/server.js must export createServer\n');
  process.exit(1);
}
console.log(`build ok: ${files.length} source files checked, entry point loads`);
