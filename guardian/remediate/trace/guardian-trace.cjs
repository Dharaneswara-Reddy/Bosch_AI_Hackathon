/* Opt-in runtime module-load recorder. Errors are swallowed so the app keeps running. */
const Module = require('node:module');
const fs = require('node:fs');
const original = Module._load;
const output = process.env.GUARDIAN_TRACE_FILE;
const maxBytes = Number(process.env.GUARDIAN_TRACE_MAX_BYTES || 10485760);
let written = 0;
Module._load = function(request, parent, isMain) {
  try {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (output && typeof resolved === 'string' && resolved.includes('node_modules')) {
      const row = JSON.stringify({module: request, resolved_path: resolved,
        parent_path: parent && parent.filename}) + '\n';
      if (written + Buffer.byteLength(row) <= maxBytes) {
        fs.appendFileSync(output, row);
        written += Buffer.byteLength(row);
      }
    }
  } catch (_) { /* tracing must never change application behavior */ }
  return original.apply(this, arguments);
};
