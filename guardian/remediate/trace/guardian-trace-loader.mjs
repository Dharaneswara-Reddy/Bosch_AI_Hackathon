/* ESM companion to guardian-trace.cjs; tracing failures never reject imports. */
import {appendFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

let written = 0;
const maxBytes = Number(process.env.GUARDIAN_TRACE_MAX_BYTES || 10485760);

export async function resolve(specifier, context, nextResolve) {
  const resolved = await nextResolve(specifier, context);
  try {
    const output = process.env.GUARDIAN_TRACE_FILE;
    const url = resolved.url || '';
    if (output && url.startsWith('file:') && url.includes('/node_modules/')) {
      const parent = context.parentURL?.startsWith('file:')
        ? fileURLToPath(context.parentURL) : null;
      const row = JSON.stringify({module: specifier, resolved_path: fileURLToPath(url),
        parent_path: parent}) + '\n';
      if (written + Buffer.byteLength(row) <= maxBytes) {
        appendFileSync(output, row);
        written += Buffer.byteLength(row);
      }
    }
  } catch (_) { /* tracing must never change application behavior */ }
  return resolved;
}
