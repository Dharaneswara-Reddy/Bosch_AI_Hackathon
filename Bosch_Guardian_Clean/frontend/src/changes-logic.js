const plural = (n, noun) => `${n} ${noun}${n === 1 ? '' : 's'}`;

export function changesHeadline(changes) {
  const parts = [
    [changes.added.length, plural(changes.added.length, 'package') + ' added'],
    [changes.removed.length, `${changes.removed.length} removed`],
    [changes.upgraded.length, `${changes.upgraded.length} upgraded`],
    [changes.downgraded.length, `${changes.downgraded.length} downgraded`],
    [changes.new_findings.length, plural(changes.new_findings.length, 'new finding')],
    [changes.resolved_findings.length, `${changes.resolved_findings.length} resolved`],
  ].filter(([count]) => count > 0).map(([, text]) => text);
  const commit = changes.baseline_commit ? ` (${changes.baseline_commit.slice(0, 7)})` : '';
  return `Since ${changes.baseline_ref}${commit}: ${parts.join(', ') || 'no dependency or finding changes'}`;
}
