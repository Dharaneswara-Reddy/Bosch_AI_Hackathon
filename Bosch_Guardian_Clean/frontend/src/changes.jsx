import React from 'react';
import {changesHeadline} from './changes-logic.js';

const versionLabel = p => `${p.name}@${p.version}`;

function ChangeList({title, items, render}) {
  if (!items.length) return null;
  return <div className="change-group"><h3>{title} ({items.length})</h3>
    <ul>{items.map((item, i) => <li key={i}>{render(item)}</li>)}</ul></div>;
}

function VersionTable({title, items}) {
  if (!items.length) return null;
  return <div className="change-group"><h3>{title} ({items.length})</h3>
    <table><tbody>{items.map(u => <tr key={u.ecosystem + u.name}>
      <td><code>{u.name}</code></td><td>{u.from_version} → <strong>{u.to_version}</strong></td></tr>)}</tbody></table></div>;
}

export function ChangesPanel({changes}) {
  if (!changes) return null;
  return <section className="panel changes-panel">
    <h2>Changed since baseline</h2>
    <p className="changes-headline">{changesHeadline(changes)}</p>
    <div className="change-grid">
      <ChangeList title="Added" items={changes.added} render={p => <code>{versionLabel(p)}</code>}/>
      <ChangeList title="Removed" items={changes.removed} render={p => <code>{versionLabel(p)}</code>}/>
      <VersionTable title="Upgraded" items={changes.upgraded}/>
      <VersionTable title="Downgraded" items={changes.downgraded}/>
      <ChangeList title="New findings" items={changes.new_findings} render={id => <code>{id}</code>}/>
      <ChangeList title="Resolved" items={changes.resolved_findings}
        render={r => <><strong>{r.finding}</strong> in <code>{r.package}</code></>}/>
    </div>
  </section>;
}
