"""Evidence-based manifest parsers. No source-code reachability claims."""
import json
import re
import tomllib
from urllib.parse import quote

SUPPORTED = ('package-lock.json', 'package.json', 'requirements.txt', 'pyproject.toml')

def component(name, version, ecosystem, source, direct=True):
    version = str(version or '').strip()
    return {'id': f'{ecosystem}:{name}@{version or "unknown"}', 'name': name, 'version': version,
            'ecosystem': ecosystem, 'source_file': source, 'direct': direct,
            'purl': f'pkg:{"npm" if ecosystem == "npm" else "pypi"}/{quote(name, safe="/@")}' + (f'@{quote(version, safe="")}' if version else '')}

def parse_files(files):
    """Return components, dependency edges and warnings. Only exact lockfile versions are treated as resolved."""
    components, edges, warnings, manifests = {}, set(), [], []
    lock_dirs = {p.rsplit('/', 1)[0] if '/' in p else '' for p in files if p.endswith('package-lock.json')}
    for path, content in sorted(files.items()):
        base = path.rsplit('/', 1)[-1]
        if base not in SUPPORTED: continue
        manifests.append(path)
        try:
            if base == 'package-lock.json':
                data = json.loads(content)
                packages = data.get('packages', {})
                if packages:
                    path_to_id = {}
                    for loc, item in packages.items():
                        if not loc: continue
                        name = item.get('name') or loc.split('node_modules/')[-1]
                        version = item.get('version', '')
                        c = component(name, version, 'npm', path, 'node_modules/' not in loc.replace('node_modules/', '', 1))
                        components[c['id']] = c
                        path_to_id[loc] = c['id']
                    root = packages.get('', {})
                    for name in {**root.get('dependencies', {}), **root.get('devDependencies', {})}:
                        loc = 'node_modules/' + name
                        if loc in path_to_id: components[path_to_id[loc]]['direct'] = True
                    for loc, item in packages.items():
                        if not loc or loc not in path_to_id: continue
                        for dep in item.get('dependencies', {}):
                            candidate = loc + '/node_modules/' + dep
                            while candidate not in path_to_id and '/node_modules/' in candidate:
                                candidate = candidate.rsplit('/node_modules/', 1)[0]
                                candidate = (candidate.rsplit('/node_modules/', 1)[0] + '/node_modules/' + dep) if '/node_modules/' in candidate else 'node_modules/' + dep
                            if candidate in path_to_id and candidate != loc:
                                edges.add((path_to_id[loc], path_to_id[candidate]))
                else:
                    warnings.append(f'{path}: older npm lockfile without packages map; using package.json declarations where available')
            elif base == 'package.json':
                directory = path.rsplit('/', 1)[0] if '/' in path else ''
                if directory in lock_dirs: continue
                data = json.loads(content)
                for name, spec in {**data.get('dependencies', {}), **data.get('devDependencies', {})}.items():
                    c = component(name, '', 'npm', path)
                    components[c['id']] = c
                warnings.append(f'{path}: package.json has version ranges, not resolved versions; vulnerability matching skipped')
            elif base == 'requirements.txt':
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(('-', 'git+', 'http:', 'https:')): continue
                    match = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(==\s*([^;\s]+))?', line)
                    if match:
                        c = component(match.group(1), match.group(3) or '', 'PyPI', path)
                        components[c['id']] = c
                        if not c['version']: warnings.append(f'{path}: {c["name"]} is not pinned')
            elif base == 'pyproject.toml':
                data = tomllib.loads(content)
                deps = data.get('project', {}).get('dependencies', [])
                for spec in deps:
                    match = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(==\s*([^;\s]+))?', spec)
                    if match:
                        c = component(match.group(1), match.group(3) or '', 'PyPI', path)
                        components[c['id']] = c
                        if not c['version']: warnings.append(f'{path}: {c["name"]} is not pinned')
        except (ValueError, TypeError, KeyError) as exc:
            warnings.append(f'{path}: could not parse ({exc})')
    if not manifests: warnings.append('No supported dependency manifests found')
    return list(components.values()), [{'source': a, 'target': b} for a,b in sorted(edges)], list(dict.fromkeys(warnings)), manifests
