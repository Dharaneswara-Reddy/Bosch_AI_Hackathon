# Guardian demo app (deliberately vulnerable, local only)

A tiny Node app used to demonstrate the Software Supply Chain Guardian end to end. It is
built to be scanned, **not run or deployed**.

| What | Package | Why it is here | Expected Guardian result |
|---|---|---|---|
| Reachable transitive vulnerability | `jsonwebtoken 0.1.0` (and `jws`, `moment`), pulled in by `express-jwt 0.1.3` | `src/server.js` imports `express-jwt`, which pulls the vulnerable `jsonwebtoken` | **relevant**: path `guardian-demo-app → express-jwt → jsonwebtoken`, introduced by `express-jwt`, reachability confirmed at `src/server.js:5` |
| Vulnerable production dependency that is never imported | `lodash 4.17.4` | Declared but not used by the code | **likely relevant**: reachability not detected (not proof it is unused) |
| Vulnerable dev-only dependency | `minimist 0.0.8` (devDependency) | Only used by tooling | **low relevance**: development scope from the lockfile |
| **Synthetic** malicious-style package | `expresss-session` (local `file:` dependency in `vendor/`) | Typosquat of `express-session` with a `postinstall` script, from outside the npm registry | `suspected_typosquat` + `unverified_install_script`, labelled **SYNTHETIC** |
| Unpinned CI step | `.github/workflows/ci.yml` uses `actions/checkout@v4` | Tag, not a commit SHA | `unpinned_ci_action` |

## The synthetic package is not malware

`vendor/expresss-session` is an inert test fixture: it contains no code, its install script
only prints a message, it is never published to any registry, and it is never installed or
run. Its `package.json` carries `"guardian": {"synthetic": true}` so every finding about it is
labelled SYNTHETIC.

## Safety rules for this demo

- Scan it locally only: in the UI choose **Scan the built-in demo app**, or run
  `guardian scan demo/vulnerable-app --out artifacts/demo`. Nothing is fetched from GitHub.
- The Guardian never installs dependencies or runs install scripts (`--ignore-scripts`).
- Do not `npm install` or start this app; do not deploy it anywhere.
- No real secrets: the token secret in `src/server.js` is a placeholder string.
- Do not point the Guardian at any real product system, production environment or
  third-party infrastructure. Allowed targets: this demo app, OWASP Juice Shop and OWASP
  RailsGoat, scanned locally.

## Regenerating the lockfile

`npm install --package-lock-only --ignore-scripts` (resolves versions from the registry
without installing anything or running scripts).
