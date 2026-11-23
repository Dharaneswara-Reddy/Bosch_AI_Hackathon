# expresss-session (SYNTHETIC)

This is **not a real package** and **not malware**. It is an inert test fixture for the
Software Supply Chain Guardian demo:

- its name is one letter away from the popular `express-session` (typosquat pattern);
- it declares a `postinstall` script that only prints a message;
- it is referenced from the demo app as a local `file:` dependency, so it never comes
  from, and is never published to, the npm registry.

The Guardian never runs install scripts (`--ignore-scripts`), so this script is never executed.
