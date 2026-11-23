# Dependency and CI change tuning case

This small target pair is for tuning P3 detectors. The clean snapshot contains
one pinned dependency and one SHA-pinned GitHub Action. The suspicious snapshot
adds an unexpected dependency and changes the action to a moving tag. Use the
clean snapshot's Git commit as the baseline for `git_diff`.
