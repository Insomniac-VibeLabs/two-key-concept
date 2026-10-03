# Contributing

This repository is the concept line. Changes should stay inside the initial
two-key: ledger, Path A, Path B, judge hooks, monitored-agent hooks.

Do not add scanning, antivirus, or DLP hooks here. Those belong in
`Insomniac-VibeLabs/two-key`.

Update `README.md`, `docs/HOWTO.md`, `docs/FIT.md`, `docs/COMPARISON.md`,
`docs/THREAT_MODEL.md`, `docs/SCOPE.md`, and `CHANGES.md` when a claim changes.
Run `python -m unittest discover -s tests` before opening a pull request.
