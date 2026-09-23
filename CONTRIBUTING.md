# Contributing

Contributions that improve determinism, provenance, reproducibility, validation, portability, or documentation are welcome.

Before opening a pull request:

1. Run `python -m unittest discover -s tests -v`.
2. Rebuild the release packs with `python scripts/build_release_packs.py`.
3. Confirm release hashes are stable across repeated builds.
4. Do not include credentials, private datasets, personal information, or proprietary source material.
5. Keep claims narrow and supported by the pack contract and provenance.

By submitting a contribution, you agree that your contribution may be distributed under the repository's applicable licenses.
