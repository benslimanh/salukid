# Security Policy

## Reporting a Vulnerability

Please report security issues privately to the maintainers by opening a
**private security advisory** on this repository. We will respond within
72 hours and coordinate disclosure.

Do **not** open public issues for security-sensitive bugs.

## Hardening defaults in salukid

- The HTTP parser is bounded (URI, header, per-header, total caps) and
  fuzzed continuously via libFuzzer + ASan/UBSan (see `.github/workflows/security.yml`).
- No `strcpy`, `sprintf`, `gets`, or `strcat` are linked (checked by
  `make hardening-check`).
- Path traversal (`..`), null bytes, symlink traversal, and backslashes in
  request paths are refused.
- TLS is minimum TLS 1.2 with safe defaults; HSTS with preload when TLS enabled.
- Workers drop privileges (`nobody` by default) and chroot if configured.
- Containers run as non-root (uid 65532) with `readOnlyRootFilesystem`,
  dropped ALL capabilities, `seccompProfile: RuntimeDefault`, and AppArmor.
- Supply chain: cosign keyless signing + SLSA-3 provenance on every release,
  SPDX SBOM, grype/trivy/osv-scanner scans on every push.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | :white_check_mark: |
