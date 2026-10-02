#!/usr/bin/env bash
# SPDX SBOM stub generator. For a real SBOM, install 'syft' or 'spdx-sbom-generator':
#   syft binary:./secure_httpd -o spdx-json=salukid.spdx.json
set -euo pipefail
ver=$(grep -oP 'SALUKID_VERSION\s+"\K[^"]+' include/common.h)
cat <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: salukid-${ver}
DocumentNamespace: https://salukid.example/spdx/${ver}
Creator: Tool: salukid-make-sbom
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)

PackageName: salukid
SPDXID: SPDXRef-Package-salukid
PackageVersion: ${ver}
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION
PackageSupplier: Organization: salukid contributors
EOF
