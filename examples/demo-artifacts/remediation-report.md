# Remediation Report: tuxcare-demo

## CVE-2026-GS-0002 (critical)

- Package: `python:urllib3@2.2.2`
- Status: `affected`
- Remediation: upgrade python:urllib3 to >=2.2.3
- Evidence paths:
  - `internal:tuxcare-supply-chain-platform@1.0.0 -> python:tuxcare-vuln-scanner@1.4.2 -> python:requests@2.32.3 -> python:urllib3@2.2.2`

## CVE-2026-GS-0001 (high)

- Package: `rpm:openssl-libs@3.2.2`
- Status: `affected`
- Remediation: upgrade rpm:openssl-libs to >=3.2.3
- Evidence paths:
  - `internal:tuxcare-supply-chain-platform@1.0.0 -> rpm:kernelcare-agent@3.1.4 -> rpm:openssl-libs@3.2.2`

