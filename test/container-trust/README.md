# Container CA trust regression test

[check-trust.sh](check-trust.sh) checks the image's OpenSSL trust bundle and hashed CA directory independently. It makes no network requests and changes no trust files. It requires a POSIX shell, OpenSSL, `dirname`, and `grep`.

Run it inside the image, with this directory mounted read-only:

```sh
docker run --rm --network none --entrypoint /bin/sh \
  -v "$PWD/test/container-trust:/trust:ro" IMAGE \
  -c '/trust/check-trust.sh && update-ca-certificates --fresh && /trust/check-trust.sh'
```

The second run detects trust restored by certificate-store regeneration. Use a disposable container for regeneration. The script defaults to `/etc/ssl/certs/ca-certificates.crt` and `/etc/ssl/certs`; optional positional arguments select a different bundle and hashed directory. `OPENSSL` can select an executable. These overrides also allow host-side inspection of extracted stores, but that does not test the image's own OpenSSL or regeneration command.

## Checks

- All 14 [eMudhra advisory](https://emudhra.we-have-a-problem.com/) server chains must fail with OpenSSL trust error 20 in **both** store modes. Certificate expiry, hostname mismatch, malformed fixtures and unsupported command options are failures of the test, not evidence of distrust.
- Every advisory chain must first **pass** against the explicit historical trust roots in [legacy-roots.pem](fixtures/controls/legacy-roots.pem). This confirms that each fixture still detects the original exposure.
- A legitimate [download.falco.org chain](fixtures/controls/download.falco.org.pem) must pass server-purpose and hostname verification through each tested store. It must fail against the unrelated legacy roots, checking that implicit system trust cannot rescue an explicit store.
- The unaffected [ISRG Root X1](fixtures/controls/isrg-root-x1.pem) and [DigiCert Global Root G2](fixtures/controls/digicert-global-root-g2.pem) must remain trusted in both stores. Roots use purpose `any`, because a CA's key usage need not allow it to act as a server leaf.

All verifications use **2026-10-23T12:00:00Z** (`1792756800`), when the saved server chains are valid. The short-lived advisory leaves would otherwise stop detecting regressions after expiry. Do not change this time without revalidating every fixture and control.

The script disables default CA files and directories. It also disables the default CA store on OpenSSL versions that provide that option; OpenSSL 1.1.1 has no separate CA-store option. File checks cannot fall back to the image's directory, and directory checks cannot fall back to its bundle. Positive directory checks require working hash entries, not just PEM files in a directory.

This checks OpenSSL chain validation and trust-store contents. It does not test revocation, Certificate Transparency enforcement, Go's verifier, or a network TLS handshake. A separate live HTTPS smoke test can check the current-time network path.

## Fixture provenance

Only public certificates are included; there are no private keys. **Never install the legacy roots into an image's trust store.** They are deliberately trusted only in isolated test invocations.

| Files | Source |
|---|---|
| [rejected/](fixtures/rejected/) — 14 complete server chains, leaf first | The advisory's published offline chain archive, retrieved 2026-10-23. Its README dates the captures to October 20 and the two `noct` chains to October 22. The non-`aaa` chains use the emSign ECC G3 trust path; the `aaa` variants use AAA Certificate Services. The `noct` variants omit SCTs. |
| [legacy-roots.pem](fixtures/controls/legacy-roots.pem) | AAA Certificate Services and emSign ECC Root CA - G3 public roots, extracted from [certifi 2024.12.14](https://github.com/certifi/python-certifi/blob/2024.12.14/certifi/cacert.pem), which carries the historical Mozilla root collection. |
| [isrg-root-x1.pem](fixtures/controls/isrg-root-x1.pem), [digicert-global-root-g2.pem](fixtures/controls/digicert-global-root-g2.pem) | Unmodified public root certificates from the same historical certifi collection. |
| [download.falco.org.pem](fixtures/controls/download.falco.org.pem) | Public chain captured from `download.falco.org:443` with SNI on 2026-10-26: leaf → Let's Encrypt YR2 → cross-signed ISRG Root YR → trusted ISRG Root X1. The fixture contains the three server-supplied certificates, not the self-signed root. The leaf is valid September 25–December 24, 2026. |

[SHA256SUMS](fixtures/SHA256SUMS) records the curated PEM file hashes. To verify them from this directory:

```sh
(cd fixtures && sha256sum -c SHA256SUMS)
```

When adding or replacing fixtures, verify the positive result against their explicit historical anchors, the rejection against fixed stores, and the independent positive server chain at the fixed time. Keep the expected advisory count synchronized only when intentionally changing coverage.
