+++
title = "OPSEC"
chapter = false
weight = 2
pre = "<b>2. </b>"
+++

## How to read this document

Every component in the Signet pipeline has two audiences:

- **Operators** : pentesters and red teamers *using* the feature on an engagement.
- **Developers** : contributors hardening the feature inside the Signet codebase.

Each section below is structured uniformly so both audiences can scan it:

- A one-line mechanism summary
- **OPSEC Considerations** : the artefacts, telemetry, and failure modes that will actually get the operator caught.
- **Improvements : For Operators** : tradecraft decisions the operator makes when *using* the feature.
- **Improvements : For Signet Developers** : code-level hardening work that would reduce the component's OPSEC surface inside the repo.

---

## Code Signing Overview

Signet applies Authenticode signatures to wrapped Mythic payloads using `osslsigncode`. The signature makes the binary appear trusted in Windows Explorer (Properties → Digital Signatures), suppresses some SmartScreen prompts on first run, and satisfies software deployment policies that require signed binaries.

**OPSEC Considerations**
- A self-signed Authenticode signature does **not** chain to a trusted root CA. Windows will still show "Unknown publisher" in UAC prompts and SmartScreen warnings unless the CA is manually trusted on the target.
- Certificate subject fields like CN, O, and C are visible to any analyst who right-clicks the binary and checks Properties → Digital Signatures → Details. Impersonating a real organization creates a forensic fingerprint that is trivially attributable if the cert is recovered.
- The signing certificate's serial number, thumbprint, and subject are logged by EDR products on process creation. Two payloads signed with the same cert are attributable to the same campaign.
- `osslsigncode` embeds the full certificate chain in the PE's `WIN_CERTIFICATE` structure. A defender who extracts the chain has the CA and code signing certificates and can fingerprint the CA across builds.

**Improvements : For Operators**
- Generate a **new CA and code signing cert per engagement** rather than reusing certificates across campaigns. Shared certificates are the single biggest attribution vector.
- Use certificate subject fields that are plausible for the target environment but not attributable to you : avoid fantasy names and avoid copying real organization names verbatim if attribution risk is a concern.
- Prefer `Clone from URL` mode when impersonating a specific vendor: the cloned subject fields match the real certificate exactly, which is harder for an analyst to flag as anomalous than hand-typed fields.

**Improvements : For Signet Developers**
- Add a per-build random serial number jitter to the CA certificate so two CAs generated seconds apart don't share adjacent serial numbers.
- Add an IOC export option that dumps the signing certificate thumbprint, serial number, and subject to a text file alongside the signed payload, so operators can track what they deployed.

---

## Generate CA + Cert Mode

*Creates a self-signed CA certificate, then issues a code signing certificate from it. Both certificates are generated inside the Mythic Docker container at build time.*

**OPSEC Considerations**
- The CA has `BasicConstraints(ca=True, path_length=0)`, which means it can only issue end-entity certificates. This is correct but unusual for a "real" CA certificate, which typically has `path_length=None` or a higher value. A forensic analyst who inspects the chain may note this.
- The CA validity is set to `3× the code signing cert validity`, so a 1-year signing cert produces a 3-year CA. The fixed multiplier is a minor fingerprint across Signet-generated chains.
- Both the CA and code signing cert use the same RSA key size and hash algorithm. Real PKI hierarchies often use a stronger key for the CA than for end-entity certs (e.g. 4096-bit CA, 2048-bit code signing).
- The CA subject is the code signing CN with `" CA"` appended, for example `"Microsoft Corporation CA"`. This is a recognizable pattern.

**Improvements : For Operators**
- Set `6.0 Key Size = 4096` for higher verisimilitude. Most real code signing certificates use 4096-bit keys.
- Set `6.2 Certificate Validity (days)` to a realistic value between 365 and 730 rather than leaving the default. Code signing certs with 10-year validity are unusual.
- Use the `7.0 Export CA Certificate` option to save the CA for reuse across payloads **within a single engagement**. Across engagements, generate a fresh CA.

**Improvements : For Signet Developers**
- Allow separate key sizes for the CA and the code signing cert.
- Randomise the CA suffix instead of always appending `" CA"`.
- Add an option to set `path_length=None` on the CA for better mimicry of real CA certificates.

---

## Upload CA Mode

*Loads an operator-provided CA in PFX, PEM, or DER format and issues a new code signing certificate from it.*

**OPSEC Considerations**
- The format auto-detection (`load_ca_from_bytes`) tries PFX → PEM → DER. If the file is ambiguous (e.g. a PEM file with garbage appended), the wrong parser may succeed silently and produce an unexpected certificate.
- When `Inherit CA Attributes = True`, the code signing cert's subject is an exact copy of the CA's subject. In a real PKI the issuer (CA) and subject (end-entity) always differ. Identical subjects are a forensic anomaly.
- The CA password is passed as a build parameter. Mythic stores build parameters in its database; an operator with database access to the Mythic server can recover the CA password.

**Improvements : For Operators**
- When inheriting CA attributes, manually adjust at least the CN to distinguish the code signing cert from the CA, for example setting the CA CN to `"Acme Corp Root CA"` and the code signing CN to `"Acme Corp"`.
- Use a strong password on the CA file. Even though Mythic stores it, a password-protected CA is defense-in-depth if the PFX file is exfiltrated from the container.
- Verify the uploaded CA's validity period covers the engagement timeline. An expired CA produces a signed binary whose signature is already invalid at signing time.

**Improvements : For Signet Developers**
- Warn in the build log when inherited attributes produce identical CA and code signing subjects.
- Validate that the CA certificate is not expired before issuing a code signing cert from it.
- Strip the CA password from build logs and `build_message` output.

---

## Upload Signing Cert Mode

*Uses a ready-to-use PFX/P12 code signing certificate directly : no certificate generation.*

**OPSEC Considerations**
- The uploaded PFX is validated via `load_pfx_from_bytes` to confirm it contains a certificate and key, but is otherwise used as-is. If the PFX contains a real, trusted code signing certificate, the signed payload will chain to a public root CA. This is effective for evasion but creates revocation and legal exposure risk.
- The PFX password is stored in Mythic's build parameter database, same caveat as Upload CA mode.
- If the PFX contains a certificate with the `CODE_SIGNING` EKU, `osslsigncode` will produce a valid Authenticode signature. If the EKU is missing or wrong, the signature is technically invalid but Windows may still display it.

**Improvements : For Operators**
- Verify the uploaded PFX has the correct Extended Key Usage (`CODE_SIGNING`, OID 1.3.6.1.5.5.7.3.3) before building. An invalid EKU won't fail the build but produces a signature that sophisticated verification tools will flag.
- If using a legitimately-purchased code signing certificate, accept the risk that the CA can revoke it post-engagement. Plan for the binary to stop appearing signed once revocation propagates.
- Never upload a code signing certificate that is shared with production software. Use a dedicated cert for red team operations.

**Improvements : For Signet Developers**
- Add a build-time check that the uploaded certificate includes the `CODE_SIGNING` EKU and warn if it's missing.
- Add a check for certificate expiry and warn if the cert expires within 30 days.

---

## Clone from URL Mode

*Scrapes X.509 subject fields from a remote HTTPS server's certificate and generates a self-signed code signing certificate with matching metadata.*

**OPSEC Considerations**
- `ssl.CERT_NONE` disables certificate verification, so the scrape works against self-signed or expired remote certs. This also means a MITM between the Mythic container and the target URL can inject arbitrary subject fields.
- The scraped fields are limited to the Subject DN. The code signing cert does **not** clone Authority Information Access (AIA), CRL Distribution Points, or Subject Alternative Names from the remote cert. A forensic analyst who compares the signed binary's certificate chain to the real vendor's chain will see these differences immediately.
- If the TLS connection fails due to a timeout, DNS failure, or blocked port, the builder falls back to using the hostname as the CN with default values. This silent fallback may produce a certificate with unexpected metadata.

**Improvements : For Operators**
- Run the Clone from URL build from a network position where the team server's IP is not attributable, such as a VPN, cloud redirector, or dedicated build host.
- Verify the cloned attributes in the build log before delivering the payload. The fallback-on-failure behavior means you may not get the fields you expected.
- Clone from a URL whose certificate has rich subject fields, at minimum CN, O, and C. CDN certificates like Cloudflare's often have minimal subjects such as `CN=cloudflare-dns.com`, which are less convincing.

**Improvements : For Signet Developers**
- Add SAN (Subject Alternative Name) cloning for better fidelity.
- Fail the build (rather than falling back to hostname) when the remote certificate cannot be retrieved, so the operator is not surprised.
- Add a connection timeout parameter or use a shorter default than 15 seconds.
- Clone the certificate's validity period (NotBefore / NotAfter) for improved mimicry.

---

## Authenticode Signature (osslsigncode)

*`osslsigncode sign` applies an Authenticode signature to the wrapped payload binary. The PFX, payload, and signed output are written to a temp directory during the signing operation.*

**OPSEC Considerations**
- The temp directory exists for the duration of the `osslsigncode` subprocess call. On a shared Docker container, another process with access to `/tmp` could read the PFX and unsigned payload during this window.
- `osslsigncode` embeds the full certificate chain in the PE's `WIN_CERTIFICATE` directory entry. A defender with the signed binary can extract the CA certificate, code signing certificate, and the timestamp counter-signature if one was applied.
- Timestamping is enabled by default with `http://timestamp.digicert.com`. When active, the **Mythic Docker container makes an outbound HTTP request** to the timestamp server at build time. This leaks the container's IP to the timestamp provider's logs and confirms that a signing operation occurred at a specific time.
- The timestamp URL itself (`http://timestamp.digicert.com`) is **not** embedded in the signed binary. Only the timestamp counter-signature (RFC 3161 response) is embedded.
- The `-pass ""` flag is passed when no password is set. Some older `osslsigncode` versions log this to stderr, which Mythic captures in the build step output.

**Improvements : For Operators**
- **Disable timestamping** (`6.3 Timestamp Server = ""`) when the team server's network egress must not be disclosed. The tradeoff: without a timestamp, the signature becomes invalid after the code signing cert expires.
- When timestamping is required, route the timestamp request through a proxy or redirector so the timestamp provider sees the proxy's IP, not the team server's.
- Use `6.4 Signature Description` to embed a plausible description such as `"Microsoft Windows Update"`. This appears in the file's Digital Signatures details and adds verisimilitude.
- Verify the signed binary with `osslsigncode verify -in payload.exe` before delivery to confirm the signature is well-formed.

**Improvements : For Signet Developers**
- Scrub the temp directory with `shutil.rmtree` in a `finally` block. Python's `tempfile.TemporaryDirectory` already does this, but add explicit verification.
- Add an optional proxy parameter for the timestamp request.
- Add a post-sign verification step (`osslsigncode verify`) and report the result in the Finalizing build step.
- Support dual-signing with SHA-1 and SHA-256 via `osslsigncode sign` → `osslsigncode sign -nest` for compatibility with older Windows versions.

---

## Certificate Export (Mythic File Store)

*When `7.0 Export CA Certificate` or `7.1 Export Signing Certificate` is enabled, the generated certificates are registered in the Mythic file store via `SendMythicRPCFileCreate`.*

**OPSEC Considerations**
- Exported certificates persist in the Mythic database until manually deleted. If the Mythic server is compromised post-engagement, the attacker has the CA private key and can issue additional code signing certificates.
- The exported files are named `signet_ca.pfx` and `signet_codesign.pfx` with fixed filenames. An analyst with access to the Mythic file store can identify Signet-generated certificates by filename alone.
- `TaskID=1` is hardcoded in the `SendMythicRPCFileCreate` call. This associates the exported file with Task 1, which may not be the correct task context for the build.

**Improvements : For Operators**
- Only export certificates if you genuinely need to reuse them across multiple builds within the same engagement.
- Delete exported certificates from the Mythic file store at the end of the engagement.

**Improvements : For Signet Developers**
- Randomize the exported filename, for example `signet_ca_<8hex>.pfx`, to reduce fingerprinting.
- Password-protect exported PFX files with an auto-generated password reported only in the build log.
- Fix the `TaskID` to use the actual build's task context rather than hardcoding `1`.

---

## Custom Payload Upload

*When `0.0 Custom Payload = True`, the operator uploads any binary file directly via `0.1 Custom Payload File`. The file UUID is passed to `getFileFromMythic` at build time to retrieve the raw bytes, which are then signed in place of the wrapped payload.*

**OPSEC Considerations**
- The uploaded file is stored in Mythic's file store and persists until deleted. If the Mythic server is compromised, the unsigned binary is recoverable.
- No format validation is performed on the uploaded file. If the file is not an Authenticode-compatible format like PE, MSI, or CAB, `osslsigncode` will fail at the signing step, but the unsigned file remains in the Mythic file store.
- The uploaded file bypasses Mythic's wrapping infrastructure entirely. There is no callback registration or agent tracking. Mythic has no awareness of what the signed binary does.

**Improvements : For Operators**
- Use this feature to sign binaries from external C2 frameworks (Cobalt Strike, Havoc, Sliver) or custom tooling that doesn't have a Mythic agent.
- Verify the uploaded file is a valid PE or MSI before building : `osslsigncode` will fail on non-signable formats.
- Delete the uploaded file from the Mythic file store after the build completes if the unsigned binary should not persist.

**Improvements : For Signet Developers**
- Add MZ header validation on the uploaded file before passing it to `osslsigncode`.
- Add an auto-delete option that removes the uploaded file from the Mythic file store after a successful build.

---

## Wrapped Payload Compatibility

*Signet wraps any Mythic agent that produces a signable binary. The `wrapper_payload_requirements` definition determines which payloads are compatible based on OS, architecture, and format metadata.*

**OPSEC Considerations**
- Signet signs whatever bytes it receives from `self.wrapped_payload` without inspecting the file format. If the wrapped agent produces raw shellcode, an archive, or a non-PE file, `osslsigncode` will either fail silently or produce a malformed output.
- The wrapped agent's own build artifacts, including strings, imports, and PE metadata, are preserved through the signing process. Signing does not modify the payload's content. It only appends the Authenticode signature structure.

**Improvements : For Operators**
- Ensure the wrapped agent produces a PE or MSI output. Signing non-PE files will fail at the `osslsigncode` step.
- If the wrapped agent is `erebus_wrapper`, disable Erebus's own code signing (`6.0 Codesign Loader = False`) to avoid double-signing, which produces two `WIN_CERTIFICATE` entries and is an anomaly.

**Improvements : For Signet Developers**
- Add a file-format check for MZ headers and MSI magic bytes before signing and fail with a clear error for unsupported formats.
- Add support for signing CAB, APPX, and MSIX files via `osslsigncode` or `signtool` equivalents.
