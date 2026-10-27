+++
title = "Signet"
chapter = true
weight = 100
+++

Signet is a code signing wrapper payload type for [Mythic C2](https://github.com/its-a-feature/Mythic). It takes any wrapped EXE, DLL, MSI, or other Authenticode-compatible binary and applies a code signing signature via `osslsigncode`, using a generated, uploaded, or URL-cloned certificate.

## What's in the box

### Signing modes

- **Generate CA + Cert**: creates a self-signed CA certificate then issues a code signing certificate from it, with operator-defined subject fields including CN, C, O, OU, ST, L, and Email.
- **Upload CA**: accepts an operator-provided CA in PFX/P12 or PEM format and issues a new code signing certificate from it. Optionally inherits subject attributes from the CA into the code signing cert.
- **Upload Signing Cert**: uses a ready-to-use PFX/P12 code signing certificate directly, bypassing all certificate generation.
- **Clone from URL**: scrapes the X.509 subject fields from a remote HTTPS certificate, for example `https://www.microsoft.com`, and generates a self-signed code signing certificate with matching metadata.

### Certificate handling

- Full X.509 certificate chain: CA → code signing cert, with `BasicConstraints`, `KeyUsage`, and `ExtendedKeyUsage(CODE_SIGNING)` extensions.
- RSA key sizes: `2048` or `4096`.
- Hash algorithms: `SHA-256`, `SHA-384`, `SHA-512`.
- PFX/P12, PEM, and DER CA input formats supported.
- Optional export of generated CA and signing certificates back to the Mythic file store for reuse across builds.

### Custom payload upload

Upload any EXE, DLL, MSI, or other binary file directly via the `0.0 Custom Payload` toggle. Signet signs it without requiring a Mythic-wrapped agent. Useful for signing binaries from other C2 frameworks or standalone tools. The uploaded file is retrieved via `SendMythicRPCFileGetContent` at build time.

### Authenticode signing

- `osslsigncode` applies the Authenticode signature to the wrapped payload.
- Configurable RFC 3161 timestamp server (default: `http://timestamp.digicert.com`).
- Optional signature description string embedded in the Authenticode signature.
- Supports EXE, DLL, MSI, and other `osslsigncode`-compatible file formats.

## Getting started

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/Signet.git
```

Then create a Signet payload from the Mythic UI, select a wrapped agent payload, and configure the signing mode and certificate options.

## Documentation

- **[Development](/wrappers/signet/development/)** : build pipeline, full BuildParameter reference, build-step reference, and project structure.
- **[OPSEC](/wrappers/signet/opsec/)** : per-component tradecraft considerations and hardening improvements for operators and developers.

## Authors

- [@Lavender-exe](https://github.com/Lavender-exe) : Project Author

{{% children %}}
