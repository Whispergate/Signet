# Signet

Signet is a code signing wrapper for [Mythic C2](https://github.com/its-a-feature/Mythic). It takes any wrapped agent binary or uploaded file and applies an Authenticode signature via `osslsigncode`.

## Signing modes

- **Generate CA + Cert**: creates a self-signed CA and issues a code signing certificate from it.
- **Upload CA**: accepts an operator-provided CA in PFX or PEM format and issues a code signing certificate from it.
- **Upload Signing Cert**: uses a PFX code signing certificate directly, no generation.
- **Clone from URL**: scrapes X.509 subject fields from a remote HTTPS certificate and generates a matching self-signed code signing cert.

## Custom payload upload

Upload any binary file directly via the `0.0 Custom Payload` toggle instead of wrapping a Mythic agent. Useful for signing output from other C2 frameworks or standalone tools.

## Installation

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/Signet.git
```

Then create a Signet payload from the Mythic UI, select a wrapped agent or upload a custom binary, and configure the signing mode and certificate options.

## Dependencies

| Package | Purpose |
|---|---|
| `mythic_container` 0.6.16 | Mythic SDK |
| `cryptography` | X.509 certificate generation, PKCS#12 |
| `osslsigncode` | Authenticode signing |

## Documentation

Full documentation is served through Mythic's documentation container:

- **Development**: build pipeline, parameter reference, project structure.
- **OPSEC**: per-component tradecraft considerations for operators and developers.

## Authors

- [@Lavender-exe](https://github.com/Lavender-exe)
