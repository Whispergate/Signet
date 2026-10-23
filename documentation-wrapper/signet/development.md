+++
title = "Development"
chapter = false
weight = 1
pre = "<b>1. </b>"
+++

## Project overview

Signet is a Mythic C2 wrapper payload type that takes any wrapped payload binary and applies an Authenticode code signing signature. It runs entirely inside a Docker container using `osslsigncode` for signing and the Python `cryptography` library for certificate generation.

### Capabilities

- **Four signing modes**: Generate CA + Cert (self-signed hierarchy), Upload CA (issue from your own CA), Upload Signing Cert (use a PFX directly), Clone from URL (spoof a remote certificate's subject).
- **Full X.509 chain**: proper CA → code signing cert hierarchy with `BasicConstraints`, `KeyUsage`, and `ExtendedKeyUsage(CODE_SIGNING)` extensions.
- **Multiple CA input formats**: accepts PFX/P12, PEM, and DER with automatic format detection.
- **Attribute inheritance**: when uploading a CA, optionally inherit CN, C, O, OU, ST, L, and Email from the CA's subject into the code signing certificate.
- **Certificate export**: optionally register generated CA and signing certificates in the Mythic file store for reuse across builds.
- **Authenticode signing**: `osslsigncode` signs EXE, DLL, MSI, and other compatible formats with configurable hash algorithm, timestamp server, and description string.

## Build pipeline

```
       ┌───────────────────────┐
       │   Start Build         │
       └───────────┬───────────┘
                   │
       ┌───────────▼───────────┐
       │  Gathering Payload    │
       │  (wrapped payload     │
       │   from Mythic)        │
       └───────────┬───────────┘
                   │
    ┌──────────────▼──────────────┐
    │  Signing Mode?              │
    │  Generate / Upload CA /     │
    │  Upload Cert / Clone URL    │
    └──┬────────┬────────┬─────┬──┘
       │        │        │     │
┌──────▼──┐ ┌───▼────┐ ┌▼───┐ ┌▼──────────┐
│Generate │ │Upload  │ │Use │ │Clone URL  │
│CA + Cert│ │CA →    │ │PFX │ │→ Generate │
│         │ │Issue   │ │as  │ │matching   │
│Self-sign│ │Code    │ │is  │ │self-signed│
│CA, then │ │Signing │ │    │ │cert       │
│issue CS │ │Cert    │ │    │ │           │
└────┬────┘ └───┬────┘ └┬───┘ └─────┬─────┘
     │          │       │           │
     └──────────┼───────┼───────────┘
                │       │
     ┌──────────▼───────▼──────────┐
     │  Optional: Export CA /      │
     │  Signing Cert to Mythic     │
     └──────────────┬──────────────┘
                    │
     ┌──────────────▼──────────────┐
     │  Signing Payload            │
     │  osslsigncode sign          │
     │  -pkcs12 <pfx>              │
     │  -h <hash_algo>             │
     │  -t <timestamp_url>         │
     │  -n <description>           │
     └──────────────┬──────────────┘
                    │
     ┌──────────────▼──────────────┐
     │  Finalizing                 │
     │  Return signed bytes        │
     │  to Mythic                  │
     └─────────────────────────────┘
```

### Pipeline stages

1. **Gathering Payload** : when `0.0 Custom Payload` is enabled, the builder retrieves the uploaded file via `getFileFromMythic(agentFileId=uuid)`. Otherwise, Mythic provides the raw wrapped payload bytes via `self.wrapped_payload`. The builder verifies the payload is present and reports its size.
2. **Preparing Certificate** : based on `1.0 Signing Mode`, one of four code paths runs:
   - *Generate CA + Cert*: `generate_ca()` creates a self-signed CA, then `create_code_signing_cert()` issues a code signing cert from it.
   - *Upload CA*: `load_ca_from_bytes()` loads the uploaded CA with PFX/PEM/DER auto-detection, optionally `extract_ca_attributes()` copies subject fields, then `create_code_signing_cert()` issues a cert.
   - *Upload Signing Cert*: `load_pfx_from_bytes()` validates the uploaded PFX and uses it directly.
   - *Clone from URL*: an SSL connection to the target host extracts X.509 subject fields via `ssl`/`socket`, then `generate_ca()` + `create_code_signing_cert()` produce a matching self-signed cert.
3. **Signing Payload** : `sign_payload()` writes the payload and PFX to a temp directory, invokes `osslsigncode sign` with the configured options, and returns the signed bytes.
4. **Finalizing** : the signed payload bytes are set on `BuildResponse.payload` and the build is marked successful.

Each stage reports progress to Mythic via `SendMythicRPCPayloadUpdatebuildStep`.

## Build parameter reference

Every BuildParameter defined in [builder.py](Payload_Type/signet/signet/builder.py) is listed once, in order.

### 0.0 – 0.1 · Custom Payload

- **0.0 Custom Payload** : `Boolean` (default `False`): when enabled, the operator uploads a custom binary file to sign instead of using the Mythic-wrapped payload. Use this to sign binaries from external tools or other C2 frameworks.
- **0.1 Custom Payload File** : `File`: the binary file (EXE, DLL, MSI, etc.) to sign. Replaces the wrapped payload entirely. Retrieved at build time via `getFileFromMythic`. Only visible when `0.0 Custom Payload = True`.

### 1.0 · Signing Mode

- **1.0 Signing Mode** : `ChooseOne`: `"Generate CA + Cert"`, `"Upload CA"`, `"Upload Signing Cert"`, or `"Clone from URL"`. Determines which downstream parameter groups are visible and which code path runs during the build.

### 2.0 – 2.2 · Certificate Authority (Upload CA mode)

Only visible when `1.0 Signing Mode = Upload CA`.

- **2.0 CA File** : `File`: CA certificate file. PFX/P12 files must contain both cert and key. PEM or DER files can contain just the certificate if the key is uploaded separately via `2.0a CA Key File`. Format is auto-detected (PFX tried first, then PEM, then DER).
- **2.0a CA Key File** : `File`: private key file for the CA certificate (PEM format). Only needed when the CA File above contains just the certificate without a private key.
- **2.1 CA Password** : `String`: password for the uploaded CA file. Leave empty if the CA has no password.
- **2.2 Inherit CA Attributes** : `Boolean` (default `True`): when enabled, copies CN, C, O, OU, ST, L, and Email from the CA certificate's subject into the new code signing certificate. When disabled, the operator supplies these fields manually via group 5.

### 3.0 – 3.1 · Signing Certificate (Upload Signing Cert mode)

Only visible when `1.0 Signing Mode = Upload Signing Cert`.

- **3.0 Signing Certificate File** : `File`: a ready-to-use PFX/P12 code signing certificate. Must contain both a certificate and a private key.
- **3.1 Signing Certificate Password** : `String`: password for the uploaded PFX. Leave empty if none.

### 4.0 · Clone Certificate (Clone from URL mode)

Only visible when `1.0 Signing Mode = Clone from URL`.

- **4.0 Clone URL** : `String` (default `"https://www.microsoft.com"`): the HTTPS URL whose server certificate subject fields (CN, C, O, OU, ST, L) will be scraped and used to generate a matching self-signed code signing certificate. If the connection fails, the hostname is used as the CN with defaults for remaining fields.

### 5.0 – 5.6 · Certificate Subject

Visible for `Generate CA + Cert` and `Upload CA` (when `Inherit CA Attributes` is disabled). Hidden for `Upload Signing Cert` and `Clone from URL`.

- **5.0 Common Name (CN)** : `String` (default `"Microsoft Corporation"`): Common Name for the code signing certificate.
- **5.1 Country (C)** : `String` (default `"US"`): two-letter ISO 3166-1 alpha-2 country code.
- **5.2 Organization (O)** : `String` (default `"Microsoft Corporation"`): organization name.
- **5.3 Organizational Unit (OU)** : `String` (optional): organizational unit.
- **5.4 State/Province (ST)** : `String` (optional): state or province.
- **5.5 Locality (L)** : `String` (optional): city or locality.
- **5.6 Email** : `String` (optional): email address embedded in the certificate subject.

### 6.0 – 6.4 · Signing Options

- **6.0 Key Size** : `ChooseOne`: `"2048"` or `"4096"`. RSA key size for generated certificates. Hidden for `Upload Signing Cert`.
- **6.1 Hash Algorithm** : `ChooseOne`: `"sha256"` (default), `"sha384"`, or `"sha512"`. Digest algorithm for both certificate signing and the Authenticode signature.
- **6.2 Certificate Validity (days)** : `String` (default `"365"`): validity period for the generated code signing certificate. The CA certificate is generated with `3×` this value. Hidden for `Upload Signing Cert`.
- **6.3 Timestamp Server** : `String` (default `"http://timestamp.digicert.com"`): RFC 3161 timestamp server URL. Leave empty to skip timestamping.
- **6.4 Signature Description** : `String` (optional): description string embedded in the Authenticode signature. Visible in the file's Properties → Digital Signatures tab.

### 7.0 – 7.1 · Output

- **7.0 Export CA Certificate** : `Boolean` (default `False`): register the generated CA certificate as `signet_ca.pfx` in the Mythic file store for reuse in future builds. Only visible for `Generate CA + Cert` (not shown for `Upload CA` or `Upload Signing Cert`).
- **7.1 Export Signing Certificate** : `Boolean` (default `False`): register the generated code signing PFX as `signet_codesign.pfx` in the Mythic file store. Hidden for `Upload Signing Cert`.

## Build step reference

Each build stage is reported to Mythic via `SendMythicRPCPayloadUpdatebuildStep`.

| # | StepName | Description |
|---|---|---|
| 1 | `Gathering Payload` | Retrieve wrapped payload bytes from Mythic |
| 2 | `Preparing Certificate` | Generate, load, or clone the signing certificate per the selected mode |
| 3 | `Signing Payload` | Apply Authenticode signature via `osslsigncode` |
| 4 | `Finalizing` | Set signed payload on BuildResponse, report success |

Build failures terminate the pipeline immediately and the operator sees the failed step with a diagnostic message in the Mythic UI.

## Project structure

```
Signet/
├── config.json                    # Mythic payload config
├── documentation-wrapper/
│   └── signet/                    # This documentation
│       ├── _index.md
│       ├── development.md
│       └── opsec.md
└── Payload_Type/
    └── signet/
        ├── Dockerfile             # Container: mythic_python_go + osslsigncode + cryptography
        ├── main.py                # Entry point: imports builder, starts mythic_service
        ├── rabbitmq_config.json   # RabbitMQ connection config
        ├── agent_icons/
        │   └── signet_logo.png    # Agent icon
        ├── certificate_store/     # Agent code path (empty at build time)
        └── signet/
            ├── __init__.py        # Exports SignetWrapper
            ├── builder.py         # PayloadType class with build parameters and build()
            └── signing.py         # Cryptographic operations (CA gen, cert gen, signing)
```

### Main files

- **[builder.py](Payload_Type/signet/signet/builder.py)** : `SignetWrapper(PayloadType)` class. Defines all build parameters, build steps, and the `build()` method that dispatches to one of four mode implementations (`_mode_generate`, `_mode_upload_ca`, `_mode_upload_cert`, `_mode_clone_url`).
- **[signing.py](Payload_Type/signet/signet/signing.py)** : pure cryptographic module. Key functions:
  - `generate_ca()` → `(ca_cert, ca_key)` : creates a self-signed CA with `BasicConstraints(ca=True, path_length=0)`.
  - `load_ca_from_bytes()` → `(ca_cert, ca_key)` : loads a CA from PFX/PEM/DER with automatic format detection.
  - `extract_ca_attributes()` → `dict` : extracts CN, C, O, OU, ST, L, Email from a certificate subject.
  - `create_code_signing_cert()` → `(cert, key)` : issues a code signing cert with `ExtendedKeyUsage(CODE_SIGNING)`.
  - `export_pfx()` → `bytes` : serializes certificate + key as PKCS#12.
  - `sign_payload()` → `bytes` : invokes `osslsigncode sign` in a temp directory and returns the signed output.
  - `load_pfx_from_bytes()` → `bytes` : validates a PFX and returns it as-is.

### Dependencies

Installed via the [Dockerfile](Payload_Type/signet/Dockerfile):

| Package | Version | Purpose |
|---|---|---|
| `mythic_container` | 0.7.0rc9 | Mythic v4 SDK (PayloadType, BuildParameter, RPC) |
| `cryptography` | latest | X.509 certificate generation, PKCS#12, RSA key generation |
| `osslsigncode` | apt package | Authenticode signing of PE/MSI binaries |
| `openssl` | apt package | TLS library dependency |
| `ca-certificates` | apt package | Root CA bundle for URL cloning mode |

### Docker image

```dockerfile
FROM itsafeaturemythic/mythic_python_go:latest
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        osslsigncode openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install mythic_container==0.7.0rc9 cryptography
RUN pip3 install --upgrade --force-reinstall "grpcio>=1.78.0"
WORKDIR /Mythic/
COPY [".", "."]
CMD ["python3", "main.py"]
```

## Extending the builder

### Adding a new signing mode

1. Add a new choice to `1.0 Signing Mode` in the `build_parameters` list.
2. Add any new BuildParameters for the mode with appropriate `HideCondition`s.
3. Implement an `async def _mode_<name>(self, resp) -> tuple` method that returns `(pfx_bytes, pfx_password, log_lines)`.
4. Add an `elif mode == "<Name>":` branch to the `build()` method's mode dispatch.

### Adding certificate format support

The format detection chain in `load_ca_from_bytes()` tries PFX → PEM → DER. To add a new format:

1. Add a new `try/except` block in `load_ca_from_bytes()` after the existing ones.
2. Use the appropriate `cryptography` loader for the format.
3. Return `(cert, key)` on success.

### Adding a new hash algorithm

1. Add the algorithm to the `HASH_ALGORITHMS` dict in `signing.py`.
2. Add the choice to `6.1 Hash Algorithm` in `builder.py`.
3. Ensure `osslsigncode` supports the hash (check `osslsigncode sign -h` for the `-h` flag options).
