"""
Signet - Mythic Code Signing Wrapper
Author: Lavender-exe
Description: Signs any wrapped payload with a generated or provided code signing certificate.
"""

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from pathlib import PurePath, Path
from signet.signing import (
    generate_ca, load_ca_from_bytes, extract_ca_attributes,
    create_code_signing_cert, export_pfx, sign_payload,
    load_pfx_from_bytes,
)


class SignetWrapper(PayloadType):
    name = "signet"
    author = "Lavender-exe"
    semver = "0.1.0"
    note = "Code signing wrapper. Signs any wrapped payload with a self-signed, CA-issued, or user-provided certificate."

    file_extension = ""
    supported_os = [
        SupportedOS.Windows,
    ]

    wrapper = True
    wrapped_payloads = [
        "apollo", "athena", "merlin", "kharon",
        "sliver", "xenon", "nimplant", "hannibal",
        "starburst", "poopsie", "erebus_wrapper",
        "emeraldstrike"
    ]
    c2_profiles = []
    agent_type = AgentType.Wrapper

    agent_path = PurePath(".") / "signet"
    _agent_icon_path = Path(__file__).resolve().parent.parent / "agent_icons" / "signet_logo.png"
    agent_icon_path = str(_agent_icon_path)
    agent_code_path = Path(__file__).resolve().parent.parent / "certificate_store"

    build_parameters = [
        # ── Custom Payload ────────────────────────────────────────────────
        BuildParameter(
            name="0.0 Custom Payload",
            group_name="0 - Custom Payload",
            parameter_type=BuildParameterType.Boolean,
            description=(
                "Upload a custom binary to sign instead of using the wrapped payload. "
                "Use this to sign binaries from external tools or other C2 frameworks."
            ),
            default_value=False,
        ),
        BuildParameter(
            name="0.1 Custom Payload File",
            group_name="0 - Custom Payload",
            parameter_type=BuildParameterType.File,
            description="Binary file (EXE, DLL, MSI, etc.) to sign. Replaces the wrapped payload.",
            required=False,
            hide_conditions=[
                HideCondition(name="0.0 Custom Payload", operand=HideConditionOperand.EQ, value="false"),
            ],
        ),

        # ── Signing Mode ──────────────────────────────────────────────────
        BuildParameter(
            name="1.0 Signing Mode",
            group_name="1 - Signing Mode",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "How the code signing certificate is obtained.\n"
                "  Generate CA + Cert  - creates a self-signed CA then issues a code signing cert from it.\n"
                "  Upload CA           - provide your own CA (PFX or PEM); a code signing cert is issued from it.\n"
                "  Upload Signing Cert - provide a ready-to-use PFX code signing certificate directly.\n"
                "  Clone from URL      - scrape X.509 subject fields from a remote HTTPS certificate and generate a matching self-signed code signing cert."
            ),
            choices=[
                "Generate CA + Cert",
                "Upload CA",
                "Upload Signing Cert",
                "Clone from URL",
            ],
            default_value="Generate CA + Cert",
        ),

        # ── CA Upload ─────────────────────────────────────────────────────
        BuildParameter(
            name="2.0 CA File",
            group_name="2 - Certificate Authority",
            parameter_type=BuildParameterType.File,
            description="CA certificate file. PFX/P12 files must contain both cert and key. PEM or DER files can contain just the certificate if the key is uploaded separately below.",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload CA"),
            ],
        ),
        BuildParameter(
            name="2.0a CA Key File",
            group_name="2 - Certificate Authority",
            parameter_type=BuildParameterType.File,
            description="Private key file for the CA certificate (PEM format). Only needed when the CA File above contains just the certificate.",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload CA"),
            ],
        ),
        BuildParameter(
            name="2.1 CA Password",
            group_name="2 - Certificate Authority",
            parameter_type=BuildParameterType.String,
            description="Password for the uploaded CA file (leave empty if none).",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload CA"),
            ],
        ),
        BuildParameter(
            name="2.2 Inherit CA Attributes",
            group_name="2 - Certificate Authority",
            parameter_type=BuildParameterType.Boolean,
            description="Copy CN, C, O, OU, etc. from the CA certificate into the code signing certificate subject.",
            default_value=False,
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload CA"),
            ],
        ),

        # ── Signing Cert Upload ───────────────────────────────────────────
        BuildParameter(
            name="3.0 Signing Certificate File",
            group_name="3 - Signing Certificate",
            parameter_type=BuildParameterType.File,
            description="PFX/P12 code signing certificate to use directly.",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload Signing Cert"),
            ],
        ),
        BuildParameter(
            name="3.1 Signing Certificate Password",
            group_name="3 - Signing Certificate",
            parameter_type=BuildParameterType.String,
            description="Password for the uploaded signing certificate.",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Upload Signing Cert"),
            ],
        ),

        # ── Clone from URL ────────────────────────────────────────────────
        BuildParameter(
            name="4.0 Clone URL",
            group_name="4 - Clone Certificate",
            parameter_type=BuildParameterType.String,
            description="HTTPS URL whose certificate subject fields will be cloned (e.g. https://microsoft.com).",
            default_value="https://www.microsoft.com",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.NotEQ, value="Clone from URL"),
            ],
        ),

        # ── Certificate Subject (manual) ─────────────────────────────────
        BuildParameter(
            name="5.0 Common Name (CN)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="Common Name for the code signing certificate.",
            default_value="Microsoft Corporation",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.1 Country (C)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="Two-letter country code (ISO 3166-1 alpha-2).",
            default_value="US",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.2 Organization (O)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="Organization name.",
            default_value="Microsoft Corporation",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.3 Organizational Unit (OU)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="Organizational Unit (optional).",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.4 State/Province (ST)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="State or Province (optional).",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.5 Locality (L)",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="City or Locality (optional).",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),
        BuildParameter(
            name="5.6 Email",
            group_name="5 - Certificate Subject",
            parameter_type=BuildParameterType.String,
            description="Email address embedded in the certificate (optional).",
            default_value="",
            required=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Clone from URL"),
                HideCondition(name="2.2 Inherit CA Attributes", operand=HideConditionOperand.EQ, value=True),
            ],
        ),

        # ── Signing Options ───────────────────────────────────────────────
        BuildParameter(
            name="6.0 Key Size",
            group_name="6 - Signing Options",
            parameter_type=BuildParameterType.ChooseOne,
            description="RSA key size for generated certificates.",
            choices=["2048", "4096"],
            default_value="2048",
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
            ],
        ),
        BuildParameter(
            name="6.1 Hash Algorithm",
            group_name="6 - Signing Options",
            parameter_type=BuildParameterType.ChooseOne,
            description="Digest algorithm for the Authenticode signature.",
            choices=["sha256", "sha384", "sha512"],
            default_value="sha256",
        ),
        BuildParameter(
            name="6.2 Certificate Validity (days)",
            group_name="6 - Signing Options",
            parameter_type=BuildParameterType.String,
            description="How many days the generated certificates are valid.",
            default_value="365",
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
            ],
        ),
        BuildParameter(
            name="6.3 Timestamp Server",
            group_name="6 - Signing Options",
            parameter_type=BuildParameterType.String,
            description="RFC 3161 timestamp server URL. Leave empty to skip timestamping.",
            default_value="http://timestamp.digicert.com",
            required=False,
        ),
        BuildParameter(
            name="6.4 Signature Description",
            group_name="6 - Signing Options",
            parameter_type=BuildParameterType.String,
            description="Description string embedded in the Authenticode signature (optional).",
            default_value="",
            required=False,
        ),

        BuildParameter(
            name="7.0 Export CA Certificate",
            group_name="7 - Output",
            parameter_type=BuildParameterType.Boolean,
            description="Register the generated CA certificate as a Mythic file so it can be reused in future builds.",
            default_value=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload CA"),
            ],
        ),
        BuildParameter(
            name="7.1 Export Signing Certificate",
            group_name="7 - Output",
            parameter_type=BuildParameterType.Boolean,
            description="Register the generated code signing PFX as a Mythic file.",
            default_value=False,
            hide_conditions=[
                HideCondition(name="1.0 Signing Mode", operand=HideConditionOperand.EQ, value="Upload Signing Cert"),
            ],
        ),
    ]

    build_steps = [
        BuildStep(step_name="Gathering Payload", step_description="Retrieving wrapped payload from Mythic"),
        BuildStep(step_name="Preparing Certificate", step_description="Generating or loading signing certificate"),
        BuildStep(step_name="Signing Payload", step_description="Applying Authenticode signature"),
        BuildStep(step_name="Finalizing", step_description="Packaging signed output"),
    ]

    async def _step(self, response, name, stdout, success=True):
        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=name,
                StepStdout=stdout,
                StepSuccess=success,
            )
        )
        if not success:
            response.set_status(BuildStatus.Error)
            response.build_stderr = stdout

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)

        # ── Step 1: Gather payload (custom upload or wrapped) ─────────────
        custom_enabled = self.get_parameter("0.0 Custom Payload")
        payload_bytes = None

        if custom_enabled:
            file_uuid = self.get_parameter("0.1 Custom Payload File")
            if not file_uuid:
                await self._step(resp, "Gathering Payload", "Custom payload enabled but no file uploaded.", success=False)
                return resp
            try:
                payload_bytes = await getFileFromMythic(agentFileId=file_uuid)
                if not payload_bytes:
                    await self._step(resp, "Gathering Payload", "Custom payload file is empty.", success=False)
                    return resp
                await self._step(resp, "Gathering Payload", f"Received {len(payload_bytes)} bytes from custom payload upload.")
            except Exception as e:
                await self._step(resp, "Gathering Payload", f"Error retrieving custom payload: {e}", success=False)
                return resp
        else:
            if self.wrapped_payload is None:
                await self._step(resp, "Gathering Payload", "No wrapped payload provided.", success=False)
                return resp
            payload_bytes = self.wrapped_payload
            await self._step(resp, "Gathering Payload", f"Received {len(payload_bytes)} bytes from wrapped payload.")

        # ── Step 2: Prepare signing certificate ───────────────────────────
        mode = self.get_parameter("1.0 Signing Mode")
        hash_algo = self.get_parameter("6.1 Hash Algorithm")
        pfx_bytes = None
        pfx_password = ""
        build_log = []

        try:
            if mode == "Generate CA + Cert":
                pfx_bytes, pfx_password, log = await self._mode_generate(resp)
                build_log.extend(log)

            elif mode == "Upload CA":
                pfx_bytes, pfx_password, log = await self._mode_upload_ca(resp)
                build_log.extend(log)

            elif mode == "Upload Signing Cert":
                pfx_bytes, pfx_password, log = await self._mode_upload_cert(resp)
                build_log.extend(log)

            elif mode == "Clone from URL":
                pfx_bytes, pfx_password, log = await self._mode_clone_url(resp)
                build_log.extend(log)

            else:
                await self._step(resp, "Preparing Certificate", f"Unknown signing mode: {mode}", success=False)
                return resp

        except Exception as e:
            await self._step(resp, "Preparing Certificate", f"Certificate preparation failed: {e}", success=False)
            return resp

        if pfx_bytes is None:
            return resp

        await self._step(resp, "Preparing Certificate", "\n".join(build_log) if build_log else "Certificate ready.")

        # ── Step 3: Sign the payload ──────────────────────────────────────
        timestamp_url = self.get_parameter("6.3 Timestamp Server") or ""
        description = self.get_parameter("6.4 Signature Description") or ""

        try:
            signed_bytes = sign_payload(
                payload_bytes=payload_bytes,
                pfx_bytes=pfx_bytes,
                pfx_password=pfx_password,
                timestamp_url=timestamp_url,
                hash_algo=hash_algo,
                description=description,
            )
        except Exception as e:
            await self._step(resp, "Signing Payload", f"Signing failed: {e}", success=False)
            return resp

        await self._step(resp, "Signing Payload", f"Payload signed successfully ({len(signed_bytes)} bytes).")

        resp.payload = signed_bytes

        # Rename output to <original>_signed.<ext>
        original = self.filename or "payload"
        if custom_enabled and file_uuid:
            try:
                search_resp = await SendMythicRPCFileSearch(
                    MythicRPCFileSearchMessage(AgentFileID=file_uuid)
                )
                if search_resp.Success and search_resp.Files:
                    original = search_resp.Files[0].Filename or original
            except Exception:
                pass
        dot = original.rfind(".")
        if dot > 0:
            updated = original[:dot] + "_signed" + original[dot:]
        else:
            updated = original + "_signed"
        resp.set_updated_filename(updated)

        resp.set_status(BuildStatus.Success)
        resp.build_message = f"Signed payload: {len(signed_bytes)} bytes, mode={mode}, hash={hash_algo}"
        resp.set_build_stdout(f"payload_in={len(payload_bytes)} signed_out={len(signed_bytes)} resp_payload={len(resp.payload)}")
        await self._step(resp, "Finalizing", f"{resp.build_message}\nOutput: {updated}")

        return resp


    async def _mode_generate(self, resp) -> tuple:
        """Generate a self-signed CA then issue a code signing cert from it."""
        cn = self.get_parameter("5.0 Common Name (CN)") or "Signet CA"
        c = self.get_parameter("5.1 Country (C)") or "US"
        o = self.get_parameter("5.2 Organization (O)") or cn
        ou = self.get_parameter("5.3 Organizational Unit (OU)") or ""
        st = self.get_parameter("5.4 State/Province (ST)") or ""
        l = self.get_parameter("5.5 Locality (L)") or ""
        email = self.get_parameter("5.6 Email") or ""
        key_size = int(self.get_parameter("6.0 Key Size"))
        hash_algo = self.get_parameter("6.1 Hash Algorithm")
        validity = int(self.get_parameter("6.2 Certificate Validity (days)") or "365")
        log = []

        ca_cert, ca_key = generate_ca(
            cn=f"{cn} CA", c=c, o=o, ou=ou, st=st, l=l, email=email,
            key_size=key_size, validity_days=validity * 3, hash_algo=hash_algo,
        )
        log.append(f"Generated CA: CN={cn} CA, C={c}, O={o}")

        cs_cert, cs_key = create_code_signing_cert(
            ca_cert, ca_key,
            cn=cn, c=c, o=o, ou=ou, st=st, l=l, email=email,
            key_size=key_size, validity_days=validity, hash_algo=hash_algo,
        )
        log.append(f"Issued code signing cert: CN={cn}")

        pfx_bytes = export_pfx(cs_cert, cs_key, ca_cert=ca_cert)
        log.append("Exported signing PFX (no password)")

        await self._maybe_export_ca(ca_cert, ca_key, log)
        await self._maybe_export_signing_cert(pfx_bytes, log)

        return pfx_bytes, "", log

    async def _mode_upload_ca(self, resp) -> tuple:
        """Load an uploaded CA and issue a code signing cert from it."""
        ca_uuid = self.get_parameter("2.0 CA File")
        ca_key_uuid = self.get_parameter("2.0a CA Key File")
        ca_password = self.get_parameter("2.1 CA Password") or ""
        inherit = self.get_parameter("2.2 Inherit CA Attributes")
        key_size = int(self.get_parameter("6.0 Key Size"))
        hash_algo = self.get_parameter("6.1 Hash Algorithm")
        validity = int(self.get_parameter("6.2 Certificate Validity (days)") or "365")
        log = []

        if not ca_uuid:
            raise ValueError("No CA file uploaded.")

        ca_bytes = await getFileFromMythic(agentFileId=ca_uuid)
        if not ca_bytes:
            raise ValueError("CA file is empty.")

        # If a separate key file was uploaded, concatenate it with the cert
        if ca_key_uuid:
            key_bytes = await getFileFromMythic(agentFileId=ca_key_uuid)
            if not key_bytes:
                raise ValueError("CA key file is empty.")
            ca_bytes = ca_bytes + b"\n" + key_bytes
            log.append("Using separate CA certificate and key files.")

        ca_cert, ca_key = load_ca_from_bytes(ca_bytes, ca_password)
        log.append("Loaded uploaded CA successfully.")

        if inherit:
            attrs = extract_ca_attributes(ca_cert)
            cn = attrs.get("cn", "Code Signing")
            c = attrs.get("c", "US")
            o = attrs.get("o", cn)
            ou = attrs.get("ou", "")
            st = attrs.get("st", "")
            l = attrs.get("l", "")
            email = attrs.get("email", "")
            log.append(f"Inherited CA attributes: CN={cn}, C={c}, O={o}")
        else:
            cn = self.get_parameter("5.0 Common Name (CN)") or "Code Signing"
            c = self.get_parameter("5.1 Country (C)") or "US"
            o = self.get_parameter("5.2 Organization (O)") or cn
            ou = self.get_parameter("5.3 Organizational Unit (OU)") or ""
            st = self.get_parameter("5.4 State/Province (ST)") or ""
            l = self.get_parameter("5.5 Locality (L)") or ""
            email = self.get_parameter("5.6 Email") or ""

        cs_cert, cs_key = create_code_signing_cert(
            ca_cert, ca_key,
            cn=cn, c=c, o=o, ou=ou, st=st, l=l, email=email,
            key_size=key_size, validity_days=validity, hash_algo=hash_algo,
        )
        log.append(f"Issued code signing cert: CN={cn}")

        pfx_bytes = export_pfx(cs_cert, cs_key, ca_cert=ca_cert)
        await self._maybe_export_signing_cert(pfx_bytes, log)

        return pfx_bytes, "", log

    async def _mode_upload_cert(self, resp) -> tuple:
        """Use a user-provided PFX signing certificate directly."""
        cert_uuid = self.get_parameter("3.0 Signing Certificate File")
        cert_password = self.get_parameter("3.1 Signing Certificate Password") or ""
        log = []

        if not cert_uuid:
            raise ValueError("No signing certificate file uploaded.")

        cert_bytes = await getFileFromMythic(agentFileId=cert_uuid)
        if not cert_bytes:
            raise ValueError("Signing certificate file is empty.")

        pfx_bytes = load_pfx_from_bytes(cert_bytes, cert_password)
        log.append("Loaded uploaded signing certificate successfully.")

        return pfx_bytes, cert_password, log

    async def _mode_clone_url(self, resp) -> tuple:
        """Scrape certificate subject from a URL and generate a matching self-signed cert."""
        import ssl
        import socket
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509 as x509_mod

        url = self.get_parameter("4.0 Clone URL") or "https://www.microsoft.com"
        key_size = int(self.get_parameter("6.0 Key Size"))
        hash_algo = self.get_parameter("6.1 Hash Algorithm")
        validity = int(self.get_parameter("6.2 Certificate Validity (days)") or "365")
        log = []

        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        cert_attrs = {"cn": hostname, "c": "US", "o": hostname, "ou": "", "st": "", "l": "", "email": ""}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509_mod.load_der_x509_certificate(der_cert, default_backend())
                    oid_map = {
                        NameOID.COMMON_NAME: "cn",
                        NameOID.COUNTRY_NAME: "c",
                        NameOID.STATE_OR_PROVINCE_NAME: "st",
                        NameOID.LOCALITY_NAME: "l",
                        NameOID.ORGANIZATION_NAME: "o",
                        NameOID.ORGANIZATIONAL_UNIT_NAME: "ou",
                    }
                    for attr in cert.subject:
                        if attr.oid in oid_map:
                            cert_attrs[oid_map[attr.oid]] = attr.value
                    if not cert_attrs["o"]:
                        cert_attrs["o"] = cert_attrs["cn"]
            log.append(f"Cloned cert from {hostname}: CN={cert_attrs['cn']}, O={cert_attrs['o']}, C={cert_attrs['c']}")
        except Exception as e:
            log.append(f"Warning: could not scrape {hostname} ({e}), using hostname as CN")

        ca_cert, ca_key = generate_ca(
            cn=f"{cert_attrs['cn']} CA",
            c=cert_attrs["c"], o=cert_attrs["o"], ou=cert_attrs["ou"],
            st=cert_attrs["st"], l=cert_attrs["l"],
            key_size=key_size, validity_days=validity * 3, hash_algo=hash_algo,
        )

        cs_cert, cs_key = create_code_signing_cert(
            ca_cert, ca_key,
            cn=cert_attrs["cn"], c=cert_attrs["c"], o=cert_attrs["o"],
            ou=cert_attrs["ou"], st=cert_attrs["st"], l=cert_attrs["l"],
            key_size=key_size, validity_days=validity, hash_algo=hash_algo,
        )
        log.append(f"Generated code signing cert with cloned attributes")

        pfx_bytes = export_pfx(cs_cert, cs_key, ca_cert=ca_cert)

        await self._maybe_export_ca(ca_cert, ca_key, log)
        await self._maybe_export_signing_cert(pfx_bytes, log)

        return pfx_bytes, "", log


    async def _maybe_export_ca(self, ca_cert, ca_key, log):
        try:
            export_ca = self.get_parameter("7.0 Export CA Certificate")
        except Exception:
            export_ca = False
        if not export_ca:
            return
        try:
            ca_pfx = export_pfx(ca_cert, ca_key)
            file_resp = await SendMythicRPCFileCreate(
                MythicRPCFileCreateMessage(
                    TaskID=1,
                    FileContents=ca_pfx,
                    DeleteAfterFetch=False,
                    Filename="signet_ca.pfx",
                    Comment="Signet-generated CA certificate",
                )
            )
            if file_resp.Success:
                log.append("Exported CA as signet_ca.pfx to Mythic files.")
            else:
                log.append(f"CA export failed: {file_resp.Error}")
        except Exception as e:
            log.append(f"CA export skipped: {e}")

    async def _maybe_export_signing_cert(self, pfx_bytes, log):
        try:
            export_cert = self.get_parameter("7.1 Export Signing Certificate")
        except Exception:
            export_cert = False
        if not export_cert:
            return
        try:
            file_resp = await SendMythicRPCFileCreate(
                MythicRPCFileCreateMessage(
                    TaskID=1,
                    FileContents=pfx_bytes,
                    DeleteAfterFetch=False,
                    Filename="signet_codesign.pfx",
                    Comment="Signet-generated code signing certificate",
                )
            )
            if file_resp.Success:
                log.append("Exported signing cert as signet_codesign.pfx to Mythic files.")
            else:
                log.append(f"Signing cert export failed: {file_resp.Error}")
        except Exception as e:
            log.append(f"Signing cert export skipped: {e}")
