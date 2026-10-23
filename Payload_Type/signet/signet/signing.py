from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone
import pathlib
import subprocess
import tempfile

HASH_ALGORITHMS = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


def _build_name_attributes(cn: str, c: str = "", o: str = "",
                           ou: str = "", st: str = "", l: str = "",
                           email: str = "") -> list:
    attrs = []
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if c:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if st:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    if l:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if o:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return attrs


def generate_ca(cn: str, c: str = "US", o: str = "", ou: str = "",
                st: str = "", l: str = "", email: str = "",
                key_size: int = 2048, validity_days: int = 3650,
                hash_algo: str = "sha256") -> tuple:
    """Generate a self-signed CA certificate and private key.
    Returns (ca_cert, ca_key) as cryptography objects.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(_build_name_attributes(cn, c, o, ou, st, l, email))

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, HASH_ALGORITHMS.get(hash_algo, hashes.SHA256()))
    )
    return ca_cert, ca_key


def load_ca_from_bytes(ca_bytes: bytes, password: str = "") -> tuple:
    """Load a CA from PFX/PEM/DER bytes. Returns (ca_cert, ca_key)."""
    pw = password.encode() if password else None

    # Try PFX/P12
    try:
        key, cert, _ = pkcs12.load_key_and_certificates(ca_bytes, pw)
        if cert and key:
            return cert, key
    except Exception:
        pass

    # Try PEM (cert + key concatenated)
    try:
        cert = x509.load_pem_x509_certificate(ca_bytes)
        key = serialization.load_pem_private_key(ca_bytes, password=pw)
        return cert, key
    except Exception:
        pass

    # Try DER cert + PEM key
    try:
        cert = x509.load_der_x509_certificate(ca_bytes)
        key = serialization.load_pem_private_key(ca_bytes, password=pw)
        return cert, key
    except Exception:
        pass

    # Check if the file contains a valid certificate but no private key
    cert_found = False
    try:
        x509.load_pem_x509_certificate(ca_bytes)
        cert_found = True
    except Exception:
        try:
            x509.load_der_x509_certificate(ca_bytes)
            cert_found = True
        except Exception:
            pass

    if cert_found:
        raise ValueError(
            "CA file contains a certificate but no private key. "
            "Upload the private key separately via '2.0a CA Key File', or use a PFX/P12 that bundles both."
        )

    raise ValueError("Could not parse CA file as PFX, PEM, or DER")


def extract_ca_attributes(ca_cert) -> dict:
    """Extract subject attributes from a CA certificate."""
    oid_map = {
        NameOID.COMMON_NAME: "cn",
        NameOID.COUNTRY_NAME: "c",
        NameOID.STATE_OR_PROVINCE_NAME: "st",
        NameOID.LOCALITY_NAME: "l",
        NameOID.ORGANIZATION_NAME: "o",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "ou",
        NameOID.EMAIL_ADDRESS: "email",
    }
    attrs = {}
    for attribute in ca_cert.subject:
        if attribute.oid in oid_map:
            attrs[oid_map[attribute.oid]] = attribute.value
    return attrs


def create_code_signing_cert(ca_cert, ca_key,
                             cn: str = "", c: str = "", o: str = "",
                             ou: str = "", st: str = "", l: str = "",
                             email: str = "",
                             key_size: int = 2048, validity_days: int = 365,
                             hash_algo: str = "sha256") -> tuple:
    """Create a code signing certificate signed by the given CA.
    Returns (cert, key) as cryptography objects.
    """
    cs_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(_build_name_attributes(cn, c, o, ou, st, l, email))

    cs_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(cs_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=True,
        )
        .sign(ca_key, HASH_ALGORITHMS.get(hash_algo, hashes.SHA256()))
    )
    return cs_cert, cs_key


def export_pfx(cert, key, ca_cert=None, password: str = "") -> bytes:
    """Export certificate + key as PFX/P12 bytes."""
    cas = [ca_cert] if ca_cert else None
    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        name=b"signet-codesign",
        key=key,
        cert=cert,
        cas=cas,
        encryption_algorithm=enc,
    )


def sign_payload(payload_bytes: bytes, pfx_bytes: bytes,
                 pfx_password: str = "", timestamp_url: str = "",
                 hash_algo: str = "sha256",
                 description: str = "") -> bytes:
    """Sign a PE/MSI/etc payload using osslsigncode. Returns signed bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        payload_path = tmp_path / "payload.bin"
        pfx_path = tmp_path / "cert.pfx"
        signed_path = tmp_path / "signed.bin"

        payload_path.write_bytes(payload_bytes)
        pfx_path.write_bytes(pfx_bytes)

        cmd = [
            "osslsigncode", "sign",
            "-pkcs12", str(pfx_path),
            "-h", hash_algo,
            "-in", str(payload_path),
            "-out", str(signed_path),
        ]

        if pfx_password:
            cmd.extend(["-pass", pfx_password])
        else:
            cmd.extend(["-pass", ""])

        if timestamp_url:
            cmd.extend(["-t", timestamp_url])

        if description:
            cmd.extend(["-n", description])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"osslsigncode failed (rc={result.returncode}): {error}")

        if not signed_path.exists():
            raise RuntimeError("osslsigncode produced no output file")

        signed = signed_path.read_bytes()
        if len(signed) == 0:
            raise RuntimeError("osslsigncode produced an empty output file")

        return signed


def load_pfx_from_bytes(pfx_bytes: bytes, password: str = "") -> bytes:
    """Validate that a PFX is parseable and return it as-is."""
    pw = password.encode() if password else None
    key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, pw)
    if not cert or not key:
        raise ValueError("PFX does not contain both a certificate and private key")
    return pfx_bytes
