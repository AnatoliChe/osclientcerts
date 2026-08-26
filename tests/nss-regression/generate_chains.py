#!/usr/bin/env python3
"""Generates synthetic certificate chains for the NSS regression harness
(scripts/nss-regression-test.sh).

Each case is a small (root CA, leaf) chain with a chosen key/signature algorithm, written to
cases/<name>/ as DER fragments plus a manifest.txt that backend_other.rs's `nss-regression`
feature reads at runtime (via OSCLIENTCERTS_NSS_REGRESSION_DIR) to serve as this crate's PKCS #11
objects -- including, for the CA, a synthetic CKO_NSS_TRUST object exactly like the one
backend_windows.rs emits for a real Windows-trusted root. expect.txt records whether the case
should end up trusted for S/MIME email use once loaded into a real NSS build; the shell script
checks vfychain's result against it.

Requires the `cryptography` package (pip install cryptography).
"""

import datetime
import hashlib
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

CASES_DIR = Path(__file__).resolve().parent / "cases"

NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ec_key(curve):
    return ec.generate_private_key(curve)


def build_root(case, key, sign_algorithm, serial):
    subject = name(f"NSS Regression Root ({case})")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(key, sign_algorithm)


def build_leaf(case, key, issuer_cert, issuer_key, sign_algorithm, serial, rsa_pss=False):
    subject = name(f"NSS Regression Leaf ({case})")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(key, rsa.RSAPrivateKey),
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.RFC822Name(f"leaf-{case}@nss-regression.invalid")]
            ),
            critical=False,
        )
    )
    if rsa_pss:
        return builder.sign(
            issuer_key,
            sign_algorithm,
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(sign_algorithm), salt_length=padding.PSS.MAX_LENGTH
            ),
        )
    return builder.sign(issuer_key, sign_algorithm)


def write(path: Path, data: bytes):
    path.write_bytes(data)


def name_der(n: x509.Name) -> bytes:
    return n.public_bytes()


def emit_cert_files(out_dir: Path, prefix: str, cert: x509.Certificate):
    der = cert.public_bytes(serialization.Encoding.DER)
    write(out_dir / f"{prefix}.der", der)
    write(out_dir / f"{prefix}.pem", cert.public_bytes(serialization.Encoding.PEM))
    write(out_dir / f"{prefix}.issuer.der", name_der(cert.issuer))
    write(out_dir / f"{prefix}.subject.der", name_der(cert.subject))
    serial_bytes = cert.serial_number.to_bytes(
        (cert.serial_number.bit_length() + 7) // 8 or 1, "big"
    )
    write(out_dir / f"{prefix}.serial.bin", serial_bytes)
    write(out_dir / f"{prefix}.sha1.bin", hashlib.sha1(der).digest())


def cert_block(prefix: str, label: str) -> str:
    return (
        f"kind=cert\n"
        f"label={label}\n"
        f"id={label}\n"
        f"der={prefix}.der\n"
        f"issuer={prefix}.issuer.der\n"
        f"subject={prefix}.subject.der\n"
        f"serial={prefix}.serial.bin\n"
    )


def trust_block(root_prefix: str, include_sha1: bool) -> str:
    lines = [
        "kind=trust",
        f"issuer={root_prefix}.issuer.der",
        f"serial={root_prefix}.serial.bin",
    ]
    if include_sha1:
        lines.append(f"sha1={root_prefix}.sha1.bin")
    return "\n".join(lines) + "\n"


def write_case(name: str, root: x509.Certificate, leaf: x509.Certificate, trust: str, expect: str, note: str):
    out_dir = CASES_DIR / name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    emit_cert_files(out_dir, "root", root)
    emit_cert_files(out_dir, "leaf", leaf)

    blocks = [cert_block("root", "root"), cert_block("leaf", "leaf")]
    if trust == "full":
        blocks.append(trust_block("root", include_sha1=True))
    elif trust == "missing-sha1":
        blocks.append(trust_block("root", include_sha1=False))
    elif trust == "none":
        pass
    else:
        raise ValueError(trust)

    (out_dir / "manifest.txt").write_text("\n\n".join(blocks) + "\n")
    (out_dir / "expect.txt").write_text(expect + "\n")
    (out_dir / "NOTE.txt").write_text(note + "\n")
    print(f"generated case: {name} (expect={expect})")


def main():
    CASES_DIR.mkdir(exist_ok=True)

    # -- Positive cases: a Windows-trusted-root-style CKO_NSS_TRUST grant, varying the chain's
    # key/signature algorithm. All should verify trusted for S/MIME email use (vfychain -u 5).
    root_key = rsa_key()
    root = build_root("rsa-pkcs1-sha256", root_key, hashes.SHA256(), 1)
    leaf_key = rsa_key()
    leaf = build_leaf("rsa-pkcs1-sha256", leaf_key, root, root_key, hashes.SHA256(), 2)
    write_case(
        "rsa-pkcs1-sha256",
        root,
        leaf,
        "full",
        "trusted",
        "RSA-2048 chain, PKCS#1 v1.5/SHA-256 signatures throughout.",
    )
    # Reused below for the negative controls, which only vary the trust grant, not the chain.
    baseline_root, baseline_leaf = root, leaf

    root_key = rsa_key()
    root = build_root("rsa-pss-sha256", root_key, hashes.SHA256(), 1)
    leaf_key = rsa_key()
    leaf = build_leaf(
        "rsa-pss-sha256", leaf_key, root, root_key, hashes.SHA256(), 2, rsa_pss=True
    )
    write_case(
        "rsa-pss-sha256",
        root,
        leaf,
        "full",
        "trusted",
        "RSA-2048 chain, leaf signed with RSA-PSS/SHA-256 (root self-signature stays PKCS#1 v1.5).",
    )

    root_key = ec_key(ec.SECP256R1())
    root = build_root("ecdsa-p256", root_key, hashes.SHA256(), 1)
    leaf_key = ec_key(ec.SECP256R1())
    leaf = build_leaf("ecdsa-p256", leaf_key, root, root_key, hashes.SHA256(), 2)
    write_case(
        "ecdsa-p256",
        root,
        leaf,
        "full",
        "trusted",
        "ECDSA P-256 chain, SHA-256 signatures.",
    )

    root_key = ec_key(ec.SECP384R1())
    root = build_root("ecdsa-p384", root_key, hashes.SHA384(), 1)
    leaf_key = ec_key(ec.SECP384R1())
    leaf = build_leaf("ecdsa-p384", leaf_key, root, root_key, hashes.SHA384(), 2)
    write_case(
        "ecdsa-p384",
        root,
        leaf,
        "full",
        "trusted",
        "ECDSA P-384 chain, SHA-384 signatures.",
    )

    # -- Negative controls: same RSA/SHA-256 chain as the first case, but with a broken or absent
    # trust grant. These reproduce the actual historical bug (a CKO_NSS_TRUST object missing
    # CKA_NSS_CERT_SHA1_HASH is silently discarded by NSS, see backend_windows.rs's Trust doc
    # comment) and the baseline "no trust info at all" case, so a future change that accidentally
    # grants trust unconditionally would be caught here.
    write_case(
        "missing-sha1-hash",
        baseline_root,
        baseline_leaf,
        "missing-sha1",
        "untrusted",
        "Same chain as rsa-pkcs1-sha256, but the CKO_NSS_TRUST object omits "
        "CKA_NSS_CERT_SHA1_HASH -- NSS's nssTrust_Create must silently discard this grant "
        "(nssTrust_IsSafeToIgnoreCertHash only allows a hash-less record for Unknown/NotTrusted).",
    )
    write_case(
        "no-trust-object",
        baseline_root,
        baseline_leaf,
        "none",
        "untrusted",
        "Same chain as rsa-pkcs1-sha256, with no CKO_NSS_TRUST object at all -- baseline sanity "
        "check that an unknown root is not trusted.",
    )


if __name__ == "__main__":
    main()
