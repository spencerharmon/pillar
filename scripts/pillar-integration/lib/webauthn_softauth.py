#!/usr/bin/env python3
"""webauthn_softauth.py — a SOFTWARE WebAuthn "authenticator + browser client"
used by the pillar-integration harness's `bootstrap-identity-custody`
scenario to drive pillar's REAL WebAuthn relying party
(`pillar_web::webauthn::RelyingParty`, over `pillar_cli::web_serve`'s
`/webauthn/register/*` and `/webauthn/authenticate/*` HTTP routes) end to end
with real Ed25519 cryptography, with no dependency on physical CTAP-HID
hardware (which this CI sandbox never has attached).

This is a black-box CLIENT only: it never links a pillar crate. It builds the
EXACT wire shapes `crates/pillar-crypto/src/webauthn.rs` documents and
verifies (a CBOR `{fmt,attStmt,authData}` attestation object with an
Ed25519/OKP COSE public key embedded in `authData`'s attested-credential-data,
and the `authenticatorData || SHA-256(clientDataJSON)` signed payload for
assertions) using the real ed25519-via-openssl private key it holds, so the
node's real crypto (not a stub) verifies every signature it is handed.

Subcommands (each prints its result to stdout; nothing else is printed there):

  genkey <keyfile>
      Generate a fresh Ed25519 keypair (openssl) at <keyfile> (PEM, PKCS#8).

  register-attestation <keyfile> <credential-id> <sign-count>
      Print the base64url attestation object for a registration ceremony
      binding <credential-id> to <keyfile>'s public key, with the given
      initial sign-count. (Pillar's RP validates no attestation *statement*
      signature — `fmt="none"` — so registration needs no signing, only the
      real embedded COSE public key.)

  sign-assertion <keyfile> <challenge-b64url> <origin> <sign-count>
      Print THREE lines: authenticatorData (b64url), clientDataJSON (b64url),
      and a REAL Ed25519 signature (b64url) over
      `authenticatorData || SHA-256(clientDataJSON)`, produced with the
      private key at <keyfile> — the exact payload
      `pillar_crypto::webauthn::verify_assertion` recomputes and checks.

  unlock-expect <credential-id> <prf-output-b64url>
      Print the base64url operational-key-unlock secret this harness expects
      the RP to derive via `pillar_crypto::webauthn::derive_unlock_secret`
      (a real HKDF-SHA256 over the PRF output, salted by the credential id) —
      computed HERE, independently, from the SAME public formula the crate
      documents, so the scenario can prove the server's `UNLOCKED <secret>`
      reply is the product of the real derivation and not a placeholder.
"""

import base64
import hashlib
import hmac
import struct
import subprocess
import sys
import tempfile

COSE_KTY_OKP = 1
COSE_ALG_EDDSA = -8
COSE_CRV_ED25519 = 6

AUTH_FLAG_UP = 0x01
AUTH_FLAG_AT = 0x40


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- minimal, dependency-free CBOR encoder for the small fixed shapes this
# module needs (definite-length major types only; every map here has <24
# entries and every text/byte string used here is short) --------------------


def _cbor_uint(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    raise ValueError(f"value {n} too large for this minimal encoder")


def cbor_uint(n: int) -> bytes:
    assert n >= 0
    return _cbor_uint(0, n)


def cbor_nint(n: int) -> bytes:
    # CBOR major type 1: encodes -(n+1) for a stored unsigned value n.
    assert n < 0
    return _cbor_uint(1, (-1) - n)


def cbor_bytes(b: bytes) -> bytes:
    return _cbor_uint(2, len(b)) + b


def cbor_text(s: str) -> bytes:
    b = s.encode("utf-8")
    return _cbor_uint(3, len(b)) + b


def cbor_map_header(n_pairs: int) -> bytes:
    return _cbor_uint(5, n_pairs)


def cbor_empty_map() -> bytes:
    return cbor_map_header(0)


def cose_ed25519_public_key(raw_pub32: bytes) -> bytes:
    assert len(raw_pub32) == 32
    out = cbor_map_header(4)
    out += cbor_uint(1) + cbor_uint(COSE_KTY_OKP)
    out += cbor_uint(3) + cbor_nint(COSE_ALG_EDDSA)
    out += cbor_nint(-1) + cbor_uint(COSE_CRV_ED25519)
    out += cbor_nint(-2) + cbor_bytes(raw_pub32)
    return out


def attestation_object(auth_data: bytes) -> bytes:
    out = cbor_map_header(3)
    out += cbor_text("fmt") + cbor_text("none")
    out += cbor_text("attStmt") + cbor_empty_map()
    out += cbor_text("authData") + cbor_bytes(auth_data)
    return out


def client_data_json(ceremony_type: str, challenge_b64url: str, origin: str) -> bytes:
    return (
        '{"type":"%s","challenge":"%s","origin":"%s"}'
        % (ceremony_type, challenge_b64url, origin)
    ).encode("utf-8")


# --- openssl-backed Ed25519 keygen / raw-pubkey extraction / raw signing ----


def openssl_genpkey(keyfile: str) -> None:
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", keyfile],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def openssl_raw_pubkey(keyfile: str) -> bytes:
    # `openssl pkey -pubout -outform DER` on an Ed25519 key emits a fixed
    # 12-byte SubjectPublicKeyInfo prefix followed by the raw 32-byte key
    # (RFC 8410) — the last 32 bytes are exactly the raw public key.
    der = subprocess.run(
        ["openssl", "pkey", "-in", keyfile, "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    if len(der) < 32:
        raise RuntimeError("unexpected DER pubkey encoding")
    return der[-32:]


def openssl_raw_sign(keyfile: str, message: bytes) -> bytes:
    with tempfile.NamedTemporaryFile() as msg_f:
        msg_f.write(message)
        msg_f.flush()
        sig = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", keyfile, "-rawin", "-in", msg_f.name],
            check=True,
            capture_output=True,
        ).stdout
    return sig


def build_auth_data(
    sign_count: int,
    *,
    attested: bool,
    credential_id: bytes = b"",
    cose_key: bytes = b"",
) -> bytes:
    flags = AUTH_FLAG_UP | (AUTH_FLAG_AT if attested else 0)
    out = bytes(32)  # rpIdHash: unchecked by the RP (see pillar-web/src/webauthn.rs)
    out += bytes([flags])
    out += struct.pack(">I", sign_count)
    if attested:
        out += bytes(16)  # aaguid
        out += struct.pack(">H", len(credential_id))
        out += credential_id
        out += cose_key
    return out


def derive_unlock_secret(prf_output: bytes, credential_id: bytes) -> bytes:
    # HKDF-SHA256(salt=credential_id, ikm=prf_output) -> expand(info, 32) —
    # mirrors crates/pillar-crypto/src/webauthn.rs::derive_unlock_secret
    # exactly (the `hkdf` crate's `Hkdf::<Sha256>::new(Some(salt), ikm)`).
    prk = hmac.new(credential_id, prf_output, hashlib.sha256).digest()
    info = b"pillar-crypto/webauthn/prf-unlock-v1"
    t1 = hmac.new(prk, info + bytes([1]), hashlib.sha256).digest()
    return t1[:32]


def cmd_genkey(args):
    (keyfile,) = args
    openssl_genpkey(keyfile)


def cmd_register_attestation(args):
    keyfile, credential_id, sign_count = args
    pub = openssl_raw_pubkey(keyfile)
    cose = cose_ed25519_public_key(pub)
    auth_data = build_auth_data(
        int(sign_count),
        attested=True,
        credential_id=credential_id.encode("utf-8"),
        cose_key=cose,
    )
    att = attestation_object(auth_data)
    print(b64url_encode(att))


def cmd_sign_assertion(args):
    keyfile, challenge_b64url, origin, sign_count = args
    cdj = client_data_json("webauthn.get", challenge_b64url, origin)
    auth_data = build_auth_data(int(sign_count), attested=False)
    signed = auth_data + hashlib.sha256(cdj).digest()
    sig = openssl_raw_sign(keyfile, signed)
    print(b64url_encode(auth_data))
    print(b64url_encode(cdj))
    print(b64url_encode(sig))


def cmd_unlock_expect(args):
    credential_id, prf_output_b64url = args
    prf_output = b64url_decode(prf_output_b64url)
    secret = derive_unlock_secret(prf_output, credential_id.encode("utf-8"))
    print(b64url_encode(secret))


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    handlers = {
        "genkey": cmd_genkey,
        "register-attestation": cmd_register_attestation,
        "sign-assertion": cmd_sign_assertion,
        "unlock-expect": cmd_unlock_expect,
    }
    fn = handlers.get(cmd)
    if fn is None:
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        return 2
    fn(rest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
