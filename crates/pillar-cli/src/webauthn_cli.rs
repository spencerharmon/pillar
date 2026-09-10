//! `pillar webauthn register|login`: the CLI's WebAuthn ceremony surface,
//! driven over ctap-hid against a locally attached hardware authenticator.
//!
//! This is CLI parity with the browser path (`web_serve`'s
//! `/webauthn/register/*` and `/webauthn/authenticate/*` dispatchers): the
//! CLI acts as its own WebAuthn "client" — building the SAME `clientDataJSON`
//! structure a browser's `navigator.credentials.{create,get}()` would, asking
//! a real CTAP2 authenticator to sign over it via
//! [`pillar_crypto::webauthn::ctap_client`], and wrapping the result into the
//! SAME attestation-object / assertion wire format the node's real RP
//! ([`pillar_web::webauthn::RelyingParty`], via `parse_attestation` /
//! `verify_assertion`) already verifies for the browser. No CLI-only
//! credential shape exists anywhere in this path.
//!
//! The hardware I/O is behind the `passkey` Cargo feature (already folded
//! into every deployed node's `hsm` build, see `crates/pillar-crypto`'s
//! `Cargo.toml`); a build without the feature fails closed with a clear
//! message rather than attempting device I/O.

use crate::bootstrap::{authority_of, http};
use pillar_bootstrap::token::{PILLAR_DOMAIN_ENV, PILLAR_TOKEN_ENV};

/// The RP origin the CLI ceremony is scoped to when `--origin` is not given.
/// Matches the fixture origin `pillar-web::webauthn`'s own tests and
/// `web_serve`'s simulated-browser tests use.
const DEFAULT_ORIGIN: &str = "https://pillar.local";
/// The relying-party id the CLI assumes when the server did not hand one back
/// (only `/webauthn/register/begin` echoes `rp_id`; `/webauthn/authenticate/begin`
/// does not) and `--rp-id` was not given.
const DEFAULT_RP_ID: &str = "pillar.local";

/// A minimal `--flag value` argv scanner, mirroring `bootstrap::Args` (kept
/// private there) for this module's own small surface (no positional args).
struct Args<'a> {
    flags: Vec<(&'a str, String)>,
}

impl<'a> Args<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if let Some(name) = a.strip_prefix("--") {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("flag --{name} requires a value"))?;
                flags.push((name, value.clone()));
                i += 2;
            } else {
                return Err(format!("unexpected positional argument `{a}`"));
            }
        }
        Ok(Args { flags })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn domain_from(parsed: &Args<'_>) -> Result<(String, String), String> {
    if let Some(d) = parsed.get("domain") {
        return Ok(authority_of(d));
    }
    let d = std::env::var(PILLAR_DOMAIN_ENV).map_err(|_| {
        format!(
            "no --domain and {PILLAR_DOMAIN_ENV} is unset — run `pillar login` or pass --domain"
        )
    })?;
    Ok(authority_of(&d))
}

fn token_from(parsed: &Args<'_>) -> Result<String, String> {
    if let Some(t) = parsed.get("token") {
        return Ok(t.to_owned());
    }
    std::env::var(PILLAR_TOKEN_ENV).map_err(|_| {
        format!("{PILLAR_TOKEN_ENV} is unset — run `pillar login` first, or pass --token")
    })
}

fn usage() -> &'static str {
    "usage:\n\
     \x20 pillar webauthn register --user <handle> [--label L] [--domain D] [--token T] [--rp-id R] [--origin O]\n\
     \x20 pillar webauthn login [--credential-id C] [--domain D] [--token T] [--rp-id R] [--origin O]\n\
     \x20 pillar webauthn list [--domain D] [--token T]\n\
     \x20 pillar webauthn revoke --credential-id <b64url> [--domain D] [--token T]\n\
     register/login drive the real ceremony over ctap-hid against a locally\n\
     attached hardware authenticator (requires the `passkey` feature); pass\n\
     --rp-id <domain> to register a PORTABLE passkey bound to that domain.\n\
     list/revoke manage the credential set over HTTP (no hardware needed)."
}

/// Dispatch `pillar webauthn <sub> …`.
///
/// # Errors
///
/// A human-readable message for any usage, transport, or ceremony error.
pub fn run(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("register") => register(&args[1..]),
        Some("login") => login(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        _ => Err(usage().to_owned()),
    }
}

/// `pillar webauthn register --user <handle>`: register a fresh credential
/// with a locally attached hardware authenticator against the node's real
/// WebAuthn RP.
///
/// 1. `POST /webauthn/register/begin` — mint a fresh challenge (+ echoed
///    `rp_id`).
/// 2. Drive `authenticatorMakeCredential` over ctap-hid
///    ([`pillar_crypto::webauthn::ctap_client::register`]).
/// 3. `POST /webauthn/register/finish` — the node parses the SAME attestation
///    object wire format the browser path produces and persists the shared
///    credential record.
fn register(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let user_handle = parsed
        .get("user")
        .ok_or("webauthn register requires --user <handle>")?;
    let (authority, _host) = domain_from(&parsed)?;
    let token = token_from(&parsed)?;
    let origin = parsed.get("origin").unwrap_or(DEFAULT_ORIGIN);

    let begin = http(
        &authority,
        "POST",
        "/webauthn/register/begin",
        &format!("{token}\n{user_handle}"),
    )?;
    if begin.status != 200 {
        return Err(format!(
            "register/begin refused: {} {}",
            begin.status, begin.body
        ));
    }
    let mut fields = begin.body.split_whitespace();
    if fields.next() != Some("CHALLENGE") {
        return Err(format!("malformed register/begin reply: {}", begin.body));
    }
    let challenge_b64 = fields
        .next()
        .ok_or_else(|| format!("malformed register/begin reply: {}", begin.body))?;
    // The credential's rpId: an explicit --rp-id (a PORTABLE passkey bound to a
    // chosen domain / the cell IPNS name) wins; otherwise the server-echoed
    // rp_id; otherwise the fixture default. This same value is sent to the node
    // as the credential's bound-scope metadata for the management surface.
    let server_rp_id = fields.next();
    let rp_id = parsed
        .get("rp-id")
        .or(server_rp_id)
        .unwrap_or(DEFAULT_RP_ID);
    let label = parsed.get("label").unwrap_or("");

    #[cfg(feature = "passkey")]
    {
        let (attestation_object, credential_id) = pillar_crypto::webauthn::ctap_client::register(
            rp_id,
            origin,
            challenge_b64,
            user_handle.as_bytes(),
            user_handle,
        )
        .map_err(|e| format!("hardware ceremony failed: {e}"))?;
        let attestation_b64 = pillar_crypto::webauthn::base64url_encode(&attestation_object);
        let finish = http(
            &authority,
            "POST",
            "/webauthn/register/finish",
            &format!("{token}\n{user_handle}\n{challenge_b64}\n{attestation_b64}\n{label}\n{rp_id}"),
        )?;
        if finish.status != 200 {
            return Err(format!(
                "register/finish refused: {} {}",
                finish.status, finish.body
            ));
        }
        let _ = credential_id;
        Ok(finish.body)
    }
    #[cfg(not(feature = "passkey"))]
    {
        let _ = (challenge_b64, rp_id, origin, token, authority, label);
        Err(
            "hardware WebAuthn ceremonies require the `passkey` build feature \
             (the deployed node's `hsm` feature set includes it)"
                .to_owned(),
        )
    }
}

/// `pillar webauthn list`: print the caller's credential set over HTTP (no
/// hardware needed). One line per live credential:
/// `<id-b64url>  <label>  <rp_id>  created=<unix>  last_used=<unix|->  signs=<n>`.
fn list(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let (authority, _host) = domain_from(&parsed)?;
    let token = token_from(&parsed)?;
    let resp = http(&authority, "POST", "/webauthn/credentials/list", &token)?;
    if resp.status != 200 {
        return Err(format!("credentials/list refused: {} {}", resp.status, resp.body));
    }
    if resp.body.trim().is_empty() {
        return Ok("no credentials enrolled".to_owned());
    }
    let mut out = String::new();
    for line in resp.body.lines() {
        // `CRED <id> <label> <rp_id> <created> <last|-> <signs>`
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() == 7 && f[0] == "CRED" {
            out.push_str(&format!(
                "{}  {}  {}  created={}  last_used={}  signs={}\n",
                f[1], f[2], f[3], f[4], f[5], f[6]
            ));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out.trim_end().to_owned())
}

/// `pillar webauthn revoke --credential-id <b64url>`: permanently revoke one
/// credential from the caller's set over HTTP (no hardware needed).
fn revoke(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let credential_id_b64 = parsed
        .get("credential-id")
        .ok_or("webauthn revoke requires --credential-id <b64url> (from `webauthn list`)")?;
    let (authority, _host) = domain_from(&parsed)?;
    let token = token_from(&parsed)?;
    let resp = http(
        &authority,
        "POST",
        "/webauthn/credentials/revoke",
        &format!("{token}\n{credential_id_b64}"),
    )?;
    if resp.status != 200 {
        return Err(format!("credentials/revoke refused: {} {}", resp.status, resp.body));
    }
    Ok(resp.body)
}

/// `pillar webauthn login`: authenticate with an already-registered hardware
/// credential against the node's real WebAuthn RP.
///
/// 1. `POST /webauthn/authenticate/begin` — mint a fresh challenge.
/// 2. Drive `authenticatorGetAssertion` (with the `hmac-secret` extension) over
///    ctap-hid ([`pillar_crypto::webauthn::ctap_client::authenticate_with_prf`]).
/// 3. `POST /webauthn/authenticate/finish` — the node verifies the SAME
///    assertion wire format the browser path produces, enforces sign-count
///    monotonicity, and derives the operational-key-unlock secret.
///
/// Requires `--credential-id <b64url>` (the id returned by a prior
/// `register`), since `authenticator/*` credential discovery (resident keys)
/// is out of scope here.
fn login(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let credential_id_b64 = parsed
        .get("credential-id")
        .ok_or("webauthn login requires --credential-id <b64url> (from a prior `register`)")?;
    let (authority, _host) = domain_from(&parsed)?;
    let token = token_from(&parsed)?;
    let origin = parsed.get("origin").unwrap_or(DEFAULT_ORIGIN);
    let rp_id = parsed.get("rp-id").unwrap_or(DEFAULT_RP_ID);

    let begin = http(&authority, "POST", "/webauthn/authenticate/begin", &token)?;
    if begin.status != 200 {
        return Err(format!(
            "authenticate/begin refused: {} {}",
            begin.status, begin.body
        ));
    }
    let mut fields = begin.body.split_whitespace();
    if fields.next() != Some("CHALLENGE") {
        return Err(format!(
            "malformed authenticate/begin reply: {}",
            begin.body
        ));
    }
    let challenge_b64 = fields
        .next()
        .ok_or_else(|| format!("malformed authenticate/begin reply: {}", begin.body))?;

    #[cfg(feature = "passkey")]
    {
        let credential_id = pillar_crypto::webauthn::base64url_decode(credential_id_b64)
            .map_err(|e| format!("malformed --credential-id: {e}"))?;
        // The PRF salt must match the RP's derivation
        // (`content_address(challenge)`'s trailing 32 bytes, see
        // `web_serve::dispatch_webauthn_register_finish`); the RP recomputes
        // the SAME salt from the challenge it just minted, so the CLI derives
        // it identically rather than needing the server to hand it back.
        let src = pillar_crypto::content::content_address(
            &pillar_crypto::webauthn::base64url_decode(challenge_b64)
                .map_err(|e| format!("malformed challenge: {e}"))?,
        )
        .map_err(|e| format!("content_address failed: {e}"))?;
        let src = src.as_bytes();
        let mut prf_salt = [0u8; 32];
        prf_salt.copy_from_slice(&src[src.len() - 32..]);

        let (auth_data, client_data_json, signature, prf_output) =
            pillar_crypto::webauthn::ctap_client::authenticate_with_prf(
                rp_id,
                origin,
                challenge_b64,
                &credential_id,
                prf_salt,
            )
            .map_err(|e| format!("hardware ceremony failed: {e}"))?;

        let ad_b64 = pillar_crypto::webauthn::base64url_encode(&auth_data);
        let cdj_b64 = pillar_crypto::webauthn::base64url_encode(&client_data_json);
        let sig_b64 = pillar_crypto::webauthn::base64url_encode(&signature);
        let prf_b64 = pillar_crypto::webauthn::base64url_encode(&prf_output);
        let finish = http(
            &authority,
            "POST",
            "/webauthn/authenticate/finish",
            &format!(
                "{token}\n{challenge_b64}\n{credential_id_b64}\n{ad_b64}\n{cdj_b64}\n{sig_b64}\n{prf_b64}"
            ),
        )?;
        if finish.status != 200 {
            return Err(format!(
                "authenticate/finish refused: {} {}",
                finish.status, finish.body
            ));
        }
        Ok(finish.body)
    }
    #[cfg(not(feature = "passkey"))]
    {
        let _ = (challenge_b64, rp_id, origin, credential_id_b64);
        Err(
            "hardware WebAuthn ceremonies require the `passkey` build feature \
             (the deployed node's `hsm` feature set includes it)"
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parses_flags() {
        let argv: Vec<String> = vec![
            "--user".into(),
            "alice".into(),
            "--domain".into(),
            "d".into(),
        ];
        let parsed = Args::parse(&argv).expect("parses");
        assert_eq!(parsed.get("user"), Some("alice"));
        assert_eq!(parsed.get("domain"), Some("d"));
    }

    #[test]
    fn missing_user_flag_is_a_usage_error() {
        let err = register(&[]).unwrap_err();
        assert!(err.contains("--user"), "unexpected error: {err}");
    }

    #[test]
    fn login_without_credential_id_is_a_usage_error() {
        let err = login(&["--domain".to_owned(), "127.0.0.1:1".to_owned()]).unwrap_err();
        assert!(err.contains("--credential-id"), "unexpected error: {err}");
    }

    #[test]
    fn unknown_verb_is_a_usage_error() {
        let err = run(&["bogus".to_owned()]).unwrap_err();
        assert!(err.contains("usage"), "unexpected error: {err}");
    }
}
