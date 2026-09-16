//! Infra-supplied outbound SMTP mail for the portal's self-service email
//! flows (`um-email-selfservice-reset`). Every host/port/credential/from
//! address is supplied at RUNTIME through environment configuration
//! (`PILLAR_SMTP_*`) — never a hardcoded infra identifier in source
//! (`AGENTS.md`'s infra-identifier rule). Delivery is best-effort: a caller
//! whose account mutation already applied never fails the request merely
//! because outbound mail could not be sent (see callers in `web_serve.rs`).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Runtime SMTP configuration — read ONLY from the environment.
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    /// The relay host to connect to (`PILLAR_SMTP_HOST`). Unused when
    /// `capture_dir` is set.
    pub host: String,
    /// The relay port (`PILLAR_SMTP_PORT`, default 25).
    pub port: u16,
    /// The envelope/`From:` address (`PILLAR_SMTP_FROM`).
    pub from: String,
    /// When set, outbound mail is written as a `.eml` file under this
    /// directory instead of opening a live SMTP connection
    /// (`PILLAR_SMTP_CAPTURE_DIR`) — the standard local/dev/test mail-capture
    /// delivery backend an operator points a non-production cell at instead
    /// of a real relay. A real install configures a real `PILLAR_SMTP_HOST`
    /// instead.
    pub capture_dir: Option<PathBuf>,
}

impl SmtpConfig {
    /// Load from the environment. Returns `None` when NEITHER a relay host
    /// nor a capture directory is configured — the caller then skips
    /// delivery entirely rather than failing the triggering request (the
    /// underlying account mutation, e.g. a re-enrollment offer, already
    /// applied independent of whether mail delivery is configured).
    #[must_use]
    pub fn from_env() -> Option<SmtpConfig> {
        let capture_dir = std::env::var("PILLAR_SMTP_CAPTURE_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let host = std::env::var("PILLAR_SMTP_HOST")
            .ok()
            .filter(|s| !s.is_empty());
        if capture_dir.is_none() && host.is_none() {
            return None;
        }
        let from = std::env::var("PILLAR_SMTP_FROM")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "no-reply@localhost".to_owned());
        let port: u16 = std::env::var("PILLAR_SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(25);
        Some(SmtpConfig {
            host: host.unwrap_or_default(),
            port,
            from,
            capture_dir,
        })
    }
}

/// Send one plaintext email. Either writes a `.eml` capture file
/// (`capture_dir` configured) or speaks a minimal real SMTP dialog
/// (`EHLO`/`MAIL FROM`/`RCPT TO`/`DATA`) to `host:port`.
pub fn send_mail(cfg: &SmtpConfig, to: &str, subject: &str, body: &str) -> Result<(), String> {
    let message = format!(
        "From: {}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n",
        cfg.from
    );
    if let Some(dir) = &cfg.capture_dir {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let safe_to: String = to
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let path = dir.join(format!("{stamp}-{safe_to}.eml"));
        std::fs::write(path, message).map_err(|e| e.to_string())
    } else {
        send_via_smtp(cfg, to, &message)
    }
}

fn send_via_smtp(cfg: &SmtpConfig, to: &str, message: &str) -> Result<(), String> {
    let stream = TcpStream::connect((cfg.host.as_str(), cfg.port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    read_smtp_reply(&mut reader)?; // banner
    smtp_cmd(&mut writer, &mut reader, "EHLO pillar\r\n")?;
    smtp_cmd(
        &mut writer,
        &mut reader,
        &format!("MAIL FROM:<{}>\r\n", cfg.from),
    )?;
    smtp_cmd(&mut writer, &mut reader, &format!("RCPT TO:<{to}>\r\n"))?;
    smtp_cmd(&mut writer, &mut reader, "DATA\r\n")?;
    writer
        .write_all(message.as_bytes())
        .map_err(|e| e.to_string())?;
    smtp_cmd(&mut writer, &mut reader, "\r\n.\r\n")?;
    smtp_cmd(&mut writer, &mut reader, "QUIT\r\n")?;
    Ok(())
}

fn smtp_cmd(
    writer: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    cmd: &str,
) -> Result<(), String> {
    writer
        .write_all(cmd.as_bytes())
        .map_err(|e| e.to_string())?;
    read_smtp_reply(reader)
}

fn read_smtp_reply(reader: &mut BufReader<TcpStream>) -> Result<(), String> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line.len() < 4 {
            return Err(format!("short SMTP reply: {line:?}"));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| format!("bad SMTP reply code: {line:?}"))?;
        if code >= 400 {
            return Err(format!("SMTP error: {}", line.trim_end()));
        }
        // A multi-line reply continues with "250-...."; the final line of the
        // group carries a space in the 4th column.
        if line.as_bytes().get(3) == Some(&b' ') {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_config_when_neither_host_nor_capture_dir_is_set() {
        // SAFETY-equivalent: this test only reads/writes its own process env
        // vars under the crate's serialized test harness assumption typical
        // of `std::env::var` usage elsewhere in this codebase.
        std::env::remove_var("PILLAR_SMTP_HOST");
        std::env::remove_var("PILLAR_SMTP_CAPTURE_DIR");
        assert!(SmtpConfig::from_env().is_none());
    }

    #[test]
    fn capture_dir_delivery_writes_an_eml_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = SmtpConfig {
            host: String::new(),
            port: 25,
            from: "no-reply@example.com".to_owned(),
            capture_dir: Some(dir.path().to_path_buf()),
        };
        send_mail(&cfg, "user@example.com", "subject line", "body text")
            .expect("capture delivery must succeed");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read capture dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "exactly one .eml file must be written");
        let content = std::fs::read_to_string(entries[0].path()).expect("read .eml");
        assert!(content.contains("subject line"));
        assert!(content.contains("body text"));
        assert!(content.contains("To: user@example.com"));
    }
}
