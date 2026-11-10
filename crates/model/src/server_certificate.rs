// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A mail server's certificate that the system doesn't trust, as the check of an account's
//! servers reports it to Add Account (Azurehawke fork).
//!
//! The account check answers with a sentence; when the sentence is about a certificate the owner
//! could choose to trust (a home server's own, self-issued one), a line is put after it holding
//! what Add Account shows before asking: which server it was (incoming or outgoing), its
//! SHA-256 fingerprint, who it was issued to and by, and its last day. [`note`] writes it and
//! [`read`] reads it back; [`sentence`] is the text without it.

use serde::{Deserialize, Serialize};

/// What starts the line that carries the certificate.
const MARK: &str = "\n[server certificate] ";

/// Longest line read back.
const MAX_LINE: usize = 4 * 1024;

/// Which of the account's servers showed the certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Incoming,
    Outgoing,
}

/// A certificate the owner may be offered to trust for one of the account's servers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UntrustedCertificate {
    pub role: Role,
    /// 64 lower-case hexadecimal digits.
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    /// The first moment it is valid, in seconds since 1970-01-01 UTC.
    pub not_before: i64,
    /// The last moment it is valid, in seconds since 1970-01-01 UTC.
    pub not_after: i64,
    /// The account already trusted another certificate for this server: this one replaced it.
    pub changed: bool,
}

/// `sentence`, followed by the line that carries `certificate`.
pub fn note(sentence: &str, certificate: &UntrustedCertificate) -> String {
    match serde_json::to_string(certificate) {
        Ok(json) => format!("{sentence}{MARK}{json}"),
        Err(_) => sentence.to_string(),
    }
}

/// The certificate an account check's answer carries, if it carries a sound one.
pub fn read(said: &str) -> Option<UntrustedCertificate> {
    let (_, json) = said.split_once(MARK)?;
    if json.len() > MAX_LINE {
        return None;
    }
    let certificate: UntrustedCertificate = serde_json::from_str(json.lines().next()?).ok()?;
    let sound = certificate.fingerprint.len() == 64 && certificate.fingerprint.bytes().all(|b| b.is_ascii_hexdigit());
    sound.then(|| UntrustedCertificate { fingerprint: certificate.fingerprint.to_ascii_lowercase(), ..certificate })
}

/// The answer without the line that carries the certificate.
pub fn sentence(said: &str) -> &str {
    said.split_once(MARK).map_or(said, |(sentence, _)| sentence)
}

#[cfg(test)]
#[path = "server_certificate_tests.rs"]
mod server_certificate_tests;
