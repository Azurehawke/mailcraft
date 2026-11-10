// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The system's certificate check (#501), against the fake IMAP server on this machine: what the
//! verifier trusts connects, what it doesn't is refused before a password goes anywhere, and the
//! name is still checked. Nothing here reaches the network.
use std::sync::Arc;

use mailcraft_model::{Account, Security, Server};
use rustls::ServerConfig;

use crate::NetError;
use crate::fake::{Fake, ImapWorld, MailIo};
use crate::tls_test_support::{Authority, trusting};

fn account(port: u16) -> Account {
    Account {
        email: "user@example.org".into(),
        incoming: Some(Server { host: "127.0.0.1".into(), port, security: Security::StartTls, trusted: String::new() }),
        ..Default::default()
    }
}

/// A fake IMAP server that offers STARTTLS and then shakes hands with `server`.
fn imap(server: Arc<ServerConfig>) -> Fake<ImapWorld> {
    Fake::imap(ImapWorld {
        user: "user@example.org".into(),
        password: "invented".into(),
        offer_starttls: true,
        starttls_upgrade: Some(Arc::new(move |stream| -> Box<dyn MailIo> {
            let connection = rustls::ServerConnection::new(server.clone()).unwrap();
            Box::new(rustls::StreamOwned::new(connection, stream))
        })),
        ..Default::default()
    })
}

/// Why the connection to the fake was refused, which must be its certificate; no password went.
/// (Azurehawke fork: an IMAP server's certificate that isn't trusted is offered to its owner, so
/// the refusal comes with what they are shown, and the system's own words are not in it.)
fn refused(peer: &Fake<ImapWorld>) -> String {
    let Err(error) = crate::sync::open_imap(&account(peer.port), "invented") else { panic!("the connection was allowed") };
    let NetError::Certificate(problem) = &error else { panic!("refused, but not by the certificate check: {error}") };
    assert!(matches!(**problem, crate::cert::CertificateProblem::NotTrusted(_)), "{error}");
    assert!(!peer.world().log.iter().any(|s| s.contains("AUTHENTICATE") || s.contains(" LOGIN ")));
    error.to_string()
}

#[test]
fn a_certificate_the_verifier_trusts_connects() {
    let authority = Authority::new("MailCraft Test Authority");
    let peer = imap(authority.server(&["localhost", "127.0.0.1"]));
    trusting(vec![authority.root()], || {
        let result = crate::sync::open_imap(&account(peer.port), "invented");
        assert!(result.is_ok(), "{:?}", result.err().map(|e| e.to_string()));
    });
    assert!(peer.world().log.iter().any(|s| s.contains(" STARTTLS")));
}

#[test]
fn a_certificate_from_an_authority_nobody_trusts_is_refused() {
    let trusted = Authority::new("MailCraft Test Authority");
    let stranger = Authority::new("Unknown Test Authority");
    let peer = imap(stranger.server(&["localhost", "127.0.0.1"]));
    let reason = trusting(vec![trusted.root()], || refused(&peer));
    assert!(reason.contains("certificate"), "{reason}");
}

#[test]
fn a_test_authority_is_not_trusted_by_the_system() {
    // Without a test's own roots, only what the system trusts is trusted.
    let authority = Authority::new("MailCraft Test Authority");
    let peer = imap(authority.server(&["localhost", "127.0.0.1"]));
    let reason = refused(&peer);
    assert!(reason.contains("certificate"), "{reason}");
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let authority = Authority::new("MailCraft Test Authority");
    let peer = imap(authority.server(&["mail.example.org"]));
    let reason = trusting(vec![authority.root()], || refused(&peer));
    // Refused all the same: only a certificate the owner chose by its fingerprint goes through.
    assert!(reason.contains("certificate"), "{reason}");
}

#[test]
fn the_settings_for_mail_and_pictures_build_from_the_system() {
    for purpose in [crate::tls::Purpose::Mail, crate::tls::Purpose::Picture] {
        let config = crate::tls::client_config(purpose).unwrap();
        assert_eq!(config.alpn_protocols.is_empty(), purpose == crate::tls::Purpose::Mail);
    }
}
