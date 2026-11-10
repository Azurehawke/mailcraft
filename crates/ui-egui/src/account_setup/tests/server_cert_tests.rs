// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Add Account and an IMAP or SMTP server's own certificate (Azurehawke fork).
use super::*;

/// A home server's own certificate (Azurehawke fork): the check stops at it, the owner sees
/// it and trusts it, and the account is checked again and added trusting exactly that one.
#[test]
fn a_servers_own_certificate_can_be_trusted() {
    use mailcraft_model::server_certificate::{Role as ServerRole, UntrustedCertificate, note};
    let fingerprint = "c0".repeat(32);
    let said = note(
        "the server's certificate is not one this computer trusts",
        &UntrustedCertificate {
            role: ServerRole::Incoming,
            fingerprint: fingerprint.clone(),
            subject: "mail.home".into(),
            issuer: "mail.home".into(),
            not_before: 1_700_000_000,
            not_after: 1_900_000_000,
            changed: false,
        },
    );
    let mut a = app(false);
    lookups(&mut a, Some(Ok(vec!["mx.lumen.example"])));
    // The first check stops at the certificate; the next goes through.
    let tried: Log<(Account, String)> = Default::default();
    let log = tried.clone();
    a.services.test_account = Some(Box::new(move |account, secret| {
        let mut log = log.lock().unwrap();
        log.push((account, secret));
        let (tx, rx) = mpsc::channel();
        tx.send(if log.len() == 1 { Err(said.clone()) } else { Ok(()) }).unwrap();
        rx
    }));
    let mut h = open(a, json!({}));
    connect(&mut h, "noor@lumen.example");
    assert_eq!(page(&h), Some(Page::Password));
    {
        let w = wizard_mut(&mut h);
        w.incoming.host = "100.107.227.53".into();
        w.outgoing.host = "100.107.227.53".into();
    }
    type_password(&mut h);
    press(&mut h, Key::Enter);
    h.run();
    assert_eq!(page(&h), Some(Page::ServerCertificate));
    h.run();
    assert!(says(&h, "Trust this server's certificate?"), "heading");
    assert!(says(&h, "c0:c0:c0"), "fingerprint");
    // Not before the box is ticked.
    assert_eq!(wizard(&h).unwrap().server_certificate.as_ref().map(|(_, ticked)| *ticked), Some(false));
    press(&mut h, Key::Enter);
    assert_eq!(page(&h), Some(Page::ServerCertificate));
    h.get_by_role_and_label(Role::CheckBox, "Trust this certificate for this server").click();
    h.run();
    click(&mut h, "Continue");
    h.run();
    let tried = tried.lock().unwrap();
    assert_eq!(tried.len(), 2);
    let again = &tried[1].0;
    assert_eq!(again.incoming.as_ref().unwrap().trusted, fingerprint);
    // The same host's outgoing server trusts it too.
    assert_eq!(again.outgoing.as_ref().unwrap().trusted, fingerprint);
    let added = h.state().session.mailbox.accounts.iter().find(|a| a.email == "noor@lumen.example").unwrap().clone();
    assert_eq!(added.incoming.unwrap().trusted, fingerprint);
}
