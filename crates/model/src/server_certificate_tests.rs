// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;

fn certificate() -> UntrustedCertificate {
    UntrustedCertificate {
        role: Role::Outgoing,
        fingerprint: "AB".repeat(32),
        subject: "mail.home; \"quoted\"".into(),
        issuer: "mail.home".into(),
        not_before: 1_700_000_000,
        not_after: 1_900_000_000,
        changed: false,
    }
}

#[test]
fn a_note_reads_back_and_leaves_its_sentence() {
    let said = note("the server's certificate is not one this computer trusts", &certificate());
    let read = read(&said).unwrap();
    assert_eq!(read.fingerprint, "ab".repeat(32));
    assert_eq!(read.role, Role::Outgoing);
    assert_eq!(read.subject, "mail.home; \"quoted\"");
    assert_eq!(sentence(&said), "the server's certificate is not one this computer trusts");
}

#[test]
fn anything_else_carries_no_certificate() {
    for said in ["sign-in failed", "", "x\n[server certificate] {", "x\n[server certificate] {\"role\":\"incoming\"}"] {
        assert_eq!(read(said), None, "{said:?}");
        assert!(!said.is_empty() || sentence(said).is_empty());
    }
    let short = note("x", &UntrustedCertificate { fingerprint: "ab".into(), ..certificate() });
    assert_eq!(read(&short), None);
    let long = format!("x\n[server certificate] {}", "a".repeat(10_000));
    assert_eq!(read(&long), None);
}
