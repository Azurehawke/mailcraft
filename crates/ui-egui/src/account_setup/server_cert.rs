// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! An IMAP or SMTP server's own certificate (Azurehawke fork).
//!
//! A home or office server often has a certificate it issued itself, which no system trusts.
//! When the check of a new account's servers stops at such a certificate, the owner is shown it
//! (who it was issued to and by, its dates, its SHA-256 fingerprint, to compare with the one on
//! the server) and may trust exactly that certificate for that server. Its fingerprint is kept
//! with the server's settings (`Server::trusted`); any other certificate is still refused, and a
//! changed one is asked about again.

use mailcraft_model::server_certificate::Role as ServerRole;

use super::*;

/// A moment as a date for the certificate page.
fn day_of(timestamp: i64) -> String {
    crate::dates::medium(mailcraft_time::DateTime::from_timestamp(timestamp, 0).date)
}

impl AccountSetup {
    /// Trust this server's certificate? Continue (with the box ticked) or Back.
    pub(super) fn server_certificate_page(&mut self, ui: &mut Ui, pass: &Pass) -> Option<Action> {
        let t = pass.t;
        let Some((certificate, _)) = self.server_certificate.clone() else {
            return Some(Action::Back);
        };
        let (server, which) = match certificate.role {
            ServerRole::Incoming => (&self.incoming, tl!("incoming mail (IMAP)")),
            ServerRole::Outgoing => (&self.outgoing, tl!("outgoing mail (SMTP)")),
        };
        let host = shown(server.host.trim(), 120);
        page(ui, &t, |ui| {
            heading(ui, if certificate.changed { tl!("The server's certificate has changed") } else { tl!("Trust this server's certificate?") }, &t);
            let says = if certificate.changed {
                tl!(
                    "The certificate the {which} server at {host} shows is not the one you trusted for it, and this computer doesn't trust it. Trust it only if you replaced the server's certificate yourself."
                )
            } else {
                tl!(
                    "This computer doesn't trust the certificate the {which} server at {host} shows. If this is your own server with a certificate it issued itself, compare the fingerprint below with the one on the server, then trust this one certificate."
                )
            };
            note(ui, &fmt(says, &[("which", which), ("host", &host)]), t.text);
            ui.add_space(4.0);
            let row = |ui: &mut Ui, label: &str, value: &str, mono: bool| {
                caption(ui, label, &t);
                let text = RichText::new(value).color(t.text);
                ui.label(if mono { text.monospace() } else { text });
            };
            row(ui, tl!("Issued to"), &shown(&certificate.subject, 160), false);
            row(ui, tl!("Issued by"), &shown(&certificate.issuer, 160), false);
            row(
                ui,
                tl!("Valid"),
                &fmt(tl!("from {from} to {to}"), &[("from", &day_of(certificate.not_before)), ("to", &day_of(certificate.not_after))]),
                false,
            );
            row(ui, tl!("SHA-256 fingerprint"), &exchange::grouped(&certificate.fingerprint), true);
            ui.add_space(6.0);
            if let Some((_, ticked)) = self.server_certificate.as_mut() {
                ui.checkbox(ticked, tl!("Trust this certificate for this server"));
            }
            note(
                ui,
                tl!(
                    "Only this certificate is trusted, and only for this server. If the server shows another one later, it is refused until you trust that one."
                ),
                t.text_dim,
            );
        });
        problem(ui, &self.error);
        let ready = self.server_certificate.as_ref().is_some_and(|(_, ticked)| *ticked);
        let (mut go, mut back) = (false, false);
        strip(ui, self.page, |ui| {
            go = button(ui, tl!("Continue"), true, ready).clicked();
            back = button(ui, tl!("Back"), false, true).clicked();
        });
        if back { Some(Action::Back) } else { (ready && (go || pass.submit)).then_some(Action::Go) }
    }

    /// The owner trusts the certificate: its fingerprint goes with the server's settings (and with
    /// the other server's too when it is the same host, which as a rule shows the same
    /// certificate), and the account is checked again with it.
    pub(super) fn trust_server_certificate(&mut self, app: &mut MailApp) {
        let certificate = match self.server_certificate.take() {
            Some((certificate, true)) => certificate,
            other => {
                self.server_certificate = other;
                return;
            }
        };
        if mailcraft_model::EwsServer::check_fingerprint(&certificate.fingerprint).is_err() || certificate.fingerprint.is_empty() {
            self.go(Page::Password);
            return;
        }
        let (server, other) = match certificate.role {
            ServerRole::Incoming => (&mut self.incoming, &mut self.outgoing),
            ServerRole::Outgoing => (&mut self.outgoing, &mut self.incoming),
        };
        server.trusted = certificate.fingerprint.clone();
        if other.trusted.is_empty() && other.host.trim().eq_ignore_ascii_case(server.host.trim()) {
            other.trusted = certificate.fingerprint;
        }
        self.go(Page::Password);
        self.try_password(app);
    }
}

/// Under a server's row: the certificate trusted for it, if one is, with Forget.
pub(super) fn trusted_row(ui: &mut Ui, server: &mut ServerFields, t: &Tokens) {
    if server.trusted.is_empty() {
        return;
    }
    let start: String = exchange::grouped(&server.trusted).lines().next().unwrap_or_default().chars().take(23).collect();
    ui.horizontal(|ui| {
        ui.label(RichText::new(fmt(tl!("Trusts the certificate {fingerprint}…"), &[("fingerprint", &start)])).color(t.text_dim).small());
        if ui.small_button(tl!("Forget")).on_hover_text(tl!("Stop trusting this certificate: the system alone decides again")).clicked() {
            server.trusted.clear();
        }
    });
}
