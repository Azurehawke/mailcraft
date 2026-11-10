// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MailCraft on Android, aimed at tablets.
//!
//! Android starts the app as a `NativeActivity` (packaging/android: the manifest names the library
//! `libmailcraft_android.so`, and there is no Java) and calls [`android_main`] on a thread of its
//! own. The window is the desktop's (`mailcraft-ui-egui`), driven the way the desktop's `App`
//! drives it. What differs here:
//! - The settings, the mailbox and its content live in the app's private data folder.
//! - Mail is sent and received through `mailcraft-net` on background threads, as on the desktop.
//! - TLS certificates are checked by Android's own verifier, set up through JNI before any
//!   connection is made ([`init_tls`]).
//! - Not in this first build: the file pickers, the built-in updater, printing, the control
//!   channel, and the soft keyboard for typed text. (Sign-in and certificate trust are shared with
//!   the desktop's window and have not been tried on a device yet.)
//!
//! Elsewhere the crate is empty, so `cargo build --workspace` on a desktop still works.
#![cfg(target_os = "android")]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver};

use mailcraft_engine::Session;
use mailcraft_engine::io::BackgroundSave;
use mailcraft_model::Mailbox;
use mailcraft_model::sync::{SyncRequest, SyncResult};
use mailcraft_ui_egui::{MailApp, Services};
use winit::platform::android::activity::AndroidApp;

/// The mailbox file in the settings folder: the same name and place as on the desktop.
fn mailbox_path() -> Option<PathBuf> {
    mailcraft_control_key::settings_dir().map(|d| d.join("mailbox.mailcraft"))
}

/// The mailbox to open, and the file it is kept in. A file that can't be read is not opened and
/// not written over: the window starts on an empty mailbox that is kept nowhere, and the file
/// stays as it was for the owner to look at.
fn open_mailbox(path: Option<PathBuf>) -> (Mailbox, Option<PathBuf>) {
    let Some(path) = path else { return (Mailbox::with_local_account("", ""), None) };
    if let Some(dir) = path.parent()
        && let Err(e) = mailcraft_engine::store::create_private_dir_all(dir)
    {
        log::warn!("settings folder {}: {e}", dir.display());
        return (Mailbox::with_local_account("", ""), None);
    }
    if !path.exists() {
        return (Mailbox::with_local_account("", ""), Some(path));
    }
    match mailcraft_engine::io::open_path(&path) {
        Ok(mailbox) => (mailbox, Some(path)),
        Err(e) => {
            log::error!("{} not opened, and not overwritten: {e}", path.display());
            (Mailbox::with_local_account("", ""), None)
        }
    }
}

/// Writes the mailbox in the background as it changes, as the desktop does.
fn background_saver(ctx: &egui::Context, path: &Path) -> Option<Box<dyn BackgroundSave>> {
    let wake = ctx.clone();
    match mailcraft_engine::store::Saver::spawn(move || wake.request_repaint()) {
        Ok(saver) => {
            saver.follow(path);
            if path.exists() {
                saver.sweep_later(path);
            }
            Some(Box::new(saver))
        }
        Err(e) => {
            log::warn!("background saving unavailable, the mailbox is saved in place: {e}");
            None
        }
    }
}

/// One Send/Receive run, on a thread of its own. Each piece of mail that comes back is handed to
/// the window as it arrives, and the window is woken for it.
fn sync_in_background(request: SyncRequest, ctx: egui::Context) -> Receiver<SyncResult> {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new().name("send/receive".into()).spawn(move || {
        let cancel = AtomicBool::new(false);
        mailcraft_net::sync_with(&request, &cancel, &mut |piece| {
            // Nobody listens any more (the window closed): the rest of the run is not needed.
            if tx.send(piece).is_ok() {
                ctx.request_repaint();
            }
        });
    });
    if let Err(e) = spawned {
        // The sender was dropped with the closure: the window sees the run end with nothing.
        log::error!("send/receive couldn't start: {e}");
    }
    rx
}

/// Sets up Android's certificate check, which `mailcraft-net` uses for every secure connection.
/// The verifier needs the app's JavaVM and its activity, which the activity hands over; this runs
/// once, before the window starts. Without it every secure connection is refused and says why.
fn init_tls() -> Result<(), String> {
    let context = ndk_context::android_context();
    // SAFETY: the VM and the activity belong to this process, and Android keeps both for as long
    // as the app runs. Attaching the thread that calls in is what the JNI requires of it.
    #[allow(unsafe_code)]
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }.map_err(|e| e.to_string())?;
    vm.attach_current_thread(|env| {
        // SAFETY: as above; the activity is a local reference for this call only.
        #[allow(unsafe_code)]
        let activity = unsafe { jni::objects::JObject::from_raw(context.context().cast()) };
        rustls_platform_verifier::android::init_with_env(env, activity)
    })
    .map_err(|e| e.to_string())
}

/// The window's app: the desktop's `MailApp`, driven as the desktop's `App` drives it.
struct MobileApp(MailApp);

impl eframe::App for MobileApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.0.logic(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.ui(ui);
    }

    fn on_exit(&mut self) {
        // A window closed while its mailbox was still opening has nothing to save.
        if self.0.is_opening() {
            return;
        }
        if let Err(e) = self.0.save_on_exit() {
            log::error!("mailbox not saved on exit: {e}");
        }
    }
}

/// Entry point, called by android-activity on its own thread once the activity is created.
#[allow(unsafe_code)] // Exported by name: android-activity looks this symbol up.
#[unsafe(no_mangle)]
fn android_main(android: AndroidApp) {
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("MailCraft"));
    std::panic::set_hook(Box::new(|info| {
        let trace = std::backtrace::Backtrace::force_capture();
        log::error!("internal error: {info}\n{trace}");
    }));

    if let Some(dir) = android.internal_data_path() {
        let tmp = dir.join("tmp");
        let _ = std::fs::create_dir_all(&tmp);
        // Android sets neither: the settings go to the app's private folder (read by
        // `settings_dir` through XDG_CONFIG_HOME, as on Linux), and temporary files go where the
        // app may write. Nothing else runs yet: this is the app's only thread besides Java's.
        #[allow(unsafe_code)]
        // SAFETY: called before eframe or any thread of ours starts, so nothing reads the
        // environment concurrently.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            std::env::set_var("TMPDIR", &tmp);
        }
        log::info!("MailCraft {} data folder {}", env!("CARGO_PKG_VERSION"), dir.display());
    }
    if let Err(e) = init_tls() {
        log::error!("the system's certificate check couldn't be set up: {e}");
    }

    let options = eframe::NativeOptions { android_app: Some(android), renderer: eframe::Renderer::Wgpu, ..Default::default() };
    let result = eframe::run_native(
        "MailCraft",
        options,
        Box::new(|cc| {
            let path = mailbox_path();
            let (mailbox, path) = open_mailbox(path);
            let mut session = Session::new(mailbox);
            session.path = path.clone();
            let mut services = Services {
                sync: Some(Box::new({
                    let ctx = cc.egui_ctx.clone();
                    move |request| sync_in_background(request, ctx.clone())
                })),
                ..Default::default()
            };
            if let Some(p) = &path {
                services.saver = background_saver(&cc.egui_ctx, p);
            }
            let mut app = MailApp::new(session, services);
            app.autosave = path.is_some();
            Ok(Box::new(MobileApp(app)))
        }),
    );
    if let Err(e) = result {
        log::error!("MailCraft stopped: {e}");
    }
}
