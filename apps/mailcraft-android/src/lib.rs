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
//! - TLS certificates are checked against Mozilla's public roots bundled in the app, not Android's
//!   own store (see `mailcraft-net`'s `tls`): that store refused the Let's Encrypt chains here.
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
use mailcraft_net::update::AndroidBuild;
use std::sync::Arc;

mod pictures;
mod secrets;
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

/// The window's app: the desktop's `MailApp`, driven as the desktop's `App` drives it.
struct MobileApp {
    app: MailApp,
    android: AndroidApp,
    /// The status bar's height in physical pixels, as Android lays it out (0 if not known).
    status_bar_px: i32,
    /// The system bars' insets last applied, in points.
    insets: egui::epaint::MarginF32,
    /// The answer to this launch's check, until it comes.
    build_check: Option<Receiver<Option<AndroidBuild>>>,
    /// A newer build that the check found.
    newer: Option<AndroidBuild>,
}

/// This APK's build number, from the workflow's run number when it was built (`0` otherwise).
fn this_build() -> u64 {
    option_env!("MAILCRAFT_ANDROID_BUILD").and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// Asks, on a thread of its own, whether a newer build is published; the answer comes back on
/// the channel, `None` when there is none or the question failed.
fn check_for_build(build: u64) -> Receiver<Option<AndroidBuild>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let found = mailcraft_net::update::newer_android_build(build).ok().flatten();
        // The window may have closed by now; nobody is then waiting for the answer.
        let _ = tx.send(found);
    });
    rx
}

/// Opens `url` in the system's browser (an intent to view it), from the activity.
#[allow(unsafe_code)] // The JavaVM and activity pointers android-activity gives, valid while the app runs.
fn open_page(android: &AndroidApp, url: &str) -> Result<(), String> {
    let vm_ptr = android.vm_as_ptr() as *mut jni::sys::JavaVM;
    let activity_ptr = android.activity_as_ptr() as jni::sys::jobject;
    if vm_ptr.is_null() || activity_ptr.is_null() {
        return Err("the activity isn't there".to_string());
    }
    // SAFETY: both pointers come from android-activity and stay valid for as long as the app runs.
    let vm = unsafe { jni::JavaVM::from_raw(vm_ptr) };
    vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        // SAFETY: the activity is a live local reference for this call, on this thread.
        let activity = unsafe { jni::objects::JObject::from_raw(env, activity_ptr) };
        let text = env.new_string(url)?;
        let uri_class = env.find_class(jni::jni_str!("android/net/Uri"))?;
        let uri = env
            .call_static_method(
                &uri_class,
                jni::jni_str!("parse"),
                jni::jni_sig!((java.lang.String) -> android.net.Uri),
                &[jni::objects::JValue::Object(&text)],
            )?
            .l()?;
        let action = env.new_string("android.intent.action.VIEW")?;
        let intent_class = env.find_class(jni::jni_str!("android/content/Intent"))?;
        let intent = env.new_object(
            &intent_class,
            jni::jni_sig!((java.lang.String, android.net.Uri) -> void),
            &[jni::objects::JValue::Object(&action), jni::objects::JValue::Object(&uri)],
        )?;
        env.call_method(
            &activity,
            jni::jni_str!("startActivity"),
            jni::jni_sig!((android.content.Intent) -> void),
            &[jni::objects::JValue::Object(&intent)],
        )?;
        Ok(())
    })
    .map_err(|e| format!("{e}"))
}

/// The status bar's height in physical pixels, asked of Android's own resources (the
/// `status_bar_height` dimension). Android 16 on One UI draws the app under the bar, and the
/// content rect doesn't shrink, so the height is the one thing that says where the bar ends.
#[allow(unsafe_code)] // The JavaVM and activity pointers android-activity gives, valid while the app runs.
fn status_bar_height_px(android: &AndroidApp) -> i32 {
    let vm_ptr = android.vm_as_ptr() as *mut jni::sys::JavaVM;
    let activity_ptr = android.activity_as_ptr() as jni::sys::jobject;
    if vm_ptr.is_null() || activity_ptr.is_null() {
        return 0;
    }
    // SAFETY: both pointers come from android-activity and stay valid for as long as the app runs.
    let vm = unsafe { jni::JavaVM::from_raw(vm_ptr) };
    vm.attach_current_thread(|env| -> jni::errors::Result<i32> {
        // SAFETY: the activity is a live local reference for this call, on this thread.
        let activity = unsafe { jni::objects::JObject::from_raw(env, activity_ptr) };
        let resources = env.call_method(&activity, jni::jni_str!("getResources"), jni::jni_sig!(() -> android.content.res.Resources), &[])?.l()?;
        let name = env.new_string("status_bar_height")?;
        let kind = env.new_string("dimen")?;
        let package = env.new_string("android")?;
        let id = env
            .call_method(
                &resources,
                jni::jni_str!("getIdentifier"),
                jni::jni_sig!((java.lang.String, java.lang.String, java.lang.String) -> int),
                &[jni::objects::JValue::Object(&name), jni::objects::JValue::Object(&kind), jni::objects::JValue::Object(&package)],
            )?
            .i()?;
        if id == 0 {
            return Ok(0);
        }
        env.call_method(&resources, jni::jni_str!("getDimensionPixelSize"), jni::jni_sig!((int) -> int), &[jni::objects::JValue::Int(id)])?.i()
    })
    .unwrap_or(0)
    .max(0)
}

impl MobileApp {
    /// The window's edges covered by system bars, in points. The sides come from Android's
    /// content rect (the part of the window the bars leave free). The top is at least the status
    /// bar's height, since the content rect can still start at the top of the screen.
    fn system_bar_insets(&self, ctx: &egui::Context, raw: &egui::RawInput) -> Option<egui::epaint::MarginF32> {
        let ppp = ctx.pixels_per_point();
        let screen = raw.screen_rect?;
        if !(ppp.is_finite() && ppp > 0.0) {
            return None;
        }
        let (w, h) = (screen.width() * ppp, screen.height() * ppp);
        let inset = |px: f32| (px / ppp).clamp(0.0, 400.0);
        let r = self.android.content_rect();
        let (left, top, right, bottom) = if r.right > r.left && r.bottom > r.top {
            (inset(r.left as f32), inset(r.top as f32), inset(w - r.right as f32), inset(h - r.bottom as f32))
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };
        Some(egui::epaint::MarginF32 { left, top: top.max(inset(self.status_bar_px as f32)), right, bottom })
    }
}

impl eframe::App for MobileApp {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        if let Some(insets) = self.system_bar_insets(ctx, raw) {
            if insets != self.insets {
                log::info!("system bar insets (points): {insets:?}");
            }
            self.insets = insets;
            raw.safe_area_insets = Some(egui::SafeAreaInsets(insets));
        }
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.app.logic(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.build_check {
            match rx.try_recv() {
                Ok(found) => {
                    self.newer = found;
                    self.build_check = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.build_check = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        // The window's whole layout goes inside the area the system bars leave free. egui's own
        // safe area isn't relied on: Android 16 draws under the bars and the root layout ignores it.
        let i = self.insets;
        let mut rect = ui.max_rect();
        rect.min.x += i.left;
        rect.min.y += i.top;
        rect.max.x -= i.right;
        rect.max.y -= i.bottom;
        if let Some(newer) = self.newer.clone() {
            // A strip across the top says a newer build is out, and opens its page.
            let strip = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), 48.0));
            rect.min.y += 48.0;
            let android = &self.android;
            ui.scope_builder(egui::UiBuilder::new().max_rect(strip), |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(format!("A newer MailCraft for Android is out (build {}).", newer.number));
                    if ui.button("Open the download page").clicked() {
                        if let Err(e) = open_page(android, &newer.page) {
                            log::error!("the download page didn't open: {e}");
                        }
                    }
                });
            });
        }
        if rect.is_positive() {
            ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| self.app.ui(ui));
        } else {
            self.app.ui(ui);
        }
    }

    fn on_exit(&mut self) {
        // A window closed while its mailbox was still opening has nothing to save.
        if self.app.is_opening() {
            return;
        }
        if let Err(e) = self.app.save_on_exit() {
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

    // The window reads the system bars' insets from this handle, every frame.
    let for_insets = android.clone();
    let for_secrets = android.clone();
    let secrets_dir = android.internal_data_path().map(|dir| dir.join("secrets"));
    let pictures_dir = android.internal_data_path().map(|dir| dir.join("pictures"));
    let options = eframe::NativeOptions { android_app: Some(android), renderer: eframe::Renderer::Wgpu, ..Default::default() };
    let result = eframe::run_native(
        "MailCraft",
        options,
        Box::new(move |cc| {
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
            // Remembered sign-ins are sealed with the Keystore, in the app's own folder.
            // Pictures a message's owner asked for come from the web, and are kept in the app's folder.
            if let Some(dir) = &pictures_dir {
                let cache = Arc::new(pictures::Pictures::new(dir.clone()));
                let ctx = cc.egui_ctx.clone();
                services.pictures = Some(Box::new({
                    let cache = cache.clone();
                    move |url| pictures::download(cache.clone(), url, ctx.clone())
                }));
                services.picture_cache = Some(Box::new(pictures::Kept(cache)));
            }
            if let Some(dir) = &secrets_dir {
                services.secrets = Some(Arc::new(secrets::AndroidSecrets::new(for_secrets.clone(), dir.clone())));
            }
            let mut app = MailApp::new(session, services);
            app.autosave = path.is_some();
            let status_bar_px = status_bar_height_px(&for_insets);
            log::info!("status bar height (pixels): {status_bar_px}");
            // Every launch asks whether a newer build is out, unless this build was made by hand.
            let build = this_build();
            let build_check = (build > 0).then(|| check_for_build(build));
            Ok(Box::new(MobileApp { app, android: for_insets, status_bar_px, insets: egui::epaint::MarginF32::default(), build_check, newer: None }))
        }),
    );
    if let Err(e) = result {
        log::error!("MailCraft stopped: {e}");
    }
}
