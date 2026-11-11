// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pictures from the web, for mail whose owner asked for them. Each is fetched by
//! `mailcraft_net::pictures::fetch` (no cookies or referrer, public hosts only, and only a PNG,
//! JPEG, GIF or WebP comes back), on a thread of its own, and kept in the app's folder under the
//! SHA-256 of its address, so that it is not asked for again.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

use sha2::{Digest, Sha256};

/// The downloaded pictures of this device, one file each in a folder of the app's own.
pub struct Pictures {
    dir: PathBuf,
}

impl Pictures {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The file for `url`: the SHA-256 of the address, in hex, so no address is in a file name.
    fn file(&self, url: &str) -> PathBuf {
        let digest = Sha256::digest(url.as_bytes());
        let name: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(name)
    }

    fn get(&self, url: &str) -> Option<Vec<u8>> {
        std::fs::read(self.file(url)).ok()
    }

    /// Keeps `bytes` for `url`. A failure only means the picture is asked for again next time.
    fn put(&self, url: &str, bytes: &[u8]) {
        let path = self.file(url);
        let result = std::fs::create_dir_all(&self.dir).and_then(|()| {
            // Written beside the file, then renamed over it, so a cut-off write leaves no half picture.
            let temp = path.with_extension("tmp");
            std::fs::write(&temp, bytes)?;
            std::fs::rename(&temp, &path)
        });
        if let Err(e) = result {
            log::warn!("a downloaded picture wasn't kept: {e}");
        }
    }

    /// Each kept file, with its size, when the folder can be read.
    fn files(&self) -> impl Iterator<Item = (PathBuf, u64)> {
        std::fs::read_dir(&self.dir).into_iter().flatten().flatten().filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            meta.is_file().then(|| (entry.path(), meta.len()))
        })
    }
}

/// The cache as the window knows it: the same folder, with what it needs to count and clear it.
pub struct Kept(pub Arc<Pictures>);

impl mailcraft_ui_egui::PictureCache for Kept {
    fn usage(&self) -> (usize, u64) {
        self.0.files().fold((0, 0), |(count, bytes), (_, len)| (count + 1, bytes + len))
    }

    fn forget(&self, url: &str) {
        let _ = std::fs::remove_file(self.0.file(url));
    }

    fn clear(&self) -> Result<(), String> {
        for (path, _) in self.0.files() {
            std::fs::remove_file(&path).map_err(|e| format!("{e}"))?;
        }
        Ok(())
    }
}

/// Downloads the picture at `url`, or takes it from `cache` when it is kept there. The answer
/// comes back on the channel, and the window is woken to show it.
pub fn download(cache: Arc<Pictures>, url: String, ctx: egui::Context) -> Receiver<Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = match cache.get(&url) {
            Some(bytes) => Ok(bytes),
            None => mailcraft_net::pictures::fetch(&url).map_err(|e| format!("{e}")).inspect(|bytes| cache.put(&url, bytes)),
        };
        // Nobody may be waiting any more; the window then simply doesn't show it.
        let _ = tx.send(result);
        ctx.request_repaint();
    });
    rx
}
