// SPDX-FileCopyrightText: MailCraft contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Remembered sign-ins on Android. Each secret is encrypted with AES-GCM under a key that lives
//! in the Android Keystore, which keeps the key in the device's secure hardware where it has
//! some. Only the encrypted copy is written, one file per key in a folder of the app's own, named
//! by the SHA-256 of the key so that no account address appears in a file name. The key never
//! leaves the Keystore, and the secret never reaches a file in plain text.

use std::path::PathBuf;
use std::sync::Mutex;

use jni::objects::{JByteArray, JObject, JValue};
use jni::{Env, JavaVM, jni_sig, jni_str};
use mailcraft_ui_egui::{SecretStore, StoreTrouble};
use sha2::{Digest, Sha256};
use winit::platform::android::activity::AndroidApp;

/// The Keystore's name for the key that seals every secret.
const ALIAS: &str = "mailcraft.secrets";
/// `KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT`.
const PURPOSE_ENCRYPT_DECRYPT: i32 = 3;
/// `Cipher.ENCRYPT_MODE` and `Cipher.DECRYPT_MODE`.
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
/// The authentication tag's length in bits.
const TAG_BITS: i32 = 128;

/// The secrets of this device, sealed with the Keystore, in the folder given.
pub struct AndroidSecrets {
    android: AndroidApp,
    dir: PathBuf,
    /// Why the store couldn't be used the last time, until someone takes the word.
    trouble: Mutex<Option<StoreTrouble>>,
}

impl AndroidSecrets {
    pub fn new(android: AndroidApp, dir: PathBuf) -> Self {
        Self { android, dir, trouble: Mutex::new(None) }
    }

    /// The file that holds the secret for `key`: the SHA-256 of the key, in hex.
    fn file(&self, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        let name: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(name)
    }

    fn trouble(&self, t: StoreTrouble) {
        if let Ok(mut word) = self.trouble.lock() {
            *word = Some(t);
        }
    }
}

impl SecretStore for AndroidSecrets {
    fn get(&self, key: &str) -> Option<String> {
        // Nothing kept under the key is not trouble: only a store that can't be used is.
        let sealed = std::fs::read(self.file(key)).ok()?;
        let (iv, body) = split(&sealed)?;
        match with_env(&self.android, |env| open(env, iv, body)) {
            Ok(plain) => String::from_utf8(plain).ok(),
            Err(e) => {
                log::error!("a remembered sign-in couldn't be read: {e}");
                self.trouble(StoreTrouble::Unavailable);
                None
            }
        }
    }

    fn set(&self, key: &str, secret: &str) -> Result<(), String> {
        let sealed = with_env(&self.android, |env| seal(env, secret.as_bytes())).inspect_err(|_| self.trouble(StoreTrouble::Unavailable))?;
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{e}"))?;
        let path = self.file(key);
        // Written beside the file, then renamed over it, so a cut-off write never leaves half a secret.
        let temp = path.with_extension("tmp");
        std::fs::write(&temp, &sealed).map_err(|e| format!("{e}"))?;
        std::fs::rename(&temp, &path).map_err(|e| format!("{e}"))
    }

    fn delete(&self, key: &str) {
        let _ = std::fs::remove_file(self.file(key));
    }

    fn take_trouble(&self) -> Option<StoreTrouble> {
        self.trouble.lock().ok()?.take()
    }
}

/// Runs `f` with the JNI environment of this thread, attached to the Java VM.
#[allow(unsafe_code)] // The JavaVM pointer android-activity gives, valid while the app runs.
fn with_env<T>(android: &AndroidApp, f: impl FnOnce(&mut Env<'_>) -> jni::errors::Result<T>) -> Result<T, String> {
    let vm_ptr = android.vm_as_ptr() as *mut jni::sys::JavaVM;
    if vm_ptr.is_null() {
        return Err("the Java VM isn't there".to_string());
    }
    // SAFETY: the pointer comes from android-activity and stays valid for as long as the app runs.
    let vm = unsafe { JavaVM::from_raw(vm_ptr) };
    vm.attach_current_thread(f).map_err(|e| format!("{e}"))
}

/// The Keystore's key that seals the secrets, made on first use.
fn sealing_key<'l>(env: &mut Env<'l>) -> jni::errors::Result<JObject<'l>> {
    let provider = env.new_string("AndroidKeyStore")?;
    let store_class = env.find_class(jni_str!("java/security/KeyStore"))?;
    let store = env
        .call_static_method(
            &store_class,
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljava/security/KeyStore;"),
            &[JValue::Object(&provider)],
        )?
        .l()?;
    env.call_method(&store, jni_str!("load"), jni_sig!("(Ljava/security/KeyStore$LoadStoreParameter;)V"), &[JValue::Object(&JObject::null())])?;
    let alias = env.new_string(ALIAS)?;
    let present = env.call_method(&store, jni_str!("containsAlias"), jni_sig!("(Ljava/lang/String;)Z"), &[JValue::Object(&alias)])?.z()?;
    if !present {
        make_key(env, &alias)?;
    }
    env.call_method(
        &store,
        jni_str!("getKey"),
        jni_sig!("(Ljava/lang/String;[C)Ljava/security/Key;"),
        &[JValue::Object(&alias), JValue::Object(&JObject::null())],
    )?
    .l()
}

/// Makes the AES key in the Keystore: encrypt and decrypt, GCM, no padding.
fn make_key(env: &mut Env<'_>, alias: &JObject<'_>) -> jni::errors::Result<()> {
    let algorithm = env.new_string("AES")?;
    let provider = env.new_string("AndroidKeyStore")?;
    let generator_class = env.find_class(jni_str!("javax/crypto/KeyGenerator"))?;
    let generator = env
        .call_static_method(
            &generator_class,
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;"),
            &[JValue::Object(&algorithm), JValue::Object(&provider)],
        )?
        .l()?;
    let builder_class = env.find_class(jni_str!("android/security/keystore/KeyGenParameterSpec$Builder"))?;
    let builder =
        env.new_object(&builder_class, jni_sig!("(Ljava/lang/String;I)V"), &[JValue::Object(alias), JValue::Int(PURPOSE_ENCRYPT_DECRYPT)])?;
    let gcm = one_string(env, "GCM")?;
    let builder = env
        .call_method(
            &builder,
            jni_str!("setBlockModes"),
            jni_sig!("([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
            &[JValue::Object(&gcm)],
        )?
        .l()?;
    let none = one_string(env, "NoPadding")?;
    let builder = env
        .call_method(
            &builder,
            jni_str!("setEncryptionPaddings"),
            jni_sig!("([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;"),
            &[JValue::Object(&none)],
        )?
        .l()?;
    let spec = env.call_method(&builder, jni_str!("build"), jni_sig!("()Landroid/security/keystore/KeyGenParameterSpec;"), &[])?.l()?;
    env.call_method(&generator, jni_str!("init"), jni_sig!("(Ljava/security/spec/AlgorithmParameterSpec;)V"), &[JValue::Object(&spec)])?;
    env.call_method(&generator, jni_str!("generateKey"), jni_sig!("()Ljavax/crypto/SecretKey;"), &[])?;
    Ok(())
}

/// A Java array of one string.
fn one_string<'l>(env: &mut Env<'l>, text: &str) -> jni::errors::Result<JObject<'l>> {
    let array = env.new_object_array(1, jni_str!("java/lang/String"), JObject::null())?;
    let value = env.new_string(text)?;
    array.set_element(env, 0, &value)?;
    Ok(array.into())
}

/// Seals `plain`: one byte giving the IV's length, the IV, then the encrypted bytes with their tag.
fn seal(env: &mut Env<'_>, plain: &[u8]) -> jni::errors::Result<Vec<u8>> {
    let key = sealing_key(env)?;
    let transform = env.new_string("AES/GCM/NoPadding")?;
    let cipher_class = env.find_class(jni_str!("javax/crypto/Cipher"))?;
    let cipher = env
        .call_static_method(
            &cipher_class,
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
            &[JValue::Object(&transform)],
        )?
        .l()?;
    env.call_method(&cipher, jni_str!("init"), jni_sig!("(ILjava/security/Key;)V"), &[JValue::Int(ENCRYPT_MODE), JValue::Object(&key)])?;
    let iv_obj = env.call_method(&cipher, jni_str!("getIV"), jni_sig!("()[B"), &[])?.l()?;
    let iv = JByteArray::cast_local(env, iv_obj)?;
    let iv = env.convert_byte_array(&iv)?;
    let data = env.byte_array_from_slice(plain)?;
    let sealed_obj = env.call_method(&cipher, jni_str!("doFinal"), jni_sig!("([B)[B"), &[JValue::Object(&data)])?.l()?;
    let sealed = JByteArray::cast_local(env, sealed_obj)?;
    let sealed = env.convert_byte_array(&sealed)?;
    let mut out = Vec::with_capacity(1 + iv.len() + sealed.len());
    out.push(u8::try_from(iv.len()).unwrap_or(0));
    out.extend_from_slice(&iv);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Splits what [`seal`] made into its IV and its encrypted bytes; `None` when it is too short.
fn split(sealed: &[u8]) -> Option<(&[u8], &[u8])> {
    let iv_len = usize::from(*sealed.first()?);
    let iv = sealed.get(1..1 + iv_len)?;
    let body = sealed.get(1 + iv_len..)?;
    Some((iv, body))
}

/// Opens the encrypted bytes `body` with the IV `iv` that [`seal`] wrote beside them.
fn open(env: &mut Env<'_>, iv: &[u8], body: &[u8]) -> jni::errors::Result<Vec<u8>> {
    let key = sealing_key(env)?;
    let transform = env.new_string("AES/GCM/NoPadding")?;
    let cipher_class = env.find_class(jni_str!("javax/crypto/Cipher"))?;
    let cipher = env
        .call_static_method(
            &cipher_class,
            jni_str!("getInstance"),
            jni_sig!("(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
            &[JValue::Object(&transform)],
        )?
        .l()?;
    let iv_array = env.byte_array_from_slice(iv)?;
    let spec_class = env.find_class(jni_str!("javax/crypto/spec/GCMParameterSpec"))?;
    let spec = env.new_object(&spec_class, jni_sig!("(I[B)V"), &[JValue::Int(TAG_BITS), JValue::Object(&iv_array)])?;
    env.call_method(
        &cipher,
        jni_str!("init"),
        jni_sig!("(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"),
        &[JValue::Int(DECRYPT_MODE), JValue::Object(&key), JValue::Object(&spec)],
    )?;
    let data = env.byte_array_from_slice(body)?;
    let plain_obj = env.call_method(&cipher, jni_str!("doFinal"), jni_sig!("([B)[B"), &[JValue::Object(&data)])?.l()?;
    let plain = JByteArray::cast_local(env, plain_obj)?;
    env.convert_byte_array(&plain)
}
