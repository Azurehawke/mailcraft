#!/usr/bin/env bash
# Build MailCraft for Android (arm64) as a signed APK: target/android-apk/mailcraft.apk.
#
# Needs: the Android SDK (ANDROID_HOME or ANDROID_SDK_ROOT, with build-tools and
# platforms;android-34), the NDK (ANDROID_NDK_HOME), `rustup target add aarch64-linux-android` and
# `cargo install cargo-ndk`. No Gradle and no Java: the app is a NativeActivity whose code is the
# library (apps/mailcraft-android), so aapt2 links the manifest and icon, the library goes into
# the archive, then zipalign and apksigner finish it. (The same recipe as WordCraft's port.)
#
# Signing: ANDROID_KEYSTORE (a path) with ANDROID_KEYSTORE_PASSWORD and ANDROID_KEY_ALIAS when
# set; otherwise the debug key next to this script (password "android"). Android only installs
# an update signed with the same key as the installed app.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/packaging/android"
OUT="$ROOT/target/android-apk"
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:?set ANDROID_HOME to the Android SDK}}
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the Android NDK}"

API=34       # targetSdk: 35 would force edge-to-edge drawing under the system bars.
MIN_API=30   # Android 11, the oldest the library is built for.
BUILD_TOOLS=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM="$SDK/platforms/android-$API/android.jar"
if [ ! -f "$PLATFORM" ]; then
    yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" "platforms;android-$API" >/dev/null
fi
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
VERSION_CODE=${VERSION_CODE:-1}

rm -rf "$OUT"
mkdir -p "$OUT/jniLibs" "$OUT/res/mipmap-xxxhdpi" "$OUT/apk/lib/arm64-v8a"

echo "== libmailcraft_android.so"
(cd "$ROOT" && cargo ndk -t arm64-v8a --platform "$MIN_API" -o "$OUT/jniLibs" build -p mailcraft-android --release)
test -f "$OUT/jniLibs/arm64-v8a/libmailcraft_android.so"

echo "== resources and manifest"
# The launcher icon: MailCraft's own app icon (assets/app-icon), as a legacy icon the launcher
# fits into its shape.
cp "$ROOT/assets/app-icon/hicolor/256x256/apps/io.github.billsecond.mailcraft.png" "$OUT/res/mipmap-xxxhdpi/ic_launcher.png"
"$BUILD_TOOLS/aapt2" compile --dir "$OUT/res" -o "$OUT/res.zip"
"$BUILD_TOOLS/aapt2" link -o "$OUT/unaligned.apk" -I "$PLATFORM" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version "$MIN_API" --target-sdk-version "$API" \
    --version-code "$VERSION_CODE" --version-name "$VERSION" \
    "$OUT/res.zip"

echo "== native library"
# Only MailCraft's library: cargo-ndk may also copy dependencies' own builds, which the app
# doesn't load.
cp "$OUT/jniLibs/arm64-v8a/libmailcraft_android.so" "$OUT/apk/lib/arm64-v8a/"
(cd "$OUT/apk" && zip -qr "$OUT/unaligned.apk" lib)

echo "== align and sign"
"$BUILD_TOOLS/zipalign" -p -f 4 "$OUT/unaligned.apk" "$OUT/aligned.apk"
KS=${ANDROID_KEYSTORE:-$HERE/debug.keystore}
KS_PASS=${ANDROID_KEYSTORE_PASSWORD:-android}
ALIAS=${ANDROID_KEY_ALIAS:-androiddebugkey}
"$BUILD_TOOLS/apksigner" sign --ks "$KS" --ks-key-alias "$ALIAS" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
    --out "$OUT/mailcraft.apk" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" verify "$OUT/mailcraft.apk"
ls -la "$OUT/mailcraft.apk"
