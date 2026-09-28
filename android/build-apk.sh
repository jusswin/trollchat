#!/bin/bash
# Builds TrollChat.apk without Gradle (aapt2 + d8 + apksigner).
#
# Prerequisites (set as env vars or edit below):
#   ANDROID_SDK_ROOT  -> Android SDK (needs build-tools 34.0.0 and android-34 platform)
#   JAVA_HOME         -> JDK 17+
#
# Optional: ANDROID_KEYSTORE -> keystore for signing (default: ~/.android/debug.keystore)
set -e
: "${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT to your Android SDK path}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK 17+ path}"
export PATH="$JAVA_HOME/bin:$PATH"

BT="$ANDROID_SDK_ROOT/build-tools/34.0.0"
AJAR="$ANDROID_SDK_ROOT/platforms/android-34/android.jar"
KEYSTORE="${ANDROID_KEYSTORE:-$HOME/.android/debug.keystore}"

P="$(cd "$(dirname "$0")" && pwd)"
B="$P/build"
rm -rf "$B"; mkdir -p "$B/gen" "$B/classes" "$B/dex" "$B/src"
cd "$P"

cp app/src/main/java/com/trollhunters/trollchat/*.java "$B/src/"

"$BT/aapt2" compile --dir app/src/main/res -o "$B/res.zip"
"$BT/aapt2" link -o "$B/app-unsigned.apk" -I "$AJAR" \
  --manifest app/src/main/AndroidManifest.xml \
  --min-sdk-version 21 --target-sdk-version 34 \
  --version-code 3 --version-name 3.0-nostr \
  --java "$B/gen" "$B/res.zip"

javac -encoding UTF-8 -source 8 -target 8 -bootclasspath "$AJAR" \
  -cp "$AJAR" -d "$B/classes" \
  $(find "$B/gen" -name "R.java") "$B/src"/*.java

"$BT/d8" --lib "$AJAR" --min-api 21 --output "$B/dex" $(find "$B/classes" -name "*.class")
cp "$B/dex/classes.dex" "$B/classes.dex"
(cd "$B" && "$BT/aapt" add -f "$B/app-unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$B/app-unsigned.apk" "$B/app-aligned.apk"

if [ ! -f "$KEYSTORE" ]; then
  echo "Generating debug keystore at $KEYSTORE ..."
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -keystore "$KEYSTORE" -alias androiddebugkey \
    -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US"
fi

"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
  --out "$B/TrollChat.apk" "$B/app-aligned.apk"
"$BT/apksigner" verify "$B/TrollChat.apk"
echo "APK ready: $B/TrollChat.apk"
