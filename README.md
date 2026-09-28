# TrollChat

A lightweight text chat between an Android TV box and an operator, with **no
PC in the middle** and **no accounts or servers of its own**. Messages travel
as encrypted Nostr DMs (NIP-04) over public relays.

```
Android TV app (com.trollhunters.trollchat)
   ↕  wss directly to public relays (no accounts, no own server)
   ├─ wss://relay.damus.io
   ├─ wss://relay.primal.net
   └─ wss://relay.snort.social
   ↕  NIP-04 encrypted DMs (kind 4), AES-256-CBC, key = SHA256(ECDH)
Operator side: nostr-poller.py (this repo)
```

- The app generates its own keypair on first launch (stored in
  `SharedPreferences`).
- DMs from the TV are encrypted to the **operator pubkey** (set
  `OPERATOR_PUB` in `MainActivity.java` before building).
- The operator replies with DMs encrypted to the TV's pubkey.
- Relays only ever see ciphertext — nobody else can read the content.

## What's here

| Path | What |
|---|---|
| `android/app/src/main/java/com/trollhunters/trollchat/` | App source: `MainActivity` (big-text, D-pad friendly UI), `NostrClient` (raw WebSocket over `SSLSocket`, no dependencies), `NostrCrypto` (BIP-340 Schnorr + NIP-04), `Secp256k1` (pure-Java curve math) |
| `android/app/src/main/AndroidManifest.xml` | Manifest with `LAUNCHER` + `LEANBACK_LAUNCHER` (shows up on Android TV launchers) |
| `android/build-apk.sh` | Builds the APK without Gradle (`aapt2` + `d8` + `apksigner`) |
| `nostr-poller.py` | Operator-side poller: receives DMs into `inbox.log`, sends via `send <pubkey> "<msg>"` |

## Quick start

### 1. Generate an operator keypair

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Save the 64-hex private key somewhere safe (permission 600). The public key is
derived from it.

### 2. Build the Android app

1. Put your operator **public** key in `MainActivity.java` (`OPERATOR_PUB`).
2. Install the Android SDK (build-tools 34.0.0, android-34 platform) and JDK 17.
3. Run:

```bash
export ANDROID_SDK_ROOT=/path/to/android-sdk
export JAVA_HOME=/path/to/jdk-17
./android/build-apk.sh
```

The APK lands in `android/build/TrollChat.apk`. Install it on the TV
(`adb install`) — it's leanback-launchable.

### 3. Run the operator poller

```bash
pip install websocket-client ecdsa pycryptodome
export TROLLCHAT_OPERATOR_PRIV=<your-64-hex-private-key>
./nostr-poller.py            # listen: DMs arrive in inbox.log
./nostr-poller.py send <tv_pubkey_hex> "Hello TV"
```

Behind a proxy? Set `HTTPS_PROXY` (and `SSL_CERT_FILE` if you need a custom CA
bundle) — the poller picks them up automatically.

## Design notes

- **No relay server to run**: public Nostr relays do the transport; encryption
  (NIP-04) provides the privacy.
- **Zero-dependency Android client**: the APK implements its own secp256k1,
  Schnorr signing and WebSocket framing so it runs on old Android TV boxes
  (minSdk 21) without a heavy crypto library.
- **Poller is dependency-light too**: `ecdsa` + `pycryptodome` only.

## License

MIT — see [LICENSE](LICENSE).
