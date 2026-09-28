package com.trollhunters.trollchat;

import android.util.Base64;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * NIP-04 (DM cifrado) + construcción y firma de eventos Nostr.
 * El id se calcula sobre [0,"pubkey",created_at,kind,tags,content]
 * (OJO: el primer elemento es el NÚMERO 0, no el string "0").
 */
public class NostrCrypto {

    public static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    /** NIP-04: base64(ct) + "?iv=" + base64(iv), AES-256-CBC con clave=SHA256(ECDH). */
    public static String nip04Encrypt(String privHex, String pubHex, String text) throws Exception {
        byte[] key = Secp256k1.ecdh(privHex, pubHex);
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(text.getBytes("UTF-8"));
        return Base64.encodeToString(ct, Base64.NO_WRAP)
                + "?iv=" + Base64.encodeToString(iv, Base64.NO_WRAP);
    }

    public static String nip04Decrypt(String privHex, String pubHex, String payload) throws Exception {
        byte[] key = Secp256k1.ecdh(privHex, pubHex);
        int i = payload.indexOf("?iv=");
        if (i < 0) throw new IllegalArgumentException("NIP-04 sin iv");
        byte[] ct = Base64.decode(payload.substring(0, i), Base64.NO_WRAP);
        byte[] iv = Base64.decode(payload.substring(i + 4), Base64.NO_WRAP);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return new String(c.doFinal(ct), "UTF-8");
    }

    /** Escapa un string para JSON (comillas, backslash, controles). */
    public static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.toString();
    }

    /** Serializa tags [["p","..."]] a JSON canónico. */
    public static String tagsJson(String[][] tags) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < tags.length; i++) {
            if (i > 0) sb.append(",");
            sb.append("[");
            for (int j = 0; j < tags[i].length; j++) {
                if (j > 0) sb.append(",");
                sb.append("\"").append(jsonEscape(tags[i][j])).append("\"");
            }
            sb.append("]");
        }
        return sb.append("]").toString();
    }

    public static class SignedEvent {
        public final String id, pubkey, content, sigJson;
        public SignedEvent(String id, String pubkey, String content, String sigJson) {
            this.id = id; this.pubkey = pubkey; this.content = content; this.sigJson = sigJson;
        }
    }

    /** Construye y firma un evento kind 4 (DM). Devuelve el objeto listo para ["EVENT",{...}]. */
    public static SignedEvent buildDm(String privHex, String toPubHex, String plainText) throws Exception {
        String pubkey = Secp256k1.pubkeyFromPriv(privHex);
        String content = nip04Encrypt(privHex, toPubHex, plainText);
        long createdAt = System.currentTimeMillis() / 1000L;
        String tags = tagsJson(new String[][]{new String[]{"p", toPubHex}});
        // Canónico NIP-01: [0,"pubkey",created_at,kind,tags,content]
        String preimage = "[0,\"" + pubkey + "\"," + createdAt + ",4," + tags
                + ",\"" + jsonEscape(content) + "\"]";
        byte[] idBytes = sha256(preimage.getBytes("UTF-8"));
        String id = Secp256k1.bytesToHex(idBytes);
        byte[] sig = Secp256k1.schnorrSign(Secp256k1.hexToBytes(privHex), idBytes);
        String sigHex = Secp256k1.bytesToHex(sig);
        String eventJson = "{\"id\":\"" + id + "\",\"pubkey\":\"" + pubkey
                + "\",\"created_at\":" + createdAt + ",\"kind\":4,\"tags\":" + tags
                + ",\"content\":\"" + jsonEscape(content) + "\",\"sig\":\"" + sigHex + "\"}";
        return new SignedEvent(id, pubkey, content, eventJson);
    }
}
