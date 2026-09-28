package com.trollhunters.trollchat;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Cliente Nostr mínimo: WebSocket crudo sobre SSLSocket (sin librerías),
 * un hilo por relay, reconexión con backoff, REQ de kind 4 y publicación.
 */
public class NostrClient {

    public interface Listener {
        void onDm(String senderPubkey, String text, String eventId);
        void onConnectionChange(boolean anyConnected);
    }

    private static final String TAG = "TrollChatNostr";

    private final String[] relays;
    private final String ownPrivHex;
    private final String ownPubHex;
    private final Listener listener;
    private final Set<String> seen = Collections.synchronizedSet(new HashSet<String>());
    private final List<RelayConn> conns = new ArrayList<>();
    private volatile boolean running = true;

    public NostrClient(String[] relays, String ownPrivHex, Listener listener) {
        this.relays = relays;
        this.ownPrivHex = ownPrivHex;
        this.ownPubHex = Secp256k1.pubkeyFromPriv(ownPrivHex);
        this.listener = listener;
    }

    public String ownPubkey() { return ownPubHex; }

    public void start() {
        for (String r : relays) {
            RelayConn c = new RelayConn(r);
            conns.add(c);
            c.start();
        }
    }

    public void stop() {
        running = false;
        for (RelayConn c : conns) c.shutdown();
    }

    /** Publica un DM (kind 4) a todos los relays conectados. */
    public void sendDm(final String toPubHex, final String text) {
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    NostrCrypto.SignedEvent ev = NostrCrypto.buildDm(ownPrivHex, toPubHex, text);
                    String msg = "[\"EVENT\"," + ev.sigJson + "]";
                    for (RelayConn c : conns) c.enqueue(msg);
                } catch (Exception e) {
                    Log.e(TAG, "sendDm falló", e);
                }
            }
        }).start();
    }

    private void updateConnState() {
        boolean any = false;
        for (RelayConn c : conns) if (c.connected) { any = true; break; }
        listener.onConnectionChange(any);
    }

    private void handleMessage(String raw) {
        try {
            JSONArray arr = new JSONArray(raw);
            String tipo = arr.optString(0, "");
            if ("EVENT".equals(tipo) && arr.length() >= 3) {
                JSONObject ev = arr.getJSONObject(2);
                if (ev.optInt("kind", -1) != 4) return;
                String id = ev.optString("id", "");
                if (id.isEmpty() || !seen.add(id)) return; // dedupe entre relays
                String sender = ev.optString("pubkey", "");
                boolean paraMi = false;
                JSONArray tags = ev.optJSONArray("tags");
                if (tags != null) {
                    for (int i = 0; i < tags.length(); i++) {
                        JSONArray t = tags.optJSONArray(i);
                        if (t != null && t.length() >= 2
                                && "p".equals(t.optString(0))
                                && ownPubHex.equals(t.optString(1))) {
                            paraMi = true;
                            break;
                        }
                    }
                }
                if (!paraMi) return;
                String text = NostrCrypto.nip04Decrypt(ownPrivHex, sender, ev.optString("content", ""));
                listener.onDm(sender, text, id);
            } else if ("NOTICE".equals(tipo)) {
                Log.w(TAG, "NOTICE: " + raw);
            } else if ("CLOSED".equals(tipo)) {
                Log.w(TAG, "CLOSED: " + raw);
            }
        } catch (Exception e) {
            Log.w(TAG, "mensaje no parseable: " + raw.substring(0, Math.min(80, raw.length())));
        }
    }

    private class RelayConn extends Thread {
        final String url;
        volatile boolean connected = false;
        volatile boolean dead = false;
        final BlockingQueue<String> outbox = new LinkedBlockingQueue<>();
        SSLSocket sock;

        RelayConn(String url) { this.url = url; setDaemon(true); }

        void enqueue(String m) { outbox.offer(m); }

        void shutdown() {
            dead = true;
            try { if (sock != null) sock.close(); } catch (Exception ignored) {}
            interrupt();
        }

        @Override public void run() {
            int backoff = 3;
            while (running && !dead) {
                try {
                    connect();
                    backoff = 3;
                    loop();
                } catch (Exception e) {
                    Log.w(TAG, url + " error: " + e);
                } finally {
                    if (connected) { connected = false; updateConnState(); }
                    closeQuiet();
                }
                if (!running || dead) break;
                try { Thread.sleep(backoff * 1000L); } catch (InterruptedException ie) { break; }
                backoff = Math.min(backoff * 2, 60);
            }
        }

        private void closeQuiet() {
            try { if (sock != null) sock.close(); } catch (Exception ignored) {}
            sock = null;
        }

        private void connect() throws Exception {
            URI u = new URI(url);
            String host = u.getHost();
            int port = u.getPort() > 0 ? u.getPort() : 443;
            String path = u.getPath();
            if (path == null || path.isEmpty()) path = "/";
            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            sock = (SSLSocket) f.createSocket(host, port);
            sock.setSoTimeout(45000);
            byte[] keyBytes = new byte[16];
            new SecureRandom().nextBytes(keyBytes);
            String key = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP);
            OutputStream os = sock.getOutputStream();
            String req = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: " + key + "\r\n"
                    + "Sec-WebSocket-Version: 13\r\n\r\n";
            os.write(req.getBytes(StandardCharsets.US_ASCII));
            os.flush();
            InputStream in = sock.getInputStream();
            String status = readHttpLine(in);
            if (status == null || !status.contains("101")) throw new Exception("handshake: " + status);
            String line;
            do { line = readHttpLine(in); } while (line != null && !line.isEmpty());
            connected = true;
            updateConnState();
            Log.i(TAG, url + " conectado");
            // Suscripción a DMs dirigidos a mí
            String sub = "[\"REQ\",\"tc\",{\"kinds\":[4],\"#p\":[\"" + ownPubHex + "\"]}]";
            sendText(sub);
            // Drenar outbox pendiente
            String m;
            while ((m = outbox.poll()) != null) sendText(m);
        }

        private void loop() throws Exception {
            InputStream in = sock.getInputStream();
            while (running && !dead && connected) {
                // Drenar outbox entre lecturas
                String m;
                while ((m = outbox.poll()) != null) sendText(m);
                String msg = readFrame(in);
                if (msg == null) throw new Exception("fin del stream");
                handleMessage(msg);
            }
        }

        private synchronized void sendText(String text) throws Exception {
            if (sock == null || sock.isClosed()) { outbox.offer(text); return; }
            byte[] payload = text.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream f = new ByteArrayOutputStream();
            f.write(0x81); // FIN + text
            int len = payload.length;
            byte maskBit = (byte) 0x80;
            if (len < 126) {
                f.write(maskBit | len);
            } else if (len < 65536) {
                f.write(maskBit | 126);
                f.write((len >> 8) & 0xFF); f.write(len & 0xFF);
            } else {
                f.write(maskBit | 127);
                for (int i = 7; i >= 0; i--) f.write((len >> (8 * i)) & 0xFF);
            }
            byte[] mask = new byte[4];
            new SecureRandom().nextBytes(mask);
            f.write(mask);
            for (int i = 0; i < len; i++) f.write(payload[i] ^ mask[i % 4]);
            OutputStream os = sock.getOutputStream();
            os.write(f.toByteArray());
            os.flush();
        }

        private String readHttpLine(InputStream in) throws Exception {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int prev = -1, ch;
            while ((ch = in.read()) != -1) {
                if (prev == '\r' && ch == '\n') break;
                if (prev != -1) b.write(prev);
                prev = ch;
            }
            return new String(b.toByteArray(), StandardCharsets.US_ASCII);
        }

        /** Lee un frame; responde pong a ping; devuelve texto o null si no es texto. */
        private String readFrame(InputStream in) throws Exception {
            int b1 = in.read();
            if (b1 == -1) return null;
            int b2 = in.read();
            if (b2 == -1) return null;
            int opcode = b1 & 0x0F;
            boolean masked = (b2 & 0x80) != 0;
            long len = b2 & 0x7F;
            if (len == 126) len = (in.read() << 8) | in.read();
            else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | (in.read() & 0xFF);
            }
            byte[] mask = null;
            if (masked) {
                mask = new byte[4];
                readFully(in, mask, 4);
            }
            if (len > 4 * 1024 * 1024) throw new Exception("frame muy grande");
            byte[] payload = new byte[(int) len];
            readFully(in, payload, (int) len);
            if (masked && mask != null)
                for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
            if (opcode == 0x9) { // ping -> pong
                sendPong(payload);
                return readFrame(in);
            }
            if (opcode == 0x8) throw new Exception("close del relay");
            if (opcode == 0x1 || opcode == 0x0)
                return new String(payload, StandardCharsets.UTF_8);
            return readFrame(in); // ignora otros
        }

        private void readFully(InputStream in, byte[] b, int n) throws Exception {
            int off = 0;
            while (off < n) {
                int r = in.read(b, off, n - off);
                if (r == -1) throw new Exception("EOF en frame");
                off += r;
            }
        }

        private synchronized void sendPong(byte[] payload) throws Exception {
            ByteArrayOutputStream f = new ByteArrayOutputStream();
            f.write(0x8A);
            f.write(0x80 | payload.length);
            byte[] mask = new byte[4];
            new SecureRandom().nextBytes(mask);
            f.write(mask);
            for (int i = 0; i < payload.length; i++) f.write(payload[i] ^ mask[i % 4]);
            sock.getOutputStream().write(f.toByteArray());
            sock.getOutputStream().flush();
        }
    }
}
