package com.trollhunters.trollchat;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * secp256k1 puro en Java (sin dependencias): aritmética de campo,
 * multiplicación de puntos, ECDH y firmas Schnorr BIP-340.
 * Verificado contra libsecp256k1 (firma) y vectores ECDH del lado Python.
 */
public class Secp256k1 {

    public static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger GX = new BigInteger(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GY = new BigInteger(
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    public static class Point {
        public final BigInteger x, y; // null,null = infinito
        public Point(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
        public boolean isInfinity() { return x == null; }
    }

    public static final Point G = new Point(GX, GY);
    private static final Point INF = new Point(null, null);

    private static Point add(Point a, Point b) {
        if (a.isInfinity()) return b;
        if (b.isInfinity()) return a;
        if (a.x.equals(b.x)) {
            if (!a.y.equals(b.y)) return INF;
            return dbl(a);
        }
        BigInteger lam = b.y.subtract(a.y)
                .multiply(b.x.subtract(a.x).modInverse(P)).mod(P);
        BigInteger xr = lam.multiply(lam).subtract(a.x).subtract(b.x).mod(P);
        BigInteger yr = lam.multiply(a.x.subtract(xr)).subtract(a.y).mod(P);
        return new Point(xr, yr);
    }

    private static Point dbl(Point a) {
        if (a.isInfinity()) return a;
        if (a.y.signum() == 0) return INF;
        BigInteger lam = a.x.multiply(a.x).multiply(BigInteger.valueOf(3))
                .multiply(a.y.multiply(BigInteger.valueOf(2)).modInverse(P)).mod(P);
        BigInteger xr = lam.multiply(lam).subtract(a.x.multiply(BigInteger.valueOf(2))).mod(P);
        BigInteger yr = lam.multiply(a.x.subtract(xr)).subtract(a.y).mod(P);
        return new Point(xr, yr);
    }

    public static Point mul(BigInteger k, Point p) {
        Point r = INF;
        Point base = p;
        int bits = k.bitLength();
        for (int i = 0; i < bits; i++) {
            if (k.testBit(i)) r = add(r, base);
            base = dbl(base);
        }
        return r;
    }

    /** Levanta x a punto (y par, según BIP-340). */
    public static Point liftX(BigInteger x) {
        BigInteger ySq = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = ySq.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);
        if (!y.multiply(y).mod(P).equals(ySq)) throw new IllegalArgumentException("x inválido");
        if (y.testBit(0)) y = P.subtract(y);
        return new Point(x, y);
    }

    public static byte[] toBytes32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        if (b.length == 33 && b[0] == 0) System.arraycopy(b, 1, out, 0, 32);
        else if (b.length <= 32) System.arraycopy(b, 0, out, 32 - b.length, b.length);
        else throw new IllegalArgumentException("entero > 32 bytes");
        return out;
    }

    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String h) {
        int n = h.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2)
            out[i / 2] = (byte) ((Character.digit(h.charAt(i), 16) << 4)
                    + Character.digit(h.charAt(i + 1), 16));
        return out;
    }

    private static byte[] taggedHash(byte[] tag, byte[] msg) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] th = d.digest(tag);
        d.reset();
        d.update(th); d.update(th); d.update(msg);
        return d.digest();
    }

    private static final byte[] TAG_AUX = "BIP0340/aux".getBytes();
    private static final byte[] TAG_NONCE = "BIP0340/nonce".getBytes();
    private static final byte[] TAG_CHALLENGE = "BIP0340/challenge".getBytes();

    /** Genera clave privada aleatoria válida (32 bytes). */
    public static byte[] generatePrivKey() {
        SecureRandom r = new SecureRandom();
        while (true) {
            byte[] b = new byte[32];
            r.nextBytes(b);
            BigInteger d = new BigInteger(1, b);
            if (d.signum() > 0 && d.compareTo(N) < 0) return b;
        }
    }

    /** Pubkey x-only (hex, 64 chars) desde privada (hex). */
    public static String pubkeyFromPriv(String privHex) {
        BigInteger d = new BigInteger(1, hexToBytes(privHex));
        Point p = mul(d, G);
        return bytesToHex(toBytes32(p.x));
    }

    /** ECDH: SHA256(x(priv * pubPoint)). Devuelve clave de 32 bytes. */
    public static byte[] ecdh(String privHex, String pubHex) throws Exception {
        BigInteger d = new BigInteger(1, hexToBytes(privHex));
        Point q = liftX(new BigInteger(1, hexToBytes(pubHex)));
        Point s = mul(d, q);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(toBytes32(s.x));
    }

    /** Firma Schnorr BIP-340. msg = 32 bytes (id del evento). Devuelve 64 bytes. */
    public static byte[] schnorrSign(byte[] privKey, byte[] msg) throws Exception {
        BigInteger d = new BigInteger(1, privKey);
        Point P = mul(d, G);
        BigInteger dd = P.y.testBit(0) ? N.subtract(d) : d;
        byte[] aux = new byte[32];
        new SecureRandom().nextBytes(aux);
        byte[] ddB = toBytes32(dd);
        byte[] t = taggedHash(TAG_AUX, aux);
        for (int i = 0; i < 32; i++) t[i] ^= ddB[i];
        byte[] pxB = toBytes32(P.x);
        byte[] nonceIn = new byte[96];
        System.arraycopy(t, 0, nonceIn, 0, 32);
        System.arraycopy(pxB, 0, nonceIn, 32, 32);
        System.arraycopy(msg, 0, nonceIn, 64, 32);
        BigInteger k = new BigInteger(1, taggedHash(TAG_NONCE, nonceIn)).mod(N);
        if (k.signum() == 0) throw new IllegalStateException("nonce cero");
        Point R = mul(k, G);
        BigInteger kk = R.y.testBit(0) ? N.subtract(k) : k;
        byte[] rxB = toBytes32(R.x);
        byte[] chIn = new byte[96];
        System.arraycopy(rxB, 0, chIn, 0, 32);
        System.arraycopy(pxB, 0, chIn, 32, 32);
        System.arraycopy(msg, 0, chIn, 64, 32);
        BigInteger e = new BigInteger(1, taggedHash(TAG_CHALLENGE, chIn)).mod(N);
        BigInteger s = kk.add(e.multiply(dd)).mod(N);
        byte[] sig = new byte[64];
        System.arraycopy(rxB, 0, sig, 0, 32);
        System.arraycopy(toBytes32(s), 0, sig, 32, 32);
        return sig;
    }
}
