package net.vrallev.java.ecc;

import djb.Curve25519;
import krm2.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519Helper {

    protected static final MessageDigest MESSAGE_DIGEST_SHA_256;

    static {
        try {
            MESSAGE_DIGEST_SHA_256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // ignore, won't happen
            throw new IllegalStateException(e);
        }
    }

    private final KeyHolder mKeyHolder;

    public Ecc25519Helper() {
        this((KeyHolder) null);
    }

    public Ecc25519Helper(byte[] privateKey) {
        this(new KeyHolder(privateKey));
    }

    public Ecc25519Helper(KeyHolder keyHolder) {
        mKeyHolder = keyHolder;
    }

    /*
     * Diffie Hellman
     */

    public byte[] diffieHellman() {
        return diffieHellman(mKeyHolder.getPrivateKey(), mKeyHolder.getPublicKeyDiffieHellman());
    }

    public byte[] diffieHellman(byte[] privateKey, byte[] publicKey) {
        byte[] sharedSecret = new byte[32];
        Curve25519.curve(sharedSecret, privateKey, publicKey);

        // see documentation of curve function above
        MESSAGE_DIGEST_SHA_256.reset();
        return MESSAGE_DIGEST_SHA_256.digest(sharedSecret);
    }

    /*
     * Signature
     */

    public byte[] sign(byte[] message) {
        return sign(message, mKeyHolder.getPrivateKey(), mKeyHolder.getPublicKeySignature());
    }

    public byte[] sign(byte[] message, byte[] privateKey, byte[] publicKey) {
        try {
            return ed25519.signature(message, privateKey, publicKey);

        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /*
     * Signature verification
     */

    public boolean isValidSignature(byte[] message, byte[] signature) {
        return isValidSignature(message, signature, mKeyHolder.getPublicKeySignature());
    }

    public boolean isValidSignature(byte[] message, byte[] signature, byte[] publicKey) {
        try {
            return ed25519.checkvalid(signature, message, publicKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /*
     * Getter
     */

    public KeyHolder getKeyHolder() {
        return mKeyHolder;
    }
}
