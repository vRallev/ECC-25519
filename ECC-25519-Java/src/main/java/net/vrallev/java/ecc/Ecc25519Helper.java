/*
 * Copyright (C) 2014 Ralf Wondratschek
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.vrallev.java.ecc;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

import djb.Curve25519;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519Helper {

    protected static final MessageDigest MESSAGE_DIGEST_SHA_256;
    protected static final MessageDigest MESSAGE_DIGEST_SHA_512;

    static {
        try {
            MESSAGE_DIGEST_SHA_256 = MessageDigest.getInstance("SHA-256");
            MESSAGE_DIGEST_SHA_512 = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            // ignore, won't happen
            throw new IllegalStateException(e);
        }
    }

    private final KeyHolder mKeyHolder;
    private final EdDSAEngine mEdDSAEngine;

    public Ecc25519Helper() {
        this((KeyHolder) null);
    }

    public Ecc25519Helper(byte[] privateKey) {
        this(new KeyHolder(privateKey));
    }

    public Ecc25519Helper(KeyHolder keyHolder) {
        mKeyHolder = keyHolder;
        mEdDSAEngine = new EdDSAEngine(MESSAGE_DIGEST_SHA_512);
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
        return signWithoutClamp(message, mKeyHolder.getPrivateKey(), mKeyHolder.getPublicKeySignature());
    }

    public byte[] sign(byte[] message, byte[] privateKey, byte[] publicKey) {
        privateKey = Arrays.copyOf(privateKey, privateKey.length);
        Curve25519.clamp(privateKey);
        return signWithoutClamp(message, privateKey, publicKey);
    }

    protected byte[] signWithoutClamp(byte[] message, byte[] privateKey, byte[] publicKey) {
        try {

            EdDSAPrivateKeySpec edDSAPrivateKeySpec = new EdDSAPrivateKeySpec(privateKey, EdDSANamedCurveTable.getByName("ed25519-sha-512"));
            mEdDSAEngine.initSign(new EdDSAPrivateKey(edDSAPrivateKeySpec));
            mEdDSAEngine.update(message);
            return mEdDSAEngine.sign();

        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
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
            EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");

            EdDSAPublicKeySpec edDSAPublicKeySpec = new EdDSAPublicKeySpec(publicKey, spec);
            EdDSAPublicKey edDSAPublicKey = new EdDSAPublicKey(edDSAPublicKeySpec);

            mEdDSAEngine.initVerify(edDSAPublicKey);
            mEdDSAEngine.update(message);

            return mEdDSAEngine.verify(signature);
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
