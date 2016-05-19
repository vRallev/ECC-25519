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
package net.vrallev.android.ecc;

import com.github.dazoe.android.Ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import djb.Curve25519;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519Helper {

    /*package*/ static MessageDigest getSha256Digest() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            return digest;
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
        return getSha256Digest().digest(sharedSecret);
    }

    /*
     * Signature
     */

    public byte[] sign(byte[] message) {
        return signWithoutClamp(message, mKeyHolder.getPrivateKey());
    }

    public byte[] sign(byte[] message, byte[] privateKey) {
        privateKey = Arrays.copyOf(privateKey, privateKey.length);
        Curve25519.clamp(privateKey);
        return signWithoutClamp(message, privateKey);
    }

    protected byte[] signWithoutClamp(byte[] message, byte[] privateKey) {
        try {
            return Ed25519.Sign(message, privateKey);

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
            return 0 == Ed25519.Verify(message, signature, publicKey);
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
