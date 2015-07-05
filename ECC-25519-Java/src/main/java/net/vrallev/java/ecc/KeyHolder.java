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

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import djb.Curve25519;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class KeyHolder {

    protected static final MessageDigest MESSAGE_DIGEST_SHA_256;

    static {
        try {
            MESSAGE_DIGEST_SHA_256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // ignore, won't happen
            throw new IllegalStateException(e);
        }
    }

    public static byte[] createPrivateKey(byte[] seed) {
        MESSAGE_DIGEST_SHA_256.reset();
        return MESSAGE_DIGEST_SHA_256.digest(seed);
    }

    protected final byte[] mPrivateKey;
    protected final byte[] mOriginalPrivateKey;
    protected final byte[] mPublicKeyDiffieHellman;
    protected final byte[] mPublicKeySignature;

    public KeyHolder(byte[] privateKey) {
        if (privateKey == null || (privateKey.length != 32 && privateKey.length != 64)) {
            throw new IllegalArgumentException("private key must contain 32 or 64 bytes.");
        }

        mOriginalPrivateKey = Arrays.copyOf(privateKey, privateKey.length);
        mPrivateKey = Arrays.copyOf(mOriginalPrivateKey, mOriginalPrivateKey.length);

        Curve25519.clamp(mPrivateKey);

        mPublicKeyDiffieHellman = new byte[32];
        Curve25519.keygen(mPublicKeyDiffieHellman, null, mPrivateKey);

        mPublicKeySignature = computePublicSignatureKey(mPrivateKey);
    }

    public KeyHolder(byte[] publicKeyDiffieHellman, byte[] publicKeySignature) {
        this(null, publicKeyDiffieHellman, publicKeySignature);
    }

    public KeyHolder(byte[] privateKey, byte[] publicKeyDiffieHellman, byte[] publicKeySignature) {
        mPrivateKey = privateKey;
        mOriginalPrivateKey = privateKey;
        mPublicKeyDiffieHellman = publicKeyDiffieHellman;
        mPublicKeySignature = publicKeySignature;
    }

    protected byte[] computePublicSignatureKey(byte[] privateKey) {
        EdDSAPrivateKeySpec edDSAPrivateKeySpec = new EdDSAPrivateKeySpec(privateKey, EdDSANamedCurveTable.getByName("ed25519-sha-512"));
        return edDSAPrivateKeySpec.getA().toByteArray();
    }

    public byte[] getPrivateKey() {
        return mPrivateKey;
    }

    public byte[] getPrivateKeyUnclamped() {
        return mOriginalPrivateKey;
    }

    public byte[] getPublicKeyDiffieHellman() {
        return mPublicKeyDiffieHellman;
    }

    public byte[] getPublicKeySignature() {
        return mPublicKeySignature;
    }
}
