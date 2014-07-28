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
package net.vrallev.java.ecc.fast;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.vrallev.java.ecc.Ecc25519Helper;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519HelperFast extends Ecc25519Helper {

    private final EdDSAEngine mEdDSAEngine;

    public Ecc25519HelperFast() {
        this((KeyHolderFast) null);
    }

    public Ecc25519HelperFast(byte[] privateKey) {
        this(new KeyHolderFast(privateKey));
    }

    public Ecc25519HelperFast(KeyHolderFast keyHolder) {
        super(keyHolder);

        MessageDigest messageDigestSha512;
        try {
            messageDigestSha512 = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            // ignore, should not happen
            throw new IllegalStateException(e);
        }

        mEdDSAEngine = new EdDSAEngine(messageDigestSha512);
    }

    @Override
    public byte[] sign(byte[] message, byte[] privateKey, byte[] publicKey) {
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

    @Override
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
}
