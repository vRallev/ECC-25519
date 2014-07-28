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

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.vrallev.java.ecc.KeyHolder;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class KeyHolderFast extends KeyHolder {

    public KeyHolderFast(byte[] privateKey) {
        super(privateKey);
    }

    public KeyHolderFast(byte[] publicKeyDiffieHellman, byte[] publicKeySignature) {
        super(publicKeyDiffieHellman, publicKeySignature);
    }

    public KeyHolderFast(byte[] privateKey, byte[] publicKeyDiffieHellman, byte[] publicKeySignature) {
        super(privateKey, publicKeyDiffieHellman, publicKeySignature);
    }

    @Override
    protected byte[] computePublicSignatureKey(byte[] privateKey) {
        EdDSAPrivateKeySpec edDSAPrivateKeySpec = new EdDSAPrivateKeySpec(privateKey, EdDSANamedCurveTable.getByName("ed25519-sha-512"));
        return edDSAPrivateKeySpec.getA().toByteArray();
    }
}
