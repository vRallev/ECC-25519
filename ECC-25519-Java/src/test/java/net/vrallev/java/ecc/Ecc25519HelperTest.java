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

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519HelperTest {

    @Test
    public void testEd25519() throws Exception {

        // instances from the same seed must contain the keys
        final byte[] seed = new byte[32];
        Ecc25519Helper helper1 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));
        Ecc25519Helper helper2 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));

        assertArrayEquals(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPrivateKey());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeyDiffieHellman(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeySignature(), helper2.getKeyHolder().getPublicKeySignature());

        helper2 = new Ecc25519Helper(helper2.getKeyHolder().getPrivateKey());

        assertArrayEquals(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPrivateKey());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeyDiffieHellman(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeySignature(), helper2.getKeyHolder().getPublicKeySignature());

        seed[0] = 1;
        helper2 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));

        assertFalse(Arrays.equals(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPrivateKey()));
        assertFalse(Arrays.equals(helper1.getKeyHolder().getPublicKeyDiffieHellman(), helper2.getKeyHolder().getPublicKeyDiffieHellman()));
        assertFalse(Arrays.equals(helper1.getKeyHolder().getPublicKeySignature(), helper2.getKeyHolder().getPublicKeySignature()));

        // diffie hellman
        Ecc25519Helper temp = new Ecc25519Helper();
        byte[] sharedSecret1 = temp.diffieHellman(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        byte[] sharedSecret2 = temp.diffieHellman(helper2.getKeyHolder().getPrivateKey(), helper1.getKeyHolder().getPublicKeyDiffieHellman());
        assertNotNull(sharedSecret1);
        assertArrayEquals(sharedSecret1, sharedSecret2);

        sharedSecret2 = helper1.diffieHellman();
        assertNotNull(sharedSecret1);
        assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

        // signature
        SecureRandom random = new SecureRandom();
        for (int i = 0; i <= 14; i++) {
            int length = (int) Math.pow(2, i);
            byte[] message = new byte[length];
            random.nextBytes(message);

            byte[] signature = helper1.sign(message);
            assertTrue(helper1.isValidSignature(message, signature));
            assertFalse(helper2.isValidSignature(message, signature));

            signature = helper2.sign(message);
            assertFalse(helper1.isValidSignature(message, signature));
            assertTrue(helper2.isValidSignature(message, signature));
        }
    }

    @Test
    public void keyHolderCTORIsSideEffectFree() {
        final byte[] pk1 = KeyHolder.createPrivateKey("hello".getBytes());
        final byte[] pk2 = pk1.clone();
        new KeyHolder(pk2);
        assertArrayEquals(pk1, pk2);
    }

    @Test
    public void keyHolderGetPrivateKeyReturnsUnmodifiedPrivateKey() {
        final byte[] pk1 = KeyHolder.createPrivateKey("hello".getBytes());
        final byte[] pk2 = new KeyHolder(pk1.clone()).getPrivateKeyUnclamped();
        assertArrayEquals(pk1, pk2);
    }

    @Test
    public void ecc25519HelperSignClampsParameter() {
        // if pk1 is not clamped, signature verification will fail.
        // the .clone() calls are to make sure no other side effects affect the outcome.
        final byte[] pk1 = KeyHolder.createPrivateKey("hello".getBytes());

        byte[] sig = new Ecc25519Helper().sign("message".getBytes(), pk1, new KeyHolder(pk1.clone()).getPublicKeySignature());

        assertTrue((new Ecc25519Helper()).isValidSignature("message".getBytes(), sig, new KeyHolder(pk1.clone()).getPublicKeySignature()));
    }

    @Test
    public void ecc25519HelperSignIsSideEffectFreeOnPrivateKeyParameter() {
        // ensure that clamping of pk2 is side-effect free.
        // the .clone() calls are to make sure no other side effects affect the outcome.
        final byte[] pk1 = KeyHolder.createPrivateKey("hello".getBytes());
        final byte[] pk2 = pk1.clone();

        byte[] sig = new Ecc25519Helper().sign("message".getBytes(), pk2, new KeyHolder(pk1.clone()).getPublicKeySignature());

        assertArrayEquals(pk1, pk2);
    }
}
