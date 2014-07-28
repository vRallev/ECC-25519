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

import net.vrallev.java.ecc.fast.Ecc25519HelperFast;
import net.vrallev.java.ecc.fast.KeyHolderFast;
import org.junit.Test;

import java.security.SecureRandom;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.*;
import static org.junit.Assert.assertArrayEquals;

/**
 * @author Ralf Wondratschek
 */
@SuppressWarnings("UnusedDeclaration")
public class Ecc25519HelperTest {

    @Test
    public void test() {
        testEd25519(new SlowFactory());
        testEd25519(new FastFactory());

        byte[] privateKey = KeyHolder.createPrivateKey("my seed".getBytes());
        Ecc25519Helper helper = new Ecc25519Helper(privateKey);
        // or
        helper = new Ecc25519HelperFast(privateKey);
    }

    @Test
    public void compareResults() {
        byte[] privateKey = KeyHolder.createPrivateKey(new byte[1]);
        Ecc25519Helper ecc25519HelperSlow = new Ecc25519Helper(new KeyHolder(privateKey));
        Ecc25519Helper ecc25519HelperFast = new Ecc25519HelperFast(new KeyHolderFast(privateKey));

        compareKeys(ecc25519HelperSlow, ecc25519HelperFast);

        // diffie hellman
        assertArrayEquals(ecc25519HelperSlow.diffieHellman(), ecc25519HelperFast.diffieHellman());

        // signature
        SecureRandom random = new SecureRandom();
        for (int i = 0; i <= 15; i++) {
            int length = (int) Math.pow(2, i);
            byte[] message = new byte[length];
            random.nextBytes(message);

            byte[] signatureSlow = ecc25519HelperSlow.sign(message);
            byte[] signatureFast = ecc25519HelperFast.sign(message);

            // assertArrayEquals(signatureSlow, signatureFast);

            assertTrue(ecc25519HelperFast.isValidSignature(message, signatureSlow));
            assertTrue(ecc25519HelperSlow.isValidSignature(message, signatureFast));
        }
    }

    private <T extends KeyHolder> void testEd25519(Factory<T> factory) {

        // instances from the same seed must contain the keys
        final byte[] seed = new byte[32];
        Ecc25519Helper helper1 = factory.createEcc25519Helper(factory.createKeyHolder(KeyHolder.createPrivateKey(seed)));
        Ecc25519Helper helper2 = factory.createEcc25519Helper(factory.createKeyHolder(KeyHolder.createPrivateKey(seed)));

        compareKeys(helper1, helper2);

        helper2 = factory.createEcc25519Helper(factory.createKeyHolder(helper2.getKeyHolder().getPrivateKey()));
        compareKeys(helper1, helper2);

        seed[0] = 1;
        helper2 = factory.createEcc25519Helper(factory.createKeyHolder(KeyHolder.createPrivateKey(seed)));

        assertThat(helper1.getKeyHolder().getPrivateKey(), not(equalTo(helper2.getKeyHolder().getPrivateKey())));
        assertThat(helper1.getKeyHolder().getPublicKeyDiffieHellman(), not(equalTo(helper2.getKeyHolder().getPublicKeyDiffieHellman())));
        assertThat(helper1.getKeyHolder().getPublicKeySignature(), not(equalTo(helper2.getKeyHolder().getPublicKeySignature())));

        // diffie hellman
        Ecc25519Helper temp = factory.createEcc25519Helper(null);
        byte[] sharedSecret1 = temp.diffieHellman(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        byte[] sharedSecret2 = temp.diffieHellman(helper2.getKeyHolder().getPrivateKey(), helper1.getKeyHolder().getPublicKeyDiffieHellman());
        assertNotNull(sharedSecret1);
        assertArrayEquals(sharedSecret1, sharedSecret2);

        sharedSecret2 = helper1.diffieHellman();
        assertNotNull(sharedSecret1);
        assertThat(sharedSecret1, not(equalTo(sharedSecret2)));

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

    private void compareKeys(Ecc25519Helper helper1, Ecc25519Helper helper2) {
        assertArrayEquals(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPrivateKey());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeyDiffieHellman(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        assertArrayEquals(helper1.getKeyHolder().getPublicKeySignature(), helper2.getKeyHolder().getPublicKeySignature());
    }

    private static interface Factory <T extends KeyHolder> {
        public Ecc25519Helper createEcc25519Helper(T keyHolder);
        public T createKeyHolder(byte[] privateKey);
    }

    private static class SlowFactory implements Factory<KeyHolder> {
        @Override
        public Ecc25519Helper createEcc25519Helper(KeyHolder keyHolder) {
            return new Ecc25519Helper(keyHolder);
        }

        @Override
        public KeyHolder createKeyHolder(byte[] privateKey) {
            return new KeyHolder(privateKey);
        }
    }

    private static class FastFactory implements Factory<KeyHolderFast> {
        @Override
        public Ecc25519Helper createEcc25519Helper(KeyHolderFast keyHolder) {
            return new Ecc25519HelperFast(keyHolder);
        }

        @Override
        public KeyHolderFast createKeyHolder(byte[] privateKey) {
            return new  KeyHolderFast(privateKey);
        }
    }
}
