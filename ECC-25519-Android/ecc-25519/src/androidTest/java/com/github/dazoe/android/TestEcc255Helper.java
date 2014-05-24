package com.github.dazoe.android;

import android.test.AndroidTestCase;

import net.vrallev.android.ecc.Ecc25519Helper;
import net.vrallev.android.ecc.KeyHolder;

import org.fest.assertions.api.Assertions;

import java.security.SecureRandom;

/**
 * @author Ralf Wondratschek
 */
public class TestEcc255Helper extends AndroidTestCase {

    public void testEd25519() throws Exception {

        // instances from the same seed must contain the keys
        final byte[] seed = new byte[32];
        Ecc25519Helper helper1 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));
        Ecc25519Helper helper2 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));

        Assertions.assertThat(helper1.getKeyHolder().getPrivateKey()).isEqualTo(helper2.getKeyHolder().getPrivateKey());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeyDiffieHellman()).isEqualTo(helper2.getKeyHolder().getPublicKeyDiffieHellman());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeySignature()).isEqualTo(helper2.getKeyHolder().getPublicKeySignature());

        helper2 = new Ecc25519Helper(helper2.getKeyHolder().getPrivateKey());

        Assertions.assertThat(helper1.getKeyHolder().getPrivateKey()).isEqualTo(helper2.getKeyHolder().getPrivateKey());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeyDiffieHellman()).isEqualTo(helper2.getKeyHolder().getPublicKeyDiffieHellman());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeySignature()).isEqualTo(helper2.getKeyHolder().getPublicKeySignature());

        seed[0] = 1;
        helper2 = new Ecc25519Helper(KeyHolder.createPrivateKey(seed));

        Assertions.assertThat(helper1.getKeyHolder().getPrivateKey()).isNotEqualTo(helper2.getKeyHolder().getPrivateKey());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeyDiffieHellman()).isNotEqualTo(helper2.getKeyHolder().getPublicKeyDiffieHellman());
        Assertions.assertThat(helper1.getKeyHolder().getPublicKeySignature()).isNotEqualTo(helper2.getKeyHolder().getPublicKeySignature());

        // diffie hellman
        Ecc25519Helper temp = new Ecc25519Helper();
        byte[] sharedSecret1 = temp.diffieHellman(helper1.getKeyHolder().getPrivateKey(), helper2.getKeyHolder().getPublicKeyDiffieHellman());
        byte[] sharedSecret2 = temp.diffieHellman(helper2.getKeyHolder().getPrivateKey(), helper1.getKeyHolder().getPublicKeyDiffieHellman());
        Assertions.assertThat(sharedSecret1).isNotNull().isEqualTo(sharedSecret2);

        sharedSecret2 = helper1.diffieHellman();
        Assertions.assertThat(sharedSecret1).isNotNull().isNotEqualTo(sharedSecret2);

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
}
