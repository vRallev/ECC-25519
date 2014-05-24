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
