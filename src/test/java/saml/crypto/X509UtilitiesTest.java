package saml.crypto;

import org.bouncycastle.openssl.PEMException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class X509UtilitiesTest {

    @Test
    void readPrivateKey() {
        assertThrows(PEMException.class, () -> X509Utilities.readPrivateKey("nipe")) ;
    }
}