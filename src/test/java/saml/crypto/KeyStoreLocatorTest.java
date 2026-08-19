package saml.crypto;

import org.junit.jupiter.api.Test;

import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreLocatorTest {

    @Test
    void createKeyStore() {
        assertThrows(CertificateException.class, ()-> KeyStoreLocator.createKeyStore("nope", "", "", ""));
    }
}