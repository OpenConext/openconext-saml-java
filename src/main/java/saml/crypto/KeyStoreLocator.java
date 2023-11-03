package saml.crypto;

import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import saml.crypto.X509Utilities;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class KeyStoreLocator {

    @SneakyThrows
    public static KeyStore createKeyStore(String name, String certificate, String privateKey, String passPhrase) {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, passPhrase.toCharArray());

        byte[] certBytes = X509Utilities.getDER(certificate);
        Certificate cert = X509Utilities.getCertificate(certBytes);
        ks.setCertificateEntry(name, cert);

        PrivateKey pkey = X509Utilities.readPrivateKey(privateKey, passPhrase);
        ks.setKeyEntry(name, pkey, passPhrase.toCharArray(), new
                Certificate[]{cert});
        return ks;
    }

}
