package saml.crypto;

import lombok.SneakyThrows;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

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
