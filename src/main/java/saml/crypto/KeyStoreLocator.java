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

    private static CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore createKeyStore(String pemPassPhrase) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, pemPassPhrase.toCharArray());
            return keyStore;
        } catch (Exception e) {
            //too many exceptions we can't handle, so brute force catch
            throw new RuntimeException(e);
        }
    }

    //privateKey must be in the DER unencrypted PKCS#8 format. See README.md
    @SneakyThrows
    public static void addPrivateKey(KeyStore keyStore, String alias, String privateKey, String certificate, String password) {
        String wrappedCert = wrapCert(certificate);
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());

        char[] passwordChars = password.toCharArray();
        Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
        ArrayList<Certificate> certs = new ArrayList<>();
        certs.add(cert);

        byte[] privKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

        KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
        keyStore.setKeyEntry(alias, privKey, passwordChars, certs.toArray(new Certificate[certs.size()]));
    }

    @SneakyThrows
    public static KeyStore createKeyStore(String name, String certificate, String privateKey, String passPhrase) {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, passPhrase.toCharArray());

        byte[] certBytes = X509Utilities.getDER(certificate);
        Certificate cert = X509Utilities.getCertificate(certBytes);
        ks.setCertificateEntry(name, cert);

        PrivateKey pkey = X509Utilities.readPrivateKey(privateKey , passPhrase);
        ks.setKeyEntry(name, pkey, passPhrase.toCharArray(), new
                Certificate[]{cert});
        return ks;
    }

    private static String wrapCert(String certificate) {
        return "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
    }

}
