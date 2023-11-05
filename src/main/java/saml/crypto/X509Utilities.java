package saml.crypto;


import lombok.SneakyThrows;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.CharArrayReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509Utilities {

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String BEGIN_KEY = "-----BEGIN RSA PRIVATE KEY-----\n";
    public static final String END_KEY = "-----END RSA PRIVATE KEY-----";

    private X509Utilities() {
    }

    public static byte[] getDER(String pem) {
        String data = keyCleanup(pem);

        return DatatypeConverter.parseBase64Binary(data);
    }

    private static String keyCleanup(String pem) {
        return pem
                .replace(BEGIN_CERT, "")
                .replace(END_CERT, "")
                .replace(BEGIN_KEY, "")
                .replace(END_KEY, "")
                .replace("\n", "")
                .trim();
    }

    public static X509Certificate getCertificate(byte[] der) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    @SneakyThrows
    public static PrivateKey readPrivateKey(String pem, String passphrase) {
        PEMParser parser = new PEMParser(new CharArrayReader(pem.toCharArray()));
        Object obj = parser.readObject();
        parser.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMKeyPair ukp = (PEMKeyPair) obj;
        KeyPair kp = converter.getKeyPair(ukp);

        return kp.getPrivate();
    }

}
