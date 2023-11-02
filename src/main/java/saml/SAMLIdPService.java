package saml;

import lombok.SneakyThrows;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.credential.Credential;

public interface SAMLIdPService {

    AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated);

    void signObject(SignableSAMLObject signable,
                    Credential credential);

    void create
}
