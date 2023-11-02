package saml;

import lombok.SneakyThrows;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;

import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import saml.model.Attribute;
import saml.model.Status;

import java.util.List;
import java.util.Optional;

public interface SAMLIdPService {

    AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated);

    void sendResponse(String inResponseTo, Status status, String optionalMessage, List<Attribute> attributes);


}
