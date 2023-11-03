package saml;

import org.opensaml.saml.saml2.core.AuthnRequest;
import saml.model.Attribute;
import saml.model.Status;

import java.util.List;

public interface SAMLIdPService {

    AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated);

    void sendResponse(String inResponseTo, Status status, String optionalMessage, List<Attribute> attributes);


}
