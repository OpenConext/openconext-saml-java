package saml;

import org.opensaml.saml.saml2.core.*;
import saml.model.SAMLAttribute;
import saml.model.SAMLStatus;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

public interface SAMLIdPService {

    /**
     * Parse the SAML xml to an {@link AuthnRequest}
     *
     * @param xml      the XML which can be BASE64 encoded and deflated
     * @param encoded  is the XML encoded
     * @param deflated is the XML deflated
     * @return parsed {@link AuthnRequest}
     */
    AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated);

    /**
     * Send an XML {@link Response} using the {@link HttpServletResponse}
     *
     * @param destination               the AssertionConsumerServiceURL from the originating {@link AuthnRequest}
     * @param inResponseTo              the ID of the originating {@link AuthnRequest}
     * @param nameId                    the nameID of the {@link Subject}
     * @param status                    the {@link StatusCode} of the {@link Response}
     * @param relayState                optional relayState from the originating {@link AuthnRequest}
     * @param optionalMessage           optional message in case the status is not {@link StatusCode.SUCCESS}
     * @param authnContextClassRefValue the value for the {@link AuthnContextClassRef}
     * @param samlAttributes            the user attributes which will be grouped by name
     * @param servletResponse           the {@link HttpServletResponse} to write content back to originating ServiceProvider
     */
    void sendResponse(String destination,
                      String inResponseTo,
                      String nameId,
                      SAMLStatus status,
                      String relayState,
                      String optionalMessage,
                      String authnContextClassRefValue,
                      List<SAMLAttribute> samlAttributes,
                      HttpServletResponse servletResponse);


}
