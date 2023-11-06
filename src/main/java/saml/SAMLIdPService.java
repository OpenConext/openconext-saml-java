package saml;

import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import saml.model.SAMLAttribute;
import saml.model.SAMLServiceProvider;
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


    /**
     * Construct the XML metadata (e.g. {@link EntityDescriptor}) with the provided IdP attributes
     *
     * @param singleSignOnService the URL for single sign on
     * @param name the name of the IdP
     * @param description  the description of the IdP
     * @param logoURI the logoURI of the IdP
     * @return XML medadata
     */
    String metaData(String singleSignOnService, String name, String description, String logoURI);

    /**
     * Resolve the metadata (e.g. {@link EntityDescriptor}) located at the provided URL
     *
     * @param serviceProvider the (e.g. {@link SAMLServiceProvider}) containing the metadata URL and entityID
     * @return the SAMLServiceProvider that may be null
     */
    SAMLServiceProvider resolveSigningCredential(SAMLServiceProvider serviceProvider);
}
