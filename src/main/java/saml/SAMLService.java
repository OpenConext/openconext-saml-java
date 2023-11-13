package saml;

import lombok.SneakyThrows;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import saml.model.SAMLAttribute;
import saml.model.SAMLServiceProvider;
import saml.model.SAMLStatus;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

public interface SAMLService {

    /**
     * Create an {@link AuthnRequest} and return the XML representation
     *
     * @param serviceProvider      the (e.g. {@link SAMLServiceProvider}) containing the entityID
     * @param destination          the destination (e.g. singleSignService URL of the IdP)
     * @param signRequest          will the request be signed. If so, then the {@link Credential} must be present in the SP
     * @param forceAuthn           do we force a new authentication
     * @param authnContextClassRef an optional value for the authnContextClassRef element
     * @return deflated and Base64 encoded SAML AuthnRequest
     */
    String createAuthnRequest(SAMLServiceProvider serviceProvider, String destination, boolean signRequest, boolean forceAuthn, String authnContextClassRef);

    /**
     * Parse XML String to {@link Response}
     * @param xml parsed XML
     * @return the populated {@link Response}
     */
    Response parseResponse(String xml);

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
     * @param spEntityID                  the entityID of the SP
     * @param inResponseTo              the ID of the originating {@link AuthnRequest}
     * @param nameId                    the nameID of the {@link Subject}
     * @param status                    the {@link StatusCode} of the {@link Response}
     * @param relayState                optional relayState from the originating {@link AuthnRequest}
     * @param optionalMessage           optional message in case the status is not {@link StatusCode.SUCCESS}
     * @param authnContextClassRefValue the value for the {@link AuthnContextClassRef}
     * @param samlAttributes            the user attributes which will be grouped by name
     * @param servletResponse           the {@link HttpServletResponse} to write content back to originating ServiceProvider
     */
    void sendResponse(String spEntityID,
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
     * @param name                the name of the IdP
     * @param description         the description of the IdP
     * @param logoURI             the logoURI of the IdP
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

    /**
     * Create SP metaData
     *
     * @param serviceProvider the (e.g. {@link SAMLServiceProvider}) containing the entityID and certificate
     * @return SAML metadata
     */
    @SneakyThrows
    String serviceProviderMetaData(SAMLServiceProvider serviceProvider);
}
