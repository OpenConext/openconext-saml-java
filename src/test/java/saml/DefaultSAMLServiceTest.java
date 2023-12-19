package saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.io.IOUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;
import saml.crypto.KeyStoreLocator;
import saml.model.*;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import java.io.File;
import static org.junit.jupiter.api.Assertions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static saml.parser.EncodingUtils.deflatedBase64encoded;

class DefaultSAMLServiceTest {

    private static final SimpleDateFormat issueFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
    private static final String spEntityId = "https://engine.test.surfconext.nl/authentication/sp/metadata";
    private static final Credential signingCredential;
    
    private static final Logger LOG = LoggerFactory.getLogger(DefaultSAMLServiceTest.class);

    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8999);
    private DefaultSAMLService defaultSAMLService;

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
        KeyStore keyStore = KeyStoreLocator.createKeyStore(
                spEntityId,
                readFile("saml_sp.crt"),
                readFile("saml_sp.pem"),
                "secret"
        );
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keyStore, Map.of(spEntityId, "secret"), UsageType.SIGNING);
        try {
            signingCredential = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(spEntityId), new UsageCriterion(UsageType.SIGNING)));
        } catch (ResolverException e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeEach
    void beforeEach() {
        SAMLConfiguration samlConfiguration = getSamlConfiguration(false);
        defaultSAMLService = new DefaultSAMLService(samlConfiguration);
    }

    private String getSPMetaData() {
        SAMLConfiguration samlConfiguration = new SAMLConfiguration(
                new SAMLIdentityProvider(
                        readFile("saml_idp.crt"),
                        readFile("saml_idp.pem"),
                        spEntityId),
                List.of(),
                false
        );
        SAMLServiceProvider serviceProvider = new SAMLServiceProvider(spEntityId, spEntityId);
        serviceProvider.setCredential(signingCredential);
        serviceProvider.setAcsLocation("https://engine.test.surfconext.nl/authentication/sp/consume-assertion");
        DefaultSAMLService tempSamlIdPService = new DefaultSAMLService(samlConfiguration);
        return tempSamlIdPService.serviceProviderMetaData(serviceProvider);
    }

    private SAMLConfiguration getSamlConfiguration(boolean requiresSignedAuthnRequest) {
        String metaData = getSPMetaData();
        stubFor(get(urlPathMatching("/sp-metadata.xml")).willReturn(aResponse()
                .withHeader("Content-Type", "text/xml")
                .withBody(metaData)));
        SAMLServiceProvider serviceProvider = new SAMLServiceProvider(
                spEntityId,
                "http://localhost:8999/sp-metadata.xml"
        );
        SAMLConfiguration samlConfiguration = new SAMLConfiguration(
                new SAMLIdentityProvider(
                        readFile("saml_idp.crt"),
                        readFile("saml_idp.pem"),
                        spEntityId),
                List.of(serviceProvider),
                requiresSignedAuthnRequest,
                true
        );
        return samlConfiguration;
    }

    @SneakyThrows
    private String samlAuthnRequest() {
        String samlRequestTemplate = readFile("authn_request.xml");
        String samlRequest = String.format(samlRequestTemplate, UUID.randomUUID(), issueFormat.format(new Date()), spEntityId);
        return deflatedBase64encoded(samlRequest);
    }

    @SneakyThrows
    private String signedSamlAuthnRequest() {
        String samlRequest = samlAuthnRequest();

        AuthnRequest authnRequest = defaultSAMLService.parseAuthnRequest(samlRequest, true, true);
        defaultSAMLService.signObject(authnRequest, signingCredential);

        Element element = XMLObjectSupport.marshall(authnRequest);
        String xml = SerializeSupport.nodeToString(element);

        return deflatedBase64encoded(xml);
    }


    @SneakyThrows
    private static String readFile(String path) {
        InputStream inputStream = DefaultSAMLService.class.getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

    @SneakyThrows
    @Test
    void parseAuthnRequest() {
        String samlRequest = this.samlAuthnRequest();
        AuthnRequest authnRequest = defaultSAMLService.parseAuthnRequest(samlRequest, true, true);
        String uri = authnRequest.getScoping().getRequesterIDs().get(0).getURI();
        assertEquals("https://test.surfconext.nl", uri);
    }

    @SneakyThrows
    @Test
    void parseAuthnRequestSignatureMissing() {
        SAMLConfiguration samlConfiguration = getSamlConfiguration(true);
        DefaultSAMLService idPService = new DefaultSAMLService(samlConfiguration);
        String samlRequest = this.samlAuthnRequest();

        assertThrows(SignatureException.class, () -> idPService.parseAuthnRequest(samlRequest, true, true));
    }

    @SneakyThrows
    @Test
    void unknownServiceProvider() {
        String samlRequestTemplate = readFile("authn_request.xml");
        String samlRequest = String.format(samlRequestTemplate, UUID.randomUUID(), issueFormat.format(new Date()), "https://nope.nl");
        String encodedSamlRequest = deflatedBase64encoded(samlRequest);
        assertThrows(IllegalArgumentException.class, () -> defaultSAMLService.parseAuthnRequest(encodedSamlRequest, true, true));
    }

    @SneakyThrows
    @Test
    void acsLocationInvalid() {
        String samlRequestTemplate = readFile("authn_request.xml");
        String samlRequest = String.format(samlRequestTemplate, UUID.randomUUID(), issueFormat.format(new Date()), spEntityId);
        samlRequest = samlRequest.replace("https://engine.test.surfconext.nl/authentication/sp/consume-assertion", "https://nope");
        String encodedSamlRequest = deflatedBase64encoded(samlRequest);
        assertThrows(IllegalArgumentException.class, () -> defaultSAMLService.parseAuthnRequest(encodedSamlRequest, true, true));
    }

    @SneakyThrows
    @Test
    void parseSignedAuthnRequest() {
        String authnRequestXML = this.signedSamlAuthnRequest();
        AuthnRequest authnRequest = defaultSAMLService.parseAuthnRequest(authnRequestXML, true, true);

        String uri = authnRequest.getScoping().getRequesterIDs().get(0).getURI();
        assertEquals("https://test.surfconext.nl", uri);
    }

    @SneakyThrows
    @Test
    void sendResponse() {
        String inResponseTo = UUID.randomUUID().toString();
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        defaultSAMLService.sendResponse(
                spEntityId,
                inResponseTo,
                "urn:specified",
                SAMLStatus.SUCCESS,
                "relayState😀",
                null,
                DefaultSAMLService.authnContextClassRefPassword,
                List.of(
                        new SAMLAttribute("group", "riders"),
                        new SAMLAttribute("group", "gliders"),
                        new SAMLAttribute("single", "value")
                ),
                httpServletResponse
        );
        String html = httpServletResponse.getContentAsString();
        Document document = Jsoup.parse(html);
        String relayState = document.select("input[name=\"RelayState\"]").first().attr("value");
        assertEquals("relayState?�", relayState);

        String samlResponse = document.select("input[name=\"SAMLResponse\"]").first().attr("value");
        //Convenient way to make simple assertions
        Response response = defaultSAMLService.parseResponse(samlResponse);

        String statusCode = response.getStatus().getStatusCode().getValue();
        assertEquals(statusCode, "urn:oasis:names:tc:SAML:2.0:status:Success");

        List<String> group = response
                .getAssertions().get(0)
                .getAttributeStatements().get(0)
                .getAttributes()
                .stream()
                .filter(attribute -> attribute.getName().equals("group")).findAny().get()
                .getAttributeValues().stream()
                .map(xmlObject -> ((XSString) xmlObject).getValue())
                .sorted()
                .collect(Collectors.toList());

        assertEquals(List.of("gliders", "riders"), group);

        Instant notBefore = response.getAssertions().get(0).getConditions().getNotBefore();
        Instant notOnOrAfter = response.getAssertions().get(0).getConditions().getNotOnOrAfter();
        Instant now = Instant.now();

        assertTrue(notBefore.isBefore(now));
        assertTrue(notOnOrAfter.isAfter(now));
    }

    @SneakyThrows
    @Test
    void sendResponseNoAuthnContext() {
        String inResponseTo = UUID.randomUUID().toString();
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        defaultSAMLService.sendResponse(
                spEntityId,
                inResponseTo,
                "urn:specified",
                SAMLStatus.NO_AUTHN_CONTEXT,
                null,
                "Not Ok",
                DefaultSAMLService.authnContextClassRefPassword,
                List.of(),
                httpServletResponse
        );
        String html = httpServletResponse.getContentAsString();
        Document document = Jsoup.parse(html);
        String samlResponse = document.select("input[name=\"SAMLResponse\"]").first().attr("value");
        //Convenient way to make simple assertions
        Response response = defaultSAMLService.parseResponse(samlResponse);

        StatusCode statusCode = response.getStatus().getStatusCode();
        StatusCode innerStatusCode = statusCode.getStatusCode();
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder", statusCode.getValue() );
        assertEquals(SAMLStatus.NO_AUTHN_CONTEXT.getStatus(), innerStatusCode.getValue());

        assertEquals("Not Ok", response.getStatus().getStatusMessage().getValue());
        assertEquals("Not Ok", ((XSString) response.getStatus().getStatusDetail().getUnknownXMLObjects().get(0)).getValue());

        List<Assertion> assertions = response.getAssertions();
        assertTrue(assertions.isEmpty());
    }

    @Test
    void metadata() {
        String singleSignOnServiceURI = "https://single.sign.on";
        String metaData = defaultSAMLService.metaData(
                singleSignOnServiceURI,
                "Test",
                "Test description",
                "https://static.surfconext.nl/media/idp/eduid.png");
        assertTrue(metaData.contains(singleSignOnServiceURI));
    }

    @Test
    void resolveSigningCredential() {
        SAMLServiceProvider serviceProvider = defaultSAMLService.resolveSigningCredential(
                new SAMLServiceProvider(spEntityId, "https://metadata.test.surfconext.nl/sp-metadata.xml")
        );
        assertEquals("https://engine.test.surfconext.nl/authentication/sp/metadata", serviceProvider.getEntityId());
        assertNotNull(serviceProvider.getCredential());
    }

    @Test
    void resolveSigningCredentialResilience() {
        SAMLServiceProvider serviceProvider = defaultSAMLService.resolveSigningCredential(
                new SAMLServiceProvider(spEntityId, "https://nope")
        );
        assertNull(serviceProvider);
    }

    @Test
    void createAuthnRequest() {
        SAMLServiceProvider serviceProvider = new SAMLServiceProvider(spEntityId, spEntityId);
        serviceProvider.setCredential(signingCredential);
        serviceProvider.setAcsLocation("https://engine.test.surfconext.nl/authentication/sp/consume-assertion");

        String authnRequestXML = this.defaultSAMLService.createAuthnRequest(serviceProvider,
                "https://mujina-idp.test.surfconext.nl/SingleSignOnService",
                true, true, "https://refeds.org/profile/mfa");
        
        AuthnRequest authnRequest = this.defaultSAMLService.parseAuthnRequest(authnRequestXML, true, true);
        assertEquals(serviceProvider.getEntityId(), authnRequest.getIssuer().getValue());
        assertEquals(serviceProvider.getAcsLocation(), authnRequest.getAssertionConsumerServiceURL());
    }
    
    /**
     * Tests signature wrapping attacks in the authentication requests, with the following message modifications:
     * - Wrapped content with/without signature
     * - Wrapped content in Object / RequestedAuthnContext
     * - Processed content with equal/modified/missing ID
     * 
     * This leads to 12 different message combinations. 
     * The destination in every message is modified to hackmanit.de. 
     * 
     * If any of the message is successfully validated AND hackmanit.de is processed as a valid destination,
     * the test fails.
     * 
     * Note that all messages were generated statically so there is a need for an update once the keys/certs 
     * are updated.
     */
    @Test
    void testSignatureWrappingAttacks() {
        
        File[] files = new File(DefaultSAMLService.class.getClassLoader().getResource("req-wrapping").getPath()).listFiles();
        
        for (File file : files) {
            String authnRequestXML = readFile("req-wrapping/" + file.getName());
            try {
                AuthnRequest authnRequest = defaultSAMLService.parseAuthnRequest(authnRequestXML, false, false);
                String destination = authnRequest.getDestination();
                LOG.warn("Signature valid for " + file.getName() + " with destination: " + destination);
                assertEquals("https://mujina-idp.test.surfconext.nl/SingleSignOnService", destination);
            } catch (Exception ex) {
                LOG.debug("Exception successfully thrown for " + file.getName(), ex);
            }
        }

    }
    
    /**
     * Tests for node splitting attacks with CDATA and comments.
     * 
     * If any of the message is successfully split the issuer text content, an error is thrown.
     * 
     * Note that all messages were generated statically so there is a need for an update once the keys/certs 
     * are updated.
     */
    @Test
    void testNodeSplitting() {
        String authnRequestXML = readFile("node-splitting/comment.xml");
        AuthnRequest authnRequest = defaultSAMLService.parseAuthnRequest(authnRequestXML, false, false);
        assertEquals("https://engine.test.surfconext.nl/authentication/sp/metadata", authnRequest.getIssuer().getValue());
        
        authnRequestXML = readFile("node-splitting/cdata.xml");
        authnRequest = defaultSAMLService.parseAuthnRequest(authnRequestXML, false, false);
        assertEquals("https://engine.test.surfconext.nl/authentication/sp/metadata", authnRequest.getIssuer().getValue());
    }
}