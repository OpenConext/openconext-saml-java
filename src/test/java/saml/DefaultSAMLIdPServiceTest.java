package saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.mock.web.MockHttpServletResponse;
import org.w3c.dom.Element;
import saml.crypto.KeyStoreLocator;
import saml.model.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

class DefaultSAMLIdPServiceTest {

    private static final SimpleDateFormat issueFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
    private static final String spEntityId = "https://engine.test.surfconext.nl/authentication/sp/metadata";
    private static final Credential signingCredential;

    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8999);
    private DefaultSAMLIdPService samlIdPService;

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
        DefaultSAMLIdPService tempSamlIdPService = new DefaultSAMLIdPService(samlConfiguration);
        return tempSamlIdPService.serviceProviderMetaData(serviceProvider);
    }

    @BeforeEach
    void beforeEach() {
        SAMLConfiguration samlConfiguration = getSamlConfiguration(false);
        samlIdPService = new DefaultSAMLIdPService(samlConfiguration);
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
                requiresSignedAuthnRequest
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

        AuthnRequest authnRequest = samlIdPService.parseAuthnRequest(samlRequest, true, true);
        samlIdPService.signObject(authnRequest, signingCredential);

        Element element = XMLObjectSupport.marshall(authnRequest);
        String xml = SerializeSupport.nodeToString(element);

        return deflatedBase64encoded(xml);
    }


    @SneakyThrows
    private static String readFile(String path) {
        InputStream inputStream = DefaultSAMLIdPService.class.getClassLoader().getResourceAsStream(path);
        return IOUtils.toString(inputStream, Charset.defaultCharset());
    }

    private String deflatedBase64encoded(String input) throws IOException {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
        deflaterStream.write(input.getBytes(Charset.defaultCharset()));
        deflaterStream.finish();
        return new String(Base64.encodeBase64(bytesOut.toByteArray()));
    }

    @SneakyThrows
    @Test
    void parseAuthnRequest() {
        String samlRequest = this.samlAuthnRequest();
        AuthnRequest authnRequest = samlIdPService.parseAuthnRequest(samlRequest, true, true);
        String uri = authnRequest.getScoping().getRequesterIDs().get(0).getURI();
        assertEquals("https://test.surfconext.nl", uri);
    }

    @SneakyThrows
    @Test
    void parseAuthnRequestSignatureMissing() {
        SAMLConfiguration samlConfiguration = getSamlConfiguration(true);
        DefaultSAMLIdPService idPService = new DefaultSAMLIdPService(samlConfiguration);
        String samlRequest = this.samlAuthnRequest();

        assertThrows(SignatureException.class, () -> idPService.parseAuthnRequest(samlRequest, true, true));
    }

    @SneakyThrows
    @Test
    void unknownServiceProvider() {
        String samlRequestTemplate = readFile("authn_request.xml");
        String samlRequest = String.format(samlRequestTemplate, UUID.randomUUID(), issueFormat.format(new Date()), "https://nope.nl");
        String encodedSamlRequest = deflatedBase64encoded(samlRequest);
        assertThrows(IllegalArgumentException.class,() -> samlIdPService.parseAuthnRequest(encodedSamlRequest, true, true)) ;
    }

    @SneakyThrows
    @Test
    void parseSignedAuthnRequest() {
        String authnRequestXML = this.signedSamlAuthnRequest();
        AuthnRequest authnRequest = samlIdPService.parseAuthnRequest(authnRequestXML, true, true);

        String uri = authnRequest.getScoping().getRequesterIDs().get(0).getURI();
        assertEquals("https://test.surfconext.nl", uri);
    }

    @SneakyThrows
    @Test
    void sendResponse() {
        String inResponseTo = UUID.randomUUID().toString();
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        samlIdPService.sendResponse(
                spEntityId,
                inResponseTo,
                "urn:specified",
                SAMLStatus.SUCCESS,
                "relayState😀",
                "Ok",
                DefaultSAMLIdPService.authnContextClassRefPassword,
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
        Response response = samlIdPService.parseResponse(samlResponse);
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
    }

    @Test
    void metadata() {
        String singleSignOnServiceURI = "https://single.sign.on";
        String metaData = samlIdPService.metaData(
                singleSignOnServiceURI,
                "Test",
                "Test description",
                "https://static.surfconext.nl/media/idp/eduid.png");
        assertTrue(metaData.contains(singleSignOnServiceURI));
    }

    @Test
    void resolveSigningCredential() {
        SAMLServiceProvider serviceProvider = samlIdPService.resolveSigningCredential(
                new SAMLServiceProvider(spEntityId, "https://metadata.test.surfconext.nl/sp-metadata.xml")
        );
        assertEquals("https://engine.test.surfconext.nl/authentication/sp/metadata", serviceProvider.getEntityId());
        assertNotNull(serviceProvider.getCredential());
    }

    @Test
    void resolveSigningCredentialResilience() {
        SAMLServiceProvider serviceProvider = samlIdPService.resolveSigningCredential(
                new SAMLServiceProvider(spEntityId, "https://nope")
        );
        assertNull(serviceProvider);
    }
}