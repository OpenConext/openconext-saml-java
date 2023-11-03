package saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import saml.crypto.KeyStoreLocator;
import saml.crypto.X509Utilities;
import saml.model.SAMLAttribute;
import saml.model.SAMLConfiguration;
import saml.model.SAMLStatus;
import saml.parser.EncodingUtils;
import saml.parser.OpenSamlVelocityEngine;

import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.nio.charset.StandardCharsets.UTF_8;

public class DefaultSAMLIdPService implements SAMLIdPService {

    public static final String authnContextClassRefPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    private static final String POST_BINDING_VM = "/templates/saml2-post-binding.vm";

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }

    private final OpenSamlVelocityEngine velocityEngine = new OpenSamlVelocityEngine();
    private final BasicParserPool parserPool;
    private final X509Credential signatureValidationCredential;
    private final SAMLConfiguration configuration;
    private final Duration skewTime = Duration.ofMinutes(5);
    private final Credential signinCredential;

    @SneakyThrows
    public DefaultSAMLIdPService(SAMLConfiguration configuration) {
        this.signatureValidationCredential = loadPublicKey(configuration.getSpCertificate());
        String entityId = configuration.getEntityId();
        KeyStore keyStore = KeyStoreLocator.createKeyStore(
                entityId,
                configuration.getIdpCertificate(),
                configuration.getIdpPrivateKey(),
                "secret"
        );
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keyStore, Map.of(entityId, "secret"), UsageType.SIGNING);
        this.signinCredential = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityId), new UsageCriterion(UsageType.SIGNING)));

        this.parserPool = new BasicParserPool();
        this.configuration = configuration;
        bootstrap();
    }

    @SneakyThrows
    private void bootstrap() {
        parserPool.setMaxPoolSize(50);
        parserPool.setCoalescing(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setIgnoreComments(true);
        parserPool.setIgnoreElementContentWhitespace(true);
        parserPool.setNamespaceAware(true);
        parserPool.setSchema(null);
        parserPool.setDTDValidating(false);
        parserPool.setXincludeAware(false);

        Map<String, Object> builderAttributes = new HashMap<>();
        parserPool.setBuilderAttributes(builderAttributes);

        Map<String, Boolean> parserBuilderFeatures = getParserBuilderFeatures();
        parserPool.setBuilderFeatures(parserBuilderFeatures);

        parserPool.initialize();

        InitializationService.initialize();

        XMLObjectProviderRegistry registry;
        synchronized (ConfigurationService.class) {
            registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
            if (registry == null) {
                registry = new XMLObjectProviderRegistry();
                ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
            }
        }
        registry.setParserPool(parserPool);
    }


    private UnmarshallerFactory getUnmarshallerFactory() {
        return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    }

    private static Map<String, Boolean> getParserBuilderFeatures() {
        Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
        parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
        parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
        parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
        parserBuilderFeatures.put(
                "http://apache.org/xml/features/validation/schema/normalized-value",
                FALSE
        );
        parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
        parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
        return parserBuilderFeatures;
    }

    @SneakyThrows
    protected void validateSignature(SignableSAMLObject target) {
        Signature signature = target.getSignature();

        if (signature == null) {
            if (this.configuration.isRequiresSignedAuthnRequest()) {
                throw new SignatureException("Signature element not found.");
            }
        } else {
            SignatureValidator.validate(signature, this.signatureValidationCredential);
        }
    }

    private XMLObject parseXMLObject(String xml, boolean encoded, boolean deflated) throws XMLParserException, UnmarshallingException {
        if (encoded) {
            xml = EncodingUtils.samlDecode(xml, deflated);
        }
        Document document = this.parserPool.parse(new ByteArrayInputStream(xml.getBytes()));
        Element element = document.getDocumentElement();
        return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
    }

    @Override
    @SneakyThrows
    public AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated) {
        AuthnRequest authnRequest = (AuthnRequest) parseXMLObject(xml, encoded, deflated);

        this.validateSignature(authnRequest);
        return authnRequest;
    }

    @SneakyThrows
    public Response parseResponse(String xml, boolean encoded, boolean deflated) {
        Response response = (Response) parseXMLObject(xml, encoded, deflated);

        this.validateSignature(response);
        return response;
    }

    private static X509Credential loadPublicKey(String certificate) throws Exception {
        byte[] certBytes = X509Utilities.getDER(certificate);
        return new BasicX509Credential(X509Utilities.getCertificate(certBytes));
    }

    private KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
        NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap
                .buildBasicKeyInfoGeneratorManager();
        return manager.getDefaultManager().getFactory(credential).newInstance();
    }

    @SneakyThrows
    protected void signObject(SignableSAMLObject signable,
                              Credential credential) {
        Signature signature = buildSAMLObject(Signature.class);
        signable.setSignature(signature);

        SignatureSigningParameters signingParameters = new SignatureSigningParameters();
        signingParameters.setSigningCredential(credential);
        signingParameters.setKeyInfoGenerator(getKeyInfoGenerator(credential));
        signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);

        SignatureSupport.prepareSignatureParams(signature, signingParameters);
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable);
        marshaller.marshall(signable);
        Signer.signObject(signature);
    }

    @SneakyThrows
    @SuppressWarnings("unchecked")
    private <T extends XMLObject> T buildSAMLObject(final Class<T> clazz) {
        QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
    }

    @SneakyThrows
    @Override
    public void sendResponse(String destination,
                             String inResponseTo,
                             String nameId,
                             SAMLStatus status,
                             String relayState,
                             String optionalMessage,
                             String authnContextClassRefValue,
                             List<SAMLAttribute> samlAttributes,
                             HttpServletResponse servletResponse) {
        Instant now = Instant.now();
        Instant notOnOrAfter = now.minus(skewTime);
        Instant notBefore = now.plus(skewTime);
        //Very cumbersome Open-SAML interface, can't be helped
        Response response = buildSAMLObject(Response.class);
        response.setDestination(destination);
        response.setID("RP" + UUID.randomUUID());
        response.setInResponseTo(inResponseTo);
        response.setIssueInstant(now);

        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(this.configuration.getIssuerId());
        response.setIssuer(issuer);
        response.setVersion(SAMLVersion.VERSION_20);

        org.opensaml.saml.saml2.core.Status newStatus = buildSAMLObject(org.opensaml.saml.saml2.core.Status.class);
        StatusCode statusCode = buildSAMLObject(StatusCode.class);
        statusCode.setValue(status.getStatus());
        if (StringUtils.isNotEmpty(optionalMessage)) {
            StatusMessage statusMessage = buildSAMLObject(StatusMessage.class);
            statusMessage.setValue(optionalMessage);
            newStatus.setStatusMessage(statusMessage);
        }
        response.setStatus(newStatus);

        Assertion assertion = buildSAMLObject(Assertion.class);
        // Can't re-use, because it is already the child of another XML Object
        Issuer newIssuer = buildSAMLObject(Issuer.class);
        newIssuer.setValue(this.configuration.getIssuerId());
        assertion.setIssuer(newIssuer);
        assertion.setID("A" + UUID.randomUUID());
        assertion.setIssueInstant(now);
        assertion.setVersion(SAMLVersion.VERSION_20);

        Subject subject = buildSAMLObject(Subject.class);
        NameID nameID = buildSAMLObject(NameID.class);
        nameID.setValue(nameId);
        nameID.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameID.setSPNameQualifier(this.configuration.getSpAudience());
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        SubjectConfirmationData subjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmationData.setNotBefore(notBefore);
        subjectConfirmationData.setRecipient(destination);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);

        Conditions conditions = buildSAMLObject(Conditions.class);
        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notOnOrAfter);
        AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class);
        Audience audience = buildSAMLObject(Audience.class);
        audience.setURI(this.configuration.getSpAudience());
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class);
        authnStatement.setAuthnInstant(now);
        authnStatement.setSessionIndex("IDX" + UUID.randomUUID());
        authnStatement.setSessionNotOnOrAfter(notOnOrAfter);

        AuthnContext authnContext = buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setURI(authnContextClassRefValue);
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        AuthenticatingAuthority authenticatingAuthority = buildSAMLObject(AuthenticatingAuthority.class);
        authenticatingAuthority.setURI(this.configuration.getIssuerId());
        authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);

        AttributeStatement attributeStatement = buildSAMLObject(AttributeStatement.class);
        List<Attribute> attributes = attributeStatement.getAttributes();
        Map<String, List<SAMLAttribute>> groupedSAMLAttributes = samlAttributes.stream().collect(Collectors.groupingBy(SAMLAttribute::getName));
        XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(XSString.TYPE_NAME);

        groupedSAMLAttributes.forEach((name, values) -> {
            Attribute attribute = buildSAMLObject(Attribute.class);
            attribute.setName(name);
            attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            attribute.getAttributeValues().addAll(values.stream().map(value -> {
                XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                stringValue.setValue(value.getValue());
                return stringValue;
            }).collect(Collectors.toList()));
            attributes.add(attribute);
        });
        assertion.getAttributeStatements().add(attributeStatement);

        this.signObject(assertion, this.signinCredential);
        response.getAssertions().add(assertion);

        this.signObject(response, this.signinCredential);

        Element element = XMLObjectSupport.marshall(response);
        String samlResponse = SerializeSupport.nodeToString(element);

        Map<String, Object> model = new HashMap<>();
        model.put("action", destination);
        String encoded = EncodingUtils.samlEncode(samlResponse, false);
        model.put("SAMLResponse", encoded);
        if (StringUtils.isNotEmpty(relayState)) {
            model.put("RelayState", EncodingUtils.toISO8859_1(StringEscapeUtils.escapeHtml4(relayState)));
        }

        servletResponse.setContentType("text/html");
        servletResponse.setCharacterEncoding(UTF_8.name());

        servletResponse.setHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        servletResponse.setHeader("Pragma", "no-cache");
        servletResponse.setHeader("Expires", "0");

        StringWriter out = new StringWriter();
        velocityEngine.process(POST_BINDING_VM, model, out);
        servletResponse.getWriter().write(out.toString());
    }
}
