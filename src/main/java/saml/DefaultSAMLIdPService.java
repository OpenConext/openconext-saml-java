package saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.io.IOUtils;
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
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.support.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import saml.crypto.KeyStoreLocator;
import saml.crypto.X509Utilities;
import saml.model.*;
import saml.parser.EncodingUtils;
import saml.parser.OpenSamlVelocityEngine;

import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    private static final Logger LOG = LoggerFactory.getLogger(DefaultSAMLIdPService.class);

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }

    private final OpenSamlVelocityEngine velocityEngine = new OpenSamlVelocityEngine();
    private final BasicParserPool parserPool;
    private final Map<String, SAMLServiceProvider> serviceProviders;
    private final SAMLConfiguration configuration;
    private final Duration skewTime = Duration.ofMinutes(5);
    private final Credential signingCredential;

    @SneakyThrows
    public DefaultSAMLIdPService(SAMLConfiguration configuration) {
        SAMLIdentityProvider identityProvider = configuration.getIdentityProvider();
        String entityId = identityProvider.getEntityId();
        String secret = "secret";
        KeyStore keyStore = KeyStoreLocator.createKeyStore(
                entityId,
                identityProvider.getCertificate(),
                identityProvider.getPrivateKey(),
                secret
        );
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keyStore, Map.of(entityId, secret), UsageType.SIGNING);
        this.signingCredential = resolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(entityId), new UsageCriterion(UsageType.SIGNING)));

        this.parserPool = new BasicParserPool();
        this.configuration = configuration;
        //Must first bootstrap before we can parse service-providers
        bootstrap();
        this.serviceProviders = configuration.getServiceProviders().stream()
                .collect(Collectors.toMap(
                        SAMLServiceProvider::getEntityId,
                        this::resolveSigningCredential
                ));
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

        synchronized (ConfigurationService.class) {
            XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
            registry.setParserPool(parserPool);
        }
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
    private void validateSignature(SignableSAMLObject target, Credential credential) {
        Signature signature = target.getSignature();
        if (signature == null) {
            if (this.configuration.isRequiresSignedAuthnRequest()) {
                throw new SignatureException("Signature element not found.");
            }
        } else {

            SignatureValidator.validate(signature, credential);
        }
    }

    private SAMLServiceProvider getSAMLServiceProvider(String entityId) {
        return this.serviceProviders
                .computeIfAbsent(entityId, key -> this.resolveSigningCredential(this.configuration.getServiceProviders().stream()
                        .filter(samlServiceProvider -> samlServiceProvider.getEntityId().equals(entityId))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Unknown SP entity: " + entityId))));
    }

    @SneakyThrows
    private XMLObject parseXMLObject(String xml, boolean encoded, boolean deflated) {
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
        SAMLServiceProvider serviceProvider = this.getSAMLServiceProvider(authnRequest.getIssuer().getValue());
        if (!serviceProvider.getAcsLocation().equalsIgnoreCase(authnRequest.getAssertionConsumerServiceURL())) {
            throw new IllegalArgumentException(String.format("ACS locations (%s, %s) does not match", serviceProvider.getAcsLocation(),
                    authnRequest.getAssertionConsumerServiceURL()));
        }
        this.validateSignature(authnRequest, serviceProvider.getCredential());
        return authnRequest;
    }

    @SneakyThrows
    public Response parseResponse(String xml) {
        Response response = (Response) parseXMLObject(xml, true, false);
        this.validateSignature(response, this.signingCredential);
        return response;
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
    public void sendResponse(String entityId,
                             String inResponseTo,
                             String nameId,
                             SAMLStatus status,
                             String relayState,
                             String optionalMessage,
                             String authnContextClassRefValue,
                             List<SAMLAttribute> samlAttributes,
                             HttpServletResponse servletResponse) {
        SAMLServiceProvider serviceProvider = this.getSAMLServiceProvider(entityId);

        Instant now = Instant.now();
        Instant notOnOrAfter = now.minus(skewTime);
        Instant notBefore = now.plus(skewTime);
        //Very cumbersome Open-SAML interface, can't be helped
        Response response = buildSAMLObject(Response.class);
        String acsLocation = serviceProvider.getAcsLocation();
        response.setDestination(acsLocation);
        response.setID("RP" + UUID.randomUUID());
        response.setInResponseTo(inResponseTo);
        response.setIssueInstant(now);

        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(this.configuration.getIdentityProvider().getEntityId());
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
        newIssuer.setValue(this.configuration.getIdentityProvider().getEntityId());
        assertion.setIssuer(newIssuer);
        assertion.setID("A" + UUID.randomUUID());
        assertion.setIssueInstant(now);
        assertion.setVersion(SAMLVersion.VERSION_20);

        Subject subject = buildSAMLObject(Subject.class);
        NameID nameID = buildSAMLObject(NameID.class);
        nameID.setValue(nameId);
        nameID.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameID.setSPNameQualifier(entityId);
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        SubjectConfirmationData subjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmationData.setNotBefore(notBefore);
        subjectConfirmationData.setRecipient(acsLocation);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);

        Conditions conditions = buildSAMLObject(Conditions.class);
        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notOnOrAfter);
        AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class);
        Audience audience = buildSAMLObject(Audience.class);
        audience.setURI(entityId);
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
        authenticatingAuthority.setURI(entityId);
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

        this.signObject(assertion, this.signingCredential);
        response.getAssertions().add(assertion);

        this.signObject(response, this.signingCredential);

        Element element = XMLObjectSupport.marshall(response);
        String samlResponse = SerializeSupport.nodeToString(element);

        Map<String, Object> model = new HashMap<>();
        model.put("action", acsLocation);
        String encoded = EncodingUtils.samlEncode(samlResponse);
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

    @SneakyThrows
    @Override
    public String metaData(String singleSignOnServiceURI, String name, String description, String logoURI) {
        EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class);
        entityDescriptor.setEntityID(this.configuration.getIdentityProvider().getEntityId());
        entityDescriptor.setID("M" + UUID.randomUUID());
        entityDescriptor.setValidUntil(Instant.now().plus(2 * 365, ChronoUnit.DAYS));

        IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class);

        Extensions extensions = buildSAMLObject(Extensions.class);
        UIInfo uiInfo = buildSAMLObject(UIInfo.class);
        List.of("en", "nl").forEach(lang -> {
                    Description newDescription = buildSAMLObject(Description.class);
                    newDescription.setValue(description);
                    newDescription.setXMLLang(lang);
                    uiInfo.getDescriptions().add(newDescription);

                    DisplayName newDisplayName = buildSAMLObject(DisplayName.class);
                    newDisplayName.setValue(description);
                    newDisplayName.setXMLLang(lang);
                    uiInfo.getDisplayNames().add(newDisplayName);
                }
        );

        Logo logo = buildSAMLObject(Logo.class);
        logo.setHeight(160);
        logo.setWidth(200);
        logo.setURI(logoURI);
        uiInfo.getLogos().add(logo);

        extensions.getUnknownXMLObjects().add(uiInfo);
        idpssoDescriptor.setExtensions(extensions);

        NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class);
        nameIDFormat.setURI("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        idpssoDescriptor.getNameIDFormats().add(nameIDFormat);

        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        SingleSignOnService singleSignOnService = buildSAMLObject(SingleSignOnService.class);
        singleSignOnService.setLocation(singleSignOnServiceURI);
        singleSignOnService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class);
        encKeyDescriptor.setUse(UsageType.SIGNING);

        encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(this.signingCredential));

        idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        Organization organization = buildSAMLObject(Organization.class);
        List.of("en", "nl").forEach(lang -> {
            OrganizationName organizationName = buildSAMLObject(OrganizationName.class);
            organizationName.setValue(name);
            organizationName.setXMLLang(lang);
            organization.getOrganizationNames().add(organizationName);

            OrganizationDisplayName organizationDisplayName = buildSAMLObject(OrganizationDisplayName.class);
            organizationDisplayName.setValue(name);
            organizationDisplayName.setXMLLang(lang);
            organization.getDisplayNames().add(organizationDisplayName);

            OrganizationURL organizationURL = buildSAMLObject(OrganizationURL.class);
            organizationURL.setURI("https://www.surf.nl/" + (lang.equals("en") ? "en" : ""));
            organizationURL.setXMLLang(lang);
            organization.getURLs().add(organizationURL);
        });
        entityDescriptor.setOrganization(organization);

        this.signObject(entityDescriptor, this.signingCredential);

        Element element = XMLObjectSupport.marshall(entityDescriptor);
        return SerializeSupport.nodeToString(element);
    }

    @SneakyThrows
    @Override
    public SAMLServiceProvider resolveSigningCredential(SAMLServiceProvider serviceProvider) {
        try {
            String xml = IOUtils.toString(new URL(serviceProvider.getMetaDataUrl()), Charset.defaultCharset());
            EntityDescriptor entityDescriptor = (EntityDescriptor) this.parseXMLObject(xml, false, false);
            String acsLocation = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAssertionConsumerServices().get(0).getLocation();
            serviceProvider.setAcsLocation(acsLocation);

            KeyDescriptor keyDescriptor = entityDescriptor.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol")
                    .getKeyDescriptors().stream().filter(kd -> kd.getUse().getValue().equals("signing"))
                    .findFirst().orElseThrow(IllegalArgumentException::new);
            X509Certificate x509Certificate = keyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);

            byte[] certBytes = X509Utilities.getDER(x509Certificate.getValue());
            java.security.cert.X509Certificate certificate = X509Utilities.getCertificate(certBytes);

            Credential signingCredential = new BasicX509Credential(certificate);
            serviceProvider.setCredential(signingCredential);

            return serviceProvider;
        } catch (RuntimeException | IOException e) {
            LOG.error("Error in resolving MetaData for metaData URL:" + serviceProvider.getMetaDataUrl(), e);
            return null;
        }
    }

    @SneakyThrows
    protected String serviceProviderMetaData(SAMLServiceProvider serviceProvider) {
        EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class);
        entityDescriptor.setEntityID(serviceProvider.getEntityId());
        entityDescriptor.setID("M" + UUID.randomUUID());
        entityDescriptor.setValidUntil(Instant.now().plus(10 * 365, ChronoUnit.DAYS));

        SPSSODescriptor spssoDescriptor = buildSAMLObject(SPSSODescriptor.class);

        NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class);
        nameIDFormat.setURI("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        spssoDescriptor.getNameIDFormats().add(nameIDFormat);

        spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        AssertionConsumerService assertionConsumerService = buildSAMLObject(AssertionConsumerService.class);
        assertionConsumerService.setLocation(serviceProvider.getAcsLocation());
        assertionConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class);
        encKeyDescriptor.setUse(UsageType.SIGNING);

        encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(serviceProvider.getCredential()));

        spssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);

        entityDescriptor.getRoleDescriptors().add(spssoDescriptor);
        this.signObject(entityDescriptor, serviceProvider.getCredential());

        Element element = XMLObjectSupport.marshall(entityDescriptor);
        return SerializeSupport.nodeToString(element);
    }

}
