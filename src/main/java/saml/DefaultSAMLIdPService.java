package saml;

import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.schema.*;
import org.opensaml.core.xml.schema.impl.*;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import saml.crypto.KeyStoreLocator;
import saml.crypto.X509Utilities;
import saml.model.Attribute;
import saml.model.SAMLConfiguration;
import saml.model.Status;
import saml.parser.EncodingUtils;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;

public class DefaultSAMLIdPService implements SAMLIdPService {

    static {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }

    private static final Logger LOG = LoggerFactory.getLogger(DefaultSAMLIdPService.class);

    private final BasicParserPool parserPool;
    private final X509Credential signatureValidationCredential;
    private final SAMLConfiguration configuration;

    @SneakyThrows
    public DefaultSAMLIdPService(SAMLConfiguration configuration) {
        this.signatureValidationCredential = loadPublicKey(configuration.getSpCertificate());
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


    public MarshallerFactory getMarshallerFactory() {
        return XMLObjectProviderRegistrySupport.getMarshallerFactory();
    }

    public UnmarshallerFactory getUnmarshallerFactory() {
        return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    }

    public EntityDescriptor getEntityDescriptor() {
        XMLObjectBuilderFactory builderFactory = getBuilderFactory();
        SAMLObjectBuilder<EntityDescriptor> builder =
                (SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor
                        .DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public SPSSODescriptor getSPSSODescriptor() {
        SAMLObjectBuilder<SPSSODescriptor> builder =
                (SAMLObjectBuilder<SPSSODescriptor>) getBuilderFactory().getBuilder(SPSSODescriptor
                        .DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public IDPSSODescriptor getIDPSSODescriptor() {
        SAMLObjectBuilder<IDPSSODescriptor> builder =
                (SAMLObjectBuilder<IDPSSODescriptor>) getBuilderFactory().getBuilder(IDPSSODescriptor
                        .DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public Extensions getMetadataExtensions() {
        SAMLObjectBuilder<Extensions> builder =
                (SAMLObjectBuilder<Extensions>) getBuilderFactory().getBuilder(Extensions.DEFAULT_ELEMENT_NAME);
        return builder.buildObject();
    }

    public XMLObjectBuilderFactory getBuilderFactory() {
        return XMLObjectProviderRegistrySupport.getBuilderFactory();
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


    public Credential getCredential(KeyStoreCredentialResolver resolver) {
        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIdCriterion criteria = new EntityIdCriterion("key");
            cs.add(criteria);
            return resolver.resolveSingle(cs);
        } catch (ResolverException e) {
            throw new RuntimeException("Can't obtain SP private key", e);
        }
    }

    public KeyStoreCredentialResolver getCredentialsResolver() {
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQRsCf6qU0DYkoFIJUhNlMxJFKMPsEvK+u3rcaBIZcyWX4Cv5OU3xtcCAg6mqRwMRFYFDNdGgR0XLTaHAOcJpR7cXYnYc0Wa6Kh8KSstgZrCl+WdqCtuUS6bMrrAdSq6HpoAPwo1JyOqyC9ccRZ9ysjhYdWQS1ELSjUHjEuxxRoEgwKfrF7kxbo89dixQ7oF9E9CgeWtftJfMtDxGtMhmtaIurHjjcfOPWR8TND0b1Lp1pLkzPn6GdI2aRWqV3tNsljKoXP9omDInhP9xrzoLiXISbekfnLrfFQW+rmylCBiu6ZqKv0weg1V6b7B6rAyV3nIcXInLuKXSlQx0nnPOdAgMBAAECggEAOrAlKSqyYIeL5XpZ+zzwCly9X/2LThtpGcpyJ+esgMrTa+CVJjcKMcBNnVjQrL93zuDEBBDQHm05gO7F3JvIMFviyxYgehTnROvaXQH+OMW1b4AcPYcR55Foxl6UNaxdVHqdgZpT6hI0eDaPYI02tnzXKG/kDq1laTuMvErJQQp6Cd611yyAhBvpX1ibpAYvex10sfTkj0GRKmOrGqwVXibN29szaRei7Xeg/RStdVBgrYJoR5/4++dkGapa27oRdOh4VJUChRfXuJtH6pyxC7uay1fMRcmo2u6NcWAT6qMOvxLcuesnNFrbSlPoZaxWNiZRX/SVqeieyRAA0WS7IQKBgQDoywh4DkdL+SPrkA/sB0rOQF3kJjlzWibk9OM17In1P+obQk37kSRYKfBvsk48VWdG1fN33Up05Pxe+f36F//AZ8mp7uTmBtd6CAoR/005WxwkCSihF6LaDiB3VtxlpcfRA/TUZ10PMud43w0AeG30AG0KpCokfIiY87OpyTjJWQKBgQDlCgsgZ9rL3Wm7FbEDZ4f2uTB5rlT0Vz80paV0OOJdUQECrZW1PjemQpqIJocr8yoNupkrZKPSi4mbNoMFF1wXIydOjLq6iQ6KWIKRdsvmeXL++tWg6TiD8nDpBxuKzjRhwMcQN2lakb/SusoXnmG8qq12PCFUvpbhoZRqRPWv5QKBgQC8jUasxxPka0U21RawXC+w4t2pn3RFBC4goGEwGgibxkr+DTRQoHzJlB6Uud04bQwbicuLuIdIKvhmjSGzYaDa3LWwmDh6P+xjgQN3FEweOreOUITCBfz3lR2iy430HtS7bPLu31G2r8pgUnmbee/FBFtNlS41I1EYYbuRt9Pw8QKBgD6aPSpRWKtqTHD3X9e3X6FfQtGvhcb3Ze5E7HFU7wJklqsduRK9+8X05HocVcv8fd0cyKrkqiZtP2JuRueIWAJ2+FJvAsbjmVbVFHMgDmFjhrwM4YFG3cyq4pO+/pc0/3pMj9xt2N0Jg23c4koMX1iLKjhr/QxFv8XSPVfCm4jFAoGALfejdx4PpFgTWpbm5ZWRxukhZRhmfCIAWifYeJbsGTB5y7bheVxKmTpP9mKEqGL+gh3cLVPcZ557HWpc4d6NetdyrHffEhWULh4NWYDKC5BRCr9HjLKydBUQUMCFeJs3XZQTtN+CZORcuaI2ISH2QvfYki9ns4ujeH8OjzfHpvI=";
        String certificate = "MIIDEzCCAfugAwIBAgIJAKoK/heBjcOYMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNVBAoMFU9yZ2FuaXphdGlvbiwgQ049T0lEQzAeFw0xNTExMTExMDEyMTVaFw0yNTExMTAxMDEyMTVaMCAxHjAcBgNVBAoMFU9yZ2FuaXphdGlvbiwgQ049T0lEQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANBGwJ/qpTQNiSgUglSE2UzEkUow+wS8r67etxoEhlzJZfgK/k5TfG1wICDqapHAxEVgUM10aBHRctNocA5wmlHtxdidhzRZroqHwpKy2BmsKX5Z2oK25RLpsyusB1KroemgA/CjUnI6rIL1xxFn3KyOFh1ZBLUQtKNQeMS7HFGgSDAp+sXuTFujz12LFDugX0T0KB5a1+0l8y0PEa0yGa1oi6seONx849ZHxM0PRvUunWkuTM+foZ0jZpFapXe02yWMqhc/2iYMieE/3GvOguJchJt6R+cut8VBb6ubKUIGK7pmoq/TB6DVXpvsHqsDJXechxcicu4pdKVDHSec850CAwEAAaNQME4wHQYDVR0OBBYEFK7RqjoodSYVXGTVEdLf3kJflP/sMB8GA1UdIwQYMBaAFK7RqjoodSYVXGTVEdLf3kJflP/sMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBADNZkxlFXh4F45muCbnQd+WmaXlGvb9tkUyAIxVL8AIu8J18F420vpnGpoUAE+Hy3evBmp2nkrFAgmr055fAjpHeZFgDZBAPCwYd3TNMDeSyMta3Ka+oS7GRFDePkMEm+kH4/rITNKUF1sOvWBTSowk9TudEDyFqgGntcdu/l/zRxvx33y3LMG5USD0x4X4IKjRrRN1BbcKgi8dq10C3jdqNancTuPoqT3WWzRvVtB/q34B7F74/6JzgEoOCEHufBMp4ZFu54P0yEGtWfTwTzuoZobrChVVBt4w/XZagrRtUCDNwRpHNbpjxYudbqLqpi1MQpV9oht/BpTHVJG2i0ro=";
        String passphrase = "secret";
        String idpEntityId = "http://entity.id";
        KeyStore keyStore = KeyStoreLocator.createKeyStore("secret");
        KeyStoreLocator.addPrivateKey(keyStore, idpEntityId, privateKey, certificate, passphrase);

        Map<String, String> passwords = Map.of(idpEntityId, passphrase);
        return new KeyStoreCredentialResolver(keyStore, passwords, UsageType.SIGNING);
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

    @Override
    @SneakyThrows
    public AuthnRequest parseAuthnRequest(String xml, boolean encoded, boolean deflated) {
        if (encoded) {
            xml = EncodingUtils.samlDecode(xml, deflated);
        }
        Document document = this.parserPool.parse(new ByteArrayInputStream(xml.getBytes()));
        Element element = document.getDocumentElement();
        AuthnRequest authnRequest = (AuthnRequest) getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);

        this.validateSignature(authnRequest);

        return authnRequest;
    }

    protected List<Object> getJavaValues(List<XMLObject> attributeValues) {
        List<Object> result = new LinkedList<>();
        for (XMLObject o : ofNullable(attributeValues).orElse(emptyList())) {
            if (o == null) {

            } else if (o instanceof XSString) {
                result.add(((XSString) o).getValue());
            } else if (o instanceof XSURI) {
                try {
                    result.add(new URI(((XSURI) o).getURI()));
                } catch (URISyntaxException e) {
                    result.add(((XSURI) o).getURI());
                }
            } else if (o instanceof XSBoolean) {
                result.add(((XSBoolean) o).getValue().getValue());
            } else if (o instanceof XSDateTime) {
                result.add(((XSDateTime) o).getValue());
            } else if (o instanceof XSInteger) {
                result.add(((XSInteger) o).getValue());
            } else if (o instanceof XSAny) {
                XSAny xsAny = (XSAny) o;
                String textContent = xsAny.getTextContent();
                if (StringUtils.isEmpty(textContent) && xsAny.getUnknownXMLObjects() != null && !xsAny.getUnknownXMLObjects().isEmpty()) {
                    XMLObject xmlObject = xsAny.getUnknownXMLObjects().get(0);
                    if (xmlObject instanceof NameIDType) {
                        result.add(((NameIDType) xmlObject).getValue());
                    }
                } else {
                    result.add(textContent);
                }
            } else {
                //we don't know the type.
                result.add(o);
            }
        }

        return result;
    }

    protected XMLObject objectToXmlObject(Object o) {
        if (o == null) {
            return null;
        } else if (o instanceof String) {
            XSStringBuilder builder = (XSStringBuilder) getBuilderFactory().getBuilder(XSString.TYPE_NAME);
            XSString s = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            s.setValue((String) o);
            return s;
        } else if (o instanceof URI || o instanceof URL) {
            XSURIBuilder builder = (XSURIBuilder) getBuilderFactory().getBuilder(XSURI.TYPE_NAME);
            XSURI uri = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSURI.TYPE_NAME);
            uri.setURI(o.toString());
            return uri;
        } else if (o instanceof Boolean) {
            XSBooleanBuilder builder = (XSBooleanBuilder) getBuilderFactory().getBuilder(XSBoolean.TYPE_NAME);
            XSBoolean b = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSBoolean.TYPE_NAME);
            XSBooleanValue v = XSBooleanValue.valueOf(o.toString());
            b.setValue(v);
            return b;
        } else if (o instanceof Instant) {
            XSDateTimeBuilder builder = (XSDateTimeBuilder) getBuilderFactory().getBuilder(XSDateTime.TYPE_NAME);
            XSDateTime dt = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
            dt.setValue((Instant) o);
            return dt;
        } else if (o instanceof Integer) {
            XSIntegerBuilder builder = (XSIntegerBuilder) getBuilderFactory().getBuilder(XSInteger.TYPE_NAME);
            XSInteger i = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
            i.setValue(((Integer) o).intValue());
            return i;
        } else {
            XSAnyBuilder builder = (XSAnyBuilder) getBuilderFactory().getBuilder(XSAny.TYPE_NAME);
            XSAny any = builder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
            any.setTextContent(o.toString());
            return any;
        }
    }


    private static X509Credential loadPublicKey(String certificate) throws Exception {
        byte[] certBytes = X509Utilities.getDER(certificate);
        return new BasicX509Credential(X509Utilities.getCertificate(certBytes));
    }


    protected String xmlObjectToString(XMLObject o) {
        String toMatch = null;
        if (o instanceof XSString) {
            toMatch = ((XSString) o).getValue();
        } else if (o instanceof XSURI) {
            toMatch = ((XSURI) o).getURI();
        } else if (o instanceof XSBoolean) {
            toMatch = ((XSBoolean) o).getValue().getValue() ? "1" : "0";
        } else if (o instanceof XSInteger) {
            toMatch = ((XSInteger) o).getValue().toString();
        } else if (o instanceof XSDateTime) {
            Instant value = ((XSDateTime) o).getValue();
            if (value != null) {
                toMatch = value.toString();
            }
        } else if (o instanceof XSBase64Binary) {
            toMatch = ((XSBase64Binary) o).getValue();
        } else if (o instanceof XSAny) {
            final XSAny wc = (XSAny) o;
            if (wc.getUnknownAttributes().isEmpty() && wc.getUnknownXMLObjects().isEmpty()) {
                toMatch = wc.getTextContent();
            }
        }
        if (toMatch != null) {
            return toMatch;
        }
        return null;
    }

    public KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
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
        signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);

        SignatureSupport.prepareSignatureParams(signature, signingParameters);
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable);
        marshaller.marshall(signable);
        Signer.signObject(signature);
    }

    @SneakyThrows
    private <T> T buildSAMLObject(final Class<T> clazz) {
        QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        return (T) getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
    }

    @Override
    public void sendResponse(String inResponseTo, Status status, String optionalMessage, List<Attribute> attributes) {

    }
}
