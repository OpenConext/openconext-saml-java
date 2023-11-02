package saml.model;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SAMLConfiguration {

    private String idpCertificate;
    private String idpPrivateKey;
    private String entityId;
    private String spCertificate;
    private boolean requiresSignedAuthnRequest;

}
