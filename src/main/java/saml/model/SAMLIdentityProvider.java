package saml.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SAMLIdentityProvider {

    private String certificate;
    private String privateKey;
    private String entityId;

}
