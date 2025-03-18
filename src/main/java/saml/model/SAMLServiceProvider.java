package saml.model;

import lombok.Getter;
import lombok.Setter;
import org.opensaml.security.credential.Credential;

@Getter
public class SAMLServiceProvider {

    private final String entityId;
    private final String metaDataUrl;
    @Setter
    private Credential credential;
    @Setter
    private String acsLocation;

    public SAMLServiceProvider(String entityId, String metaDataUrl) {
        this.entityId = entityId;
        this.metaDataUrl = metaDataUrl;
    }

}
