package saml.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.opensaml.security.credential.Credential;

@Getter
public class SAMLServiceProvider {

    private String entityId;
    private String metaDataUrl;
    private Credential credential;
    private String acsLocation;

    public SAMLServiceProvider(String entityId, String metaDataUrl) {
        this.entityId = entityId;
        this.metaDataUrl = metaDataUrl;
    }

    public void setCredential(Credential credential) {
        this.credential = credential;
    }

    public void setAcsLocation(String acsLocation) {
        this.acsLocation = acsLocation;
    }
}
