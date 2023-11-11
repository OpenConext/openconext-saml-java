package saml.model;

import lombok.Getter;
import org.opensaml.saml.saml2.core.StatusCode;

@Getter
public enum SAMLStatus {

    SUCCESS(StatusCode.SUCCESS),
    NO_AUTHN_CONTEXT(StatusCode.NO_AUTHN_CONTEXT);

    private final String status;

    SAMLStatus(String s) {
        this.status = s;
    }
}
