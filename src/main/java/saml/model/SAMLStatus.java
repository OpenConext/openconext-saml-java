package saml.model;

import lombok.Getter;

@Getter
public enum SAMLStatus {

    SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
    NO_AUTHN_CONTEXT("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext");

    private final String status;

    SAMLStatus(String s) {
        this.status = s;
    }
}
