package saml.model;


import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SAMLConfiguration {

    private SAMLIdentityProvider identityProvider;
    private List<SAMLServiceProvider> serviceProviders;
    private boolean requiresSignedAuthnRequest;
    private boolean requiresSignedResponse;

    public SAMLConfiguration(SAMLIdentityProvider identityProvider, List<SAMLServiceProvider> serviceProviders, boolean requiresSignedAuthnRequest) {
        this(identityProvider, serviceProviders, requiresSignedAuthnRequest, true);
    }

}
