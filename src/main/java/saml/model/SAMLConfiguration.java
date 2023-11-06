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
}
