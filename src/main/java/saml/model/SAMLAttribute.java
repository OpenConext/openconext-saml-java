package saml.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SAMLAttribute {

    private String name;
    private String value;

}
