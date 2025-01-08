# openconext-samlidp-libjava
[![JAVA CI](https://github.com/OpenConext/openconext-samlidp-libjava/actions/workflows/actions.yml/badge.svg)](https://github.com/OpenConext/openconext-samlidp-libjava/actions/workflows/actions.yml)
![Coverage](.github/badges/jacoco.svg)
![Branches](.github/badges/branches.svg)

### [Dependencies](#dependencies)

The 3.0.0. release now uses the latest `tomcat-embed-core` which is compliant with Spring Security 6. All references
to `javax.servlet.http.HttpServletResponse` have been replaced with `jakarta.servlet.http.HttpServletResponse`.

### [Usage](#usage)

The main interface of the SAML library is `SAMLService`. 
It provides the following functionality for service / identity providers:
- create an (optionally signed) `org.opensaml.saml.saml2.core.AuthnRequest`
- construct the SP metadata
- parsing SAML to an `org.opensaml.saml.saml2.core.AuthnRequest`
- sending SAML response back to the Service Provider
- construct the IdP metadata
- resolve the SigningCredential of a Service Provider based on the metadata URL

### [Crypto](#crypto)

The saml-java library uses a private RSA key and corresponding certificate to sign the SAML requests. If you want to
deploy the application in an environment where the certificate needs to be registered with the Service Provider (Proxy)
then you can generate a key pair with the following commands:
```
openssl genrsa -traditional -out saml_idp.pem 2048
openssl req -subj '/O=Organization, CN=SURF/' -key saml_idp.pem -new -x509 -days 365 -out saml_idp.crt
```
If you need to register the IdP public key somewhere then issue this command and copy & paste it for the correct IdP:
```
cat saml_idp.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

