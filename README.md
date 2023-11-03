# openconext-samlidp-libjava
[![JAVA CI](https://github.com/OpenConext/openconext-samlidp-libjava/actions/workflows/actions.yml/badge.svg)](https://github.com/OpenConext/openconext-samlidp-libjava/actions/workflows/actions.yml)
[![codecov.io](https://codecov.io/github/OpenConext/openconext-samlidp-libjava/coverage.svg)](https://codecov.io/github/OpenConext/openconext-samlidp-libjava)

### [Usage](#usage)

The main interface of the SAML IdP library is `SAMLIdPService`. 
It provides the following functionality
- parsing SAML to an `org.opensaml.saml.saml2.core.AuthnRequest`
- sending SAML response back to the Service Provider

### [Crypto](#crypto)

The saml-idp library uses a private RSA key and corresponding certificate to sign the SAML requests. If you want to
deploy the application in an environment where the certificate needs to be registered with the Service Provider (Proxy)
then you can generate a key pair with the following commands:
```
openssl genrsa -traditional -out saml_idp.pem 2048
openssl req -subj '/O=Organization, CN=SURF/' -key saml_idp.pem -new -x509 -days 365 -out saml_idp.crt
```
If you need to register the public key in EB then issue this command and copy & paste it in Manage for the correct IdP:
```
cat saml_idp.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

