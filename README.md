# openconext-samlidp-libjava

### [Crypto](#crypto)

The saml-idp library uses a private RSA key and corresponding certificate to sign the SAML requests. We don't want
to provide defaults, so in the integration tests the key / certificate pair is generated on the fly. if you want to
deploy the application in an environment where the certificate needs to be registered with the Service Provider (Proxy)
then you can generate a key pair with the following commands:
```
cd src/main/resources
openssl genrsa -traditional -out saml_idp.pem 2048
openssl req -subj '/O=Organization, CN=SURF/' -key saml_idp.pem -new -x509 -days 365 -out saml_idp.crt
```
Instantiate the `DefaultSAMLIdPService` with:
```
private_key_path: classpath:/saml_idp.pem
certificate_path: classpath:/saml_idp.crt
```
If you need to register the public key in EB then issue this command and copy & paste it in Manage for the correct IdP:
```
cat saml_idp.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

