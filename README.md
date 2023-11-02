# openconext-samlidp-libjava

### [Crypto](#crypto)

The myconext application uses a private RSA key and corresponding certificate to sign the SAML requests. We don't want
to provide defaults, so in the integration tests the key / certificate pair is generated on the fly. if you want to
deploy the application in an environment where the certificate needs to be registered with the Service Provider (Proxy)
then you can generate a key pair with the following commands:
```
cd src/main/resources
openssl genrsa -traditional -out saml_idp.pem 2048
openssl req -subj '/O=Organization, CN=SURF/' -key saml_idp.pem -new -x509 -days 365 -out saml_idp.crt
```
Add the key pair to the [application.yml](myconext-server/src/main/resources/application.yml) file:
```
private_key_path: classpath:/myconext.pem
certificate_path: classpath:/myconext.crt
```
If you need to register the public key in EB then issue this command and copy & paste it in Manage for the correct IdP:
```
cat myconext.crt |ghead -n -1 |tail -n +2 | tr -d '\n'; echo
```

