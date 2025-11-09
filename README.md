# iam_cas_client
Spring boot application that serves as a CAS client.

## Configuration
- application.properties:

```

spring.application.name=casclient

# --- Spring Boot Client Configuration ---
server.port=8451

# The base URL of your application (The CAS Client) is now HTTPS
cas.client.serviceUrl=https://localhost:8451/login/cas

# --- CAS Server Configuration (Assuming this remains the same) ---
cas.server.urlPrefix=https://localhost:8443/cas
cas.server.loginUrl=${cas.server.urlPrefix}/login
cas.server.validationUrl=${cas.server.urlPrefix}
cas.client.hostUrl=https://localhost:8451
cas.validation-type=CAS

# --- HTTPS Configuration for Spring Boot ---
# Note: You MUST provide a keystore file for this to work.
# Replace with your actual keystore file path and password.
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12

```

- Generate key

```
keytool -genkeypair -alias spring-boot-app -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650
```

- Trust Development Cert of CAS Server

```
keytool -importcert -alias localcas -keystore "$JAVA_HOME/lib/security/cacerts" -file ~/cas-server.cer

keytool -importcert -alias localcas -keystore "/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/lib/security/cacerts" -file ~/Download/cas.example.org.pem
```

- Register service on Apereo CAS server

```
{
  "@class": "org.apereo.cas.services.RegexRegisteredService",
  "serviceId": "^https://localhost:8451/.*",
  "name": "SpringBootApp",
  "id": 1000,
  "description": "My Spring Boot CAS Client",
  "evaluationOrder": 1,
  "accessStrategy": {
    "@class": "org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy",
    "enabled": true,
    "ssoEnabled": true
  },
  "responseType": "REDIRECT", 
  "responseMode": "FORM_POST",
  "logoutType": "REDIRECT",
  "properties": {
    "@class": "java.util.HashMap",
    "registeredServiceResponseHeaderPolicy": {
      "@class": "org.apereo.cas.services.RegisteredServiceResponseHeaderPolicy",
      "contentSecurityPolicyHeader": "default-src 'self'",
      "xFrameOptions": "SAMEORIGIN",
      "xContentTypeOptions": "nosniff",
      "xssProtection": "1; mode=block"
    }
  }
}
```
- Test/Run
 -- https://localhost:8451/secured