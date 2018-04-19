# OpenID Connect Client

## Configure
**generate public/private key pair**
```bash
openssl genrsa -aes256 -out private.pem 2048

openssl rsa -pubout -in private.pem -out public.pem
```

**configure profiles.clj**
```clojure
{:production {:env {:client-id "ID"
                    :client-secret "SECRET"
                    :private-key "private.pem"
                    :private-key-passphrase "PASSPHRASE"}}}
```

## Develop
```bash
lein ring server-headless
```

## Build
```bash
lein with-profile +production ring uberjar
```

## Run
```bash
java -jar target/uberjar/openid-client-0.1.0-SNAPSHOT-standalone.jar
```
