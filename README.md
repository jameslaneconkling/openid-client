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
The bouncycastle signing library [cannot be included in the uberjar build](https://github.com/funcool/buddy-core/issues/43).
Download `bcpkix-jdk15on-159.jar` and `bcprov-jdk15on-159.jar` from [here](https://www.bouncycastle.org/latest_releases.html) and add to the classpath when running the app.

```bash
java -cp target/uberjar/openid-client-0.1.0-SNAPSHOT-standalone.jar:bcpkix-jdk15on-159.jar:bcprov-jdk15on-159.jar openid_client.core.main
```
