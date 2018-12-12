# TOTP for Java ME

Java ME TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238)) authenticator. It can be used as a token generator for
 * Google's two phase authentication
 * LinOTP authentication
 * other authentication servers which support TOTP

## Project web

URL: http://totpme.sourceforge.net

## Development

You can simply build the software yourself.

### How to get the sources

You should have [git](http://git-scm.com/) installed

```bash
git clone git://github.com/kwart/totp-me.git
```

or you can download [current sources as a zip file](https://github.com/kwart/totp-me/archive/master.zip)

### How to build it

Install [Maven](https://maven.apache.org).

Download `lcrypto-j2me-xxx` archive ("xxx" - current version of lcrypto, for example "lcrypto-j2me-160.tar.gz") 
from the [Bouncy Castle website](https://www.bouncycastle.org/latest_releases.html), 
extract it and install the classes as a JAR file to your local repository:

```bash
wget https://www.bouncycastle.org/download/lcrypto-j2me-160.tar.gz
tar xf ./lcrypto-j2me-160.tar.gz
mvn install:install-file -Dfile=lcrypto-j2me-160/zips/cldc_bccore_classes.zip -DgroupId=org.bouncycastle -DartifactId=lcrypto-j2me -Dversion=1.60 -Dpackaging=jar
```

Build the `totp-me` and feed it with `lcrypto` version from the previous step:

```bash
mvn clean package -Dlcrypto.version=1.60
```

This default build uses Microemulator API implementation to simplify the build process, but it's only MIDP-2.0
implementation. To be sure the source code is __MIDP-1.0 compatible__, you should install Oracle WTK and provide
path to it to Maven as `wtk.home` system property

```bash
mvn clean package -Dwtk.home=/opt/WTK2.5.2
```

### How to run it in the Microemulator

Just use `exec:java` goal after you've successfully built the project
(provide lcrypto version if needed).

```bash
mvn exec:java -Dlcrypto.version=1.60
```

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
