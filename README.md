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

	$ git clone git://github.com/kwart/totp-me.git

or you can download [current sources as a zip file](https://github.com/kwart/totp-me/archive/master.zip)

### How to build it

Download `lcrypto-j2me-xxx.zip` ("xxx" - current version of lcrypto, for example "lcrypto-j2me-156.zip") 
from the [Bouncy Castle website](https://www.bouncycastle.org/latest_releases.html) 
and extract it to new `lcrypto-j2me` folder.

Copy folder `totp-me/for-lcrypto-j2me/` contents to `lcrypto-j2me` folder.

Correct the lcrypto-j2me version number in `pom.xml` files
* `lcrypto-j2me/pom.xml`: find `<version>1.56</version>`
* `totp-me/pom.xml`: find `<artifactId>lcrypto-j2me</artifactId>` .. `<version>1.56</version>`

Install [Maven](https://maven.apache.org).

Build and install lcrypto-j2me

	$ cd lcrypto-j2me
	$ mvn clean install

Build totp-me

	$ cd ../totp-me
	$ mvn clean package

This default build uses Microemulator API implementation to simplify the build process, but it's only MIDP-2.0
implementation. To be sure the source code is __MIDP-1.0 compatible__, you should install Oracle WTK and provide
path to it to Maven as `wtk.home` system property

	$ mvn clean package -Dwtk.home=/opt/WTK2.5.2

### How to run it in the Microemulator

Just use `exec:java` goal after you've successfully built the project

	$ mvn exec:java

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
