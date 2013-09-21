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

You need to have [Maven](http://maven.apache.org/) installed

	$ cd totp-me
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
