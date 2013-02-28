# TOTP for Java ME

Java ME TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238)) authenticator. It can be used as a token generator for
 * Google's two phase authentication
 * LinOTP authentication
 * other authentication servers which support TOTP

## Download

Download the [latest binaries](https://sourceforge.net/projects/totpme/files/latest/download) 
from the [SourceForge project pages](https://sourceforge.net/projects/totpme/).

If you want to use direct installation to your device, use either [JAD](http://totpme.sourceforge.net/totp-me.jad)
or [JAR](http://totpme.sourceforge.net/totp-me.jar).

## Features

Key (and only) features:

 * configurable parameters
   - secret key (shared)
   - digest algorithm: SHA-1 (default), SHA-256, SHA-512
   - number of token digits (default is 6)
   - time step (default is 30)
   - time correction (default is 0) - advanced feature, the value (may be negative) is added to the device's system time
     during computing a token value
 * input validation
 * key generator with Base32 and HEX output

### Change log

Check [Release notes](https://github.com/kwart/totp-me/blob/master/ReleaseNotes-README.md) for the list of changes.

## Screenshots

![Main screen](http://sourceforge.net/p/totpme/screenshot/totp-me-main.png)
![Options screen](http://sourceforge.net/p/totpme/screenshot/totp-me-options.png)
![Key generator](http://sourceforge.net/p/totpme/screenshot/totp-me-key-generator.png)

## How to install it

Unzip files from the distribution package and copy `totp-me.jar` to your device which supports Java ME.
Some devices may also need the description file `totp-me.jad` to be copied together with the JAR.

## How to use it

You either have already a secret key, then fill it as Base32 encoded String after the start (Options 
form is displayed if no key is set already). Or you can generate the secret key directly by the application and then
fill it as a shared secret in the authentication server.

### Generate new secret key

 * choose your preferred digest algorithm in the `Options` screen (the default is `SHA-1`)
 * choose `Key generator` from the menu - it will switch you to screen for generating the new key
 * use `New key` command to generate a new key, you can use it more times if you are not satisfied with the generated value
 * fill the `HEX` value in you authentication server configuration
 * press `OK` command and you will be switched back to the `Options` screen; confirm your configuration and press `OK` command again
 * if no problem occurs, you are switched to the main application screen, where the `Token` value is already present 
 * _you can synchronize the authentication server with your token now_

## Development

You can simply build the software yourself.

### How to get the sources

You should have [git](http://git-scm.com/) installed

	$ git clone git://github.com/kwart/topt-me.git

or you can download [current sources as a zip file](https://github.com/kwart/totp-me/archive/master.zip)

### How to build it

You need to have [Maven](http://maven.apache.org/) installed

	$ cd totp-me
	$ mvn clean package

### How to run it in the Microemulator

Just use `exec:java` goal after you've successfully built the project 

	$ mvn exec:java

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
