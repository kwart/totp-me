# TOTP for Java ME

Java ME TOTP (RFC 6238) authenticator. 

## How to get it

You should have [git](http://git-scm.com/) installed

	$ git clone git://github.com/kwart/topt-me.git

or you can download [current sources as a zip file](https://github.com/kwart/totp-me/archive/master.zip)

## How to build it

You need to have [Maven](http://maven.apache.org/) installed

	$ cd totp-me
	$ mvn clean install -Dwtk.home=[YourWTKinstallationPath]

## How to install it

Copy the produced `totp-me.jar` from the `target` folder to your device.

## How to use it

You either have already a secret key, then fill it as Base32 encoded String after the start (Options 
form is displayed if no key is set already). Or you can generate the secret key directly by the application and then
fill it as a shared secret in the authentication server.

### Generate new secret key

 * choose `Key generator` from the application menu - it will switch you to screen for generating the new key
 * use `New key` command to generate a new key, you can use it more times if you are not satisfied with the generated value
 * fill the `HEX` value in you authentication server configuration
 * press `OK` command and you will be switched to the main screen, where the PIN is already present 
 * _synchronize the authentication server with your token now_

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
