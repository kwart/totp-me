# TOTP for Java ME

Java ME TOTP authenticator - based on gauthj2me project. 

The gauthj2me doesn't work on my Siemens S75, therefor I've created this new project, which works just fine. :-)
 
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

## License

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)