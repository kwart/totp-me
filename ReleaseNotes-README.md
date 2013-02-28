# Release Notes

## 1.3 (MIDP-1.0)

* Issue#10 support for MIDP-1.0 devices
* Issue#12 this Release notes added 

## 1.2

* Issue#9 fix configuration loading introduced in 1.1
* Issue#11 display application version in the title of the main screen

## 1.1 (contains bug in configuration reading!!!)

* Issue#1 token validity count down progress bar (Gauge) on the main screen
* Issue#2 configurable parameter for time adjustment/correction
* Issue#7 optimization of token generation 

## 1.0

The first release of the totp-me authenticator (uses MIDP-2.0/CLDC-1.1 profile). It supports following configurable parameters:

* secret key
* digest algorithms: SHA-1, SHA-256, SHA-512
* number of token digits
* time step

It also contains a key generator and validation of provided configuration. 