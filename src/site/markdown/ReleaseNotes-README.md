<head>
    <title>Release Notes</title>
</head>
# Release Notes

TOTP authenticator for Java ME enabled devices. It's an implementation of the RFC 6238 (TOTP: Time-Based One-Time Password Algorithm).

## 1.8

* Issue#21 Added a confirmation screen for profile removing
* Issue#22 Profiles sorted alphabetically in the list

## 1.7

* Issue#20 allow shorter or longer keys to be used 
* Issue#19 profiles handling code improved

## 1.6

* Issue#17 wrong constant used for reading month value when creating a profile

## 1.5

* Issue#16 fixed profiles removing

## 1.4

* Issue#4 support for multiple profiles/accounts

## 1.3

* Issue#10 support for MIDP-1.0 devices
* Issue#12 this Release notes added
* Issue#13 Include a baseDirectory in the released files

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