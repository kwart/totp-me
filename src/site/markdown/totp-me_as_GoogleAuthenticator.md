# Tutorial: totp-me as Google Authenticator - 2 step verification

*Have you ever wondered, how to enable Google 2 phase authentication on your older, not so smart, but Java enabled phone?*

This tutorial drives you step-by-step by the process, using **totp-me** Java ME application.

1. Go to http://www.google.com/landing/2step/  
![Screenshot](images/google-authenticator/010.png)

1. Log into your Google account  
![Screenshot](images/google-authenticator/020.png)

1. Click `Start setup`  
![Screenshot](images/google-authenticator/030.png)

1. Complete 4 steps
	2. Provide info about your mobile phone  
	![Screenshot](images/google-authenticator/040.png)
	2. You receive an SMS with verification code from Google - rewrite the code to the verification field  
	![Screenshot](images/google-authenticator/050.png)
	2. Check or uncheck `Trust this computer` field  
	![Screenshot](images/google-authenticator/060.png)
	2. and click `Continue`  
	![Screenshot](images/google-authenticator/070.png)

1. Follow `Android` link in Mobile applications section  
![Screenshot](images/google-authenticator/080.png)

1. Click on the `Can't scan the barcode?`  
![Screenshot](images/google-authenticator/090.png)

1. You will see newly generated secret key (Base32 encoded)  
![Screenshot](images/google-authenticator/100.png)

1. Start the **totp-me** application on your phone  
![Screenshot](images/google-authenticator/110.png)

1. Fill the Google generated key in `Secret key (Base32)` text input, you can also change the `Profile name`, then
confirm the options by using `OK` command  
![Screenshot](images/google-authenticator/130.png)

1. You will see newly generated key  
![Screenshot](images/google-authenticator/140.png)

1. Fill the **totp-me** generated key in Google's `Code` field and click `Verify and Save`   
![Screenshot](images/google-authenticator/150.png)

1. If the steps were finished succesfully, then you should see this information  
![Screenshot](images/google-authenticator/160.png)

1. You'll be asked for a new login ...  
![Screenshot](images/google-authenticator/170.png)

1. ... and confirmation, the settings are up-to-date (use `Looks good` button, if you're satisfied)  
![Screenshot](images/google-authenticator/180.png)

1. *(Optional)* Print or backup some one-time codes (e.g. useful when you loose your phone or if it's discharged)
	2. Follow `Show backup codes` link  
	![Screenshot](images/google-authenticator/190.png)
	2. Print or store the codes  
	![Screenshot](images/google-authenticator/200.png)

1. *(Optional)*  Try to login to your Google account from another computer or browser
	2. Let's try [GMail](https://mail.google.com/) for instance  
	![Screenshot](images/google-authenticator/210.png)
	2. You should be asked for verification code. Run **totp-me**, and fill the newly generated one in `Enter code:` field  
	![Screenshot](images/google-authenticator/220.png)
	2. It's all, you've completed 2-step verification settings using **totp-me**  
	![Screenshot](images/google-authenticator/230.png)

## That's all
Congratulations, You, brave reader! You have 2-step verification enabled now. 