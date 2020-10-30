# ucs_client_v0.0.1

This is the main repository for the UCS client pre-alpha version.

## Table of contents
* [What is UCS](#what-is-ucs)
* [Technologies used](#technologies-used)
* [How to install on LINUX](#how-to-install-on-linux)
* [How to install on ANDROID](#how-to-install-on-android)
* [Community](#community)

## What is UCS
The [Universal Credit System](https://www.universal-credit-system.org) offers a **free digital basic income** for everybody. Every day a number of universal credit coins will be granted to all users of the universal credit system client. Purpose of this document is to show how you can setup and run the client.

## Technologies used
The UCS client was written as **linux basic shell** script. The following has been used:
* Rasbperry Pi Model B (Raspberry Pi Model B V1.2)
* Raspbian Buster 10 (Raspbian GNU/Linux 10 (buster))

Although the script was written on a Raspberry Pi 3 with Raspbian, you can run it on any machine if you follow the installation instructions!

The script itself uses below programs:
* bc		used for floating point calculations
* wget		used to fetch certificate files of TSA from Internet
* curl		used to send query to TSA and request response
* shasum	used to hash files
* openssl	used for TSA stamp verification
* gpg		used for transaction signing
* dialog	used for GUI
* git		used only to fetch the sourcecode from GitHub

## How to install on LINUX
**Assuming you use APT as packaging tool, the `apt-get install` command is used. PLEASE NOTE, THAT IF YOU ARE NOT USING "APT" AS PACKAGING TOOL THE COMMAND FOR INSTALLING A PACKAGE MIGHT BE DIFFERENT FROM THE BELOW USED `apt-get install`.THIS MEANS YOU HAVE TO CHANGE THE COMMAND `apt-get install` TO THE COMMAND THAT YOUR PACKAGING TOOL USES!**

To install the programs that are required for UCS just type the following into command prompt:
```
sudo apt-get install bc
sudo apt-get install wget
sudo apt-get install curl
sudo apt-get install perl
sudo apt-get install gnupg2
sudo apt-get install openssl
sudo apt-get install dialog
sudo apt-get install git
```

Now create a directory with `mkdir` wherever you want and step into this directory with `cd`:
```
mkdir ucs
cd ucs
```

Now clone the GitHub repository of UCS, in this case latest version is `ucs_client_v0.0.1`:
```
git clone https://github.com/universal-credit-system/ucs_client_v0.0.1
```

Step into directory that contains the cloned repository:
```
cd ucs_client_v0.0.1/
```

You may need to change permissions to make the install script executable:
```
chmod +x install.sh
```

Now you can execute the install.sh script that creates required folders:
```
./install.sh
```

Once you have installed ucs you can run the UCS Client just like you would executed any other script:
```
./ucs_client.sh
```

## How to install on ANDROID
**If you would like to run the script on ANDROID, you need a shell that you can access from where you can execute the script. We suggest that you use TERMUX for that, but you can use any other app that provides you a equal functionality. You can find the TERMUX on the Google PlayStore. If you decide to use TERMUX you can use below commands for installation. PLEASE NOTE, THAT IF YOU ARE NOT USING TERMUX THE COMMAND FOR INSTALLING A PACKAGE MIGHT BE DIFFERENT FROM THE BELOW USED `pkginstall`. THIS MEANS YOU HAVE TO CHANGE THE COMMAND `pkginstall` TO THE COMMAND THAT YOUR PACKAGING TOOL USES!**

To install the programs that are required for UCS just type the following into command prompt:
```
pkginstall bc
pkginstall wget
pkginstall curl
pkginstall perl
pkginstall gnupg2
pkginstall openssl
pkginstall dialog
pkginstall git
```

Now create a directory with `mkdir` wherever you want and step into this directory with `cd`:
```
mkdir ucs
cd ucs
```

Now clone the GitHub repository of UCS, in this case latest version is `ucs_client_v0.0.1`:
```
git clone https://github.com/universal-credit-system/ucs_client_v0.0.1
```

Step into directory that contains the cloned repository:
```
cd ucs_client_v0.0.1/
```

You may need to change permissions to make the install script executable:
```
chmod +x install.sh
```

Now you can execute the install.sh script that creates required folders:
```
./install.sh
```

Once you have installed ucs you can run the UCS Client just like you would executed any other script:
```
./ucs_client.sh
```

## Community
**We have set up a [Forum](https://forum.universal-credit-system.org) for the community were they can meet and discuss things related to the Universal Credit System. We encourage you to join the community think tank and contribute to this project. If you have any questions, suggestions or critics you are welcome to post it on the forum.**

**NOW HAVE FUN!**
