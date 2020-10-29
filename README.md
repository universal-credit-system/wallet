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

## How to install on LINUX
As already written in "Technologies used" the script was written on a Raspberry Pi 3 with Raspbian, but you can run it on any machine! You just have to make sure you have the following programs installed before running the UCS Client:
* bc		(used for floating point calculations)
* wget		(used to fetch certificate files of TSA from Internet)
* curl		(used to send query to TSA and request response)
* shasum	(used to hash files)
* openssl	(used for TSA stamp verification)
* gpg		(used for transaction signing)
* dialog	(used for GUI)
* git		(used only to fetch the files from GitHub)


To install these programs just type the following into command prompt:
```
$ sudo apt-get install bc
$ sudo apt-get install wget
$ sudo apt-get install curl
$ sudo apt-get install perl
$ sudo apt-get install gnupg2
$ sudo apt-get install openssl
$ sudo apt-get install dialog
$ sudo apt-get install git
```

Now create a directory with `mkdir` wherever you want and step into this directory with `cd`:
```
$ mkdir ucs
$ cd ucs
```

Now clone the GitHub repository of UCS, in this case latest version is `ucs_client_v0.0.1`:
```
$ git clone https://github.com/universal-credit-system/ucs_client_v0.0.1
```

Step into directory that contains the cloned repository:
```
$ cd ucs_client_v0.0.1/
```

You may need to change permissions to make the install script and the ucs client script executable:
```
$ chmod +x install.sh
$ chmod +x ucs_client.sh
```

Now you can execute the install.sh script that creates required folders:
```
$ ./install.sh
```

Once you have installed ucs you can run the UCS Client just like you would executed any other script:
```
$ ./ucs_client.sh
```

## How to install on ANDROID
**IF YOU WOULD LIKE TO RUN THE UCS CLIENT ON ANDROID, FIRST DOWNLOAD AND INSTALL TERMUX. IT WILL SERVE AS SHELL THAT ANDROID CAN ACCESS TO RUN THE SCRIPT. YOU CAN FIND TERMUX AT THE PLAYSTORE. WHEN USING TERMUX ALL PKGS EXCEPT THE GITHUB PACKAGE WILL BE INSTALLED BY THE INSTALL SCRIPT INSTEAD OF MANUAL COMMANDS!**

**START TERMUX**

Install GitHub Repository:
```
$ pkginstall git
```

Now create a directory with `mkdir` wherever you want and step into this directory with `cd`:
```
$ mkdir ucs
$ cd ucs
```

Now clone the GitHub repository of UCS, in this case latest version is `ucs_client_v0.0.1`:
```
$ git clone https://github.com/universal-credit-system/ucs_client_v0.0.1
```

Step into directory that contains the cloned repository:
```
$ cd ucs_client_v0.0.1/
```

You may need to change permissions to make the install script and the ucs client script executable:
```
$ chmod +x termux_install.sh
$ chmod +x ucs_client.sh
```

Now you can execute the install.sh script that creates required folders:
```
$ ./termux_install.sh
```

Once you have installed ucs you can run the UCS Client just like you would executed any other script:
```
$ ./ucs_client.sh
```

## Community
We encourage you to join the [Community](https://forum.universal-credit-system.org). **If you have any questions, suggestions or critics you are welcome to post it on the community discourse forum.**

**HAVE FUN!**
