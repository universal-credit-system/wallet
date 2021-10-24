# ucs_client_v0.0.1

This is the main repository for the UCS client pre-alpha version.

## Table of contents
* [What is UCS](#what-is-ucs)
* [Technologies used](#technologies-used)
* [How to install on LINUX](#how-to-install-on-linux)
* [How to install on ANDROID](#how-to-install-on-android)
* [Community](#community)

## What is UCS
The [Universal Credit System](https://www.universal-credit-system.org) offers a **free digital basic income** for everybody. Every day a number of universal credit coins will be granted to all users of the universal credit system program. The purpose of this document is to show how you can setup and run the UCS program. This program is actually the wallet you need to receive, send and manage your universal credit coins.

## Technologies used
The program was written as **linux standard shell (#!/bin/sh)** script.

**You can run it on any machine if you follow the installation instructions!**

The script **depends** on below programs that must be installed:

* **awk**     used to sort/filter data
* **bc**      used for floating point calculations
* **cat**     used to concatenate content
* **chmod**   used to change permissions
* **cp**      used to copy files
* **curl**    used to send query to TSA and request response
* **cut**     used to extract data from streams
* **date**    used for date operations
* **dialog**  used as GUI
* **echo**    used to write output
* **expr**    used for calculations
* **find**    used to search files/directories
* **gpg**     used for transaction signing
* **grep**    used to search files
* **head**    used to display heading lines/bytes of a file
* **ls**      used to list files and directories
* **mkdir**   used to create folders and subfolders
* **mv**      used to move files
* **netcat**  used to send/request files
* **openssl** used for TSA stamp verification
* **printf**  used to write output
* **rm**      used to delete files
* **sed**     used to read/modify files
* **shasum**  used to hash files
* **sort**    used to sort files
* **stat**    used to get permissions of files/directories
* **tail**    used to display tailing lines of a file
* **tar**     used to create the transaction file
* **test**    used to test files
* **touch**   used to create files
* **tr**      used to convert chars
* **umask**   used to determine umask
* **uniq**    used to filter files
* **wc**      used to count lines, words, bytes
* **wget**    used to fetch certificate files of TSA from Internet

## How to install on LINUX
**Assuming you use APT as packaging tool, the command `apt-get install` is used. Please note that if you are using any other packaging tool than APT the command for installing a package might be different. This means you have the change `apt-get install` to the command your packaging tool is using!**

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

Now you can execute the install.sh script that creates required folders:
```
./install.sh
```

Once you have installed ucs you can run the UCS program just like you would executed any other script:
```
./ucs_client.sh
```

## How to install on ANDROID
**If you would like to run the script on ANDROID, you need a shell that you can access from where you can install and run the script. There are apps which allow you even to install a full linux within. We suggest that you use TERMUX for a simple shell access without installing a operating system inside the app. You can find TERMUX on the Google PlayStore. If you decide to use TERMUX you can use below commands for installation; it's very easy. Please note that if you are using any other app the command for installing a package might be different. The same applies if you have installed a linux operating system within one of the apps. This means that in both cases you have to change `pkginstall` to the command of the packaging tool your app/operating system is using!**

To install the programs that are required for UCS just type the following into command prompt:
```
pkg install bc
pkg install wget
pkg install curl
pkg install perl
pkg install gnupg
pkg install openssl
pkg install dialog
pkg install git
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
**Do you have problem? We have set up a [Forum](https://forum.universal-credit-system.org) for troubleshooting. It's the place for the ucs community were they can meet and discuss things related to the Universal Credit System. We encourage you to join the community think tank and contribute to this project. If you have any questions, suggestions or critics you are always welcome to post it on the forum.**

**NOW HAVE FUN!**
