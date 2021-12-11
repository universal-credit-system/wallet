# Universal Credit System Wallet

This is the repository for the UCS wallet.

## Table of contents
* [What is UCS](#what-is-ucs)
* [Technologies used](#technologies-used)
* [How to install](#how-to-install)
* [Community](#community)

## What is Universal Credit System
The [Universal Credit System](https://www.universal-credit-system.org) is a resource friendly and highly innovative crypto currency. Every day a number of universal credit coins will be granted to all users of the universal credit system resulting in a **free digital basic income** for all participants. Users process their own blocks and permanently review and audit each other on a file based protocol which allows them too manage themself offline in a decentralised block grid. The purpose of this document is to show how you can setup and run the UCS wallet you need to receive, send and manage your universal credit coins.

## Technologies used
The program was written as **standard shell script (#!/bin/sh)**.

The script depends on other programs. Most of them are **GNU core utilities**, which means that depending on your version of the GNU core utils they should be already installed. But some programs (like i.e. ``bc``, ``openssl``, ``curl`` and some more) maybe not. During setup the `install.sh` script will perform a check if any program is missing so you don't need to check them yourself.

The following programs are used:

* **awk**     used to sort/filter data
* **basename** used to strip directory and suffix from filenames
* **bc**      used for floating point calculations
* **cat**     used to concatenate content
* **chmod**   used to change permissions
* **cp**      used to copy files
* **curl**    used to send query to TSA and request response
* **cut**     used to extract data from streams
* **date**    used for date operations
* **dd**      used to convert files
* **dialog**  used as GUI
* **dirname** used to strip non-directory suffix from file name
* **echo**    used to write output
* **expr**    used for calculations
* **find**    used to search files/directories
* **flock**   used to manage read locks for multi user setups 
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
* **shasum**  used to hash files (i.e. shipped with PERL package)
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

## How to install
**Assuming you use APT as packaging tool, the command `apt-get install` is used. Please note that if you are using any other packaging tool than APT the command for installing a package might be different. This means you have the change `apt-get install` to the command your packaging tool is using!**

Install Git (you may use `sudo` in front):
```
apt-get install git
```

Create a directory wherever you want and step into this directory:
```
mkdir ucs
cd ucs
```

Clone the GitHub repository and step into this directory:
```
git clone https://github.com/universal-credit-system/ucs_client_v0.0.1
cd ucs_client_v0.0.1/
```

Now you can execute the install.sh script. The script will check for depending programs and if all depending programs are installed the setup will continue. 
If there is a program that needs to be installed the script will output the program names and then quit. In this case you have to install these programs first and then run `install.sh` script again.
```
./install.sh
```

After setup you can run `ucs_client.sh`:
```
./ucs_client.sh
```

## Community
**Do you have a problem? We have set up a [Forum](https://forum.universal-credit-system.org) and also a [Discord Server](https://discord.gg/5kvCP6kkRn) for troubleshooting. It's the place for the ucs community were they can meet and discuss things related to the Universal Credit System. We encourage you to join the community think tank and contribute to this project. If you have any questions, suggestions or critics you are always welcome to post it on the forum.**

**NOW HAVE FUN!**
