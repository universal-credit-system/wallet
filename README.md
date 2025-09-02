# Universal Credit System Wallet

Repository of the Universal Credit System Wallet.

## Table of contents
* [Description](#description)
* [Technologies used](#technologies-used)
* [Installation](#installation)
* [Start](#start)
* [Update](#update)
* [Extensions](#extensions)
* [Community](#community)

## Description
The [Universal Credit System](https://www.universal-credit-system.org) Wallet is the wallet software for a new and revolutionary stablecoin cryptocurrency called Universal Credit Coins. The cryptocurrency is based on a innovative monetary standard in which any newly minted coins are backed by time. Users process their own blocks and permanently review and audit each other on a file based protocol that allows them to manage themself offline in a decentralised block grid. Contrary to other cryptocurrencies users get daily rewards for the elapsed time instead of spent computing power (pow) or held balance (pos).

## Technologies used
The program was written as **bourne shell script (#!/bin/sh)**

The script depends on other programs. Most of them are **core utilities**, which means that depending on your version of the core utils they should be already installed. But some programs (like i.e. ``bc``, ``openssl``, ``curl`` and some more) maybe not. During setup the `install.sh` script will perform a check if any program is missing so you don't need to check them yourself.

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
* **file**    used to check file types
* **find**    used to search files/directories
* **flock**   used to manage read locks for multi user setups 
* **gpg**     used for transaction signing
* **grep**    used to search files
* **head**    used to display heading lines/bytes of a file
* **ls**      used to list files and directories
* **mkdir**   used to create folders and subfolders
* **mktemp**  used to create files with unique IDs
* **mv**      used to move files
* **netcat**  used to send/request files
* **openssl** used for TSA stamp verification
* **printf**  used to write output
* **rm**      used to delete files
* **sed**     used to modify files
* **sha224sum** used to hash files
* **sha256sum** used to hash files
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

## Installation
**Assuming you use APT as packaging tool, the command `apt-get install` is used. Please note that if you are using any other packaging tool than APT the command for installing a package might be different. This means you have the change `apt-get install` to the command your packaging tool is using!**

Install Git (you may use `sudo` in front)
```bash
apt-get install git
```

Clone the GitHub repository
```bash
git clone https://github.com/universal-credit-system/wallet
```

Step into this directory using `cd`
```bash
cd wallet/
```

Now you can execute the install.sh script. The script will check for depending programs and if all depending programs are installed the setup will continue. 
If there is a program that needs to be installed the script will display the program names and then quit. In this case you have to manually install these programs first and then run `install.sh` script again.
```bash
./install.sh
```

## Start
To start the wallet `ucs_client.sh` simply type
```bash
./ucs_client.sh
```

## Update
To get the latest updates for the source code run `git pull`
```bash
git pull
```
## Extensions
There are additional archives that contain the different extensions:

* **contractor.tar**

  Universal Contractor including sample contracts
  
* **docker.tar**

  Dockerfiles including build and deployment scripts
* **explorer.tar**

  UCS Tangle explorer
* **otsa.tar**

  scripts to create and deploy your own TSA service
  
* **webwallet_home.tar**

  webwallet wallet connector
  
* **webwallet_www-data.tar**

  webwallet webpage
  
* **webapi.tar**

  WebAPI RPC
  
* **server.tar**

  UCA LINK Server
  
* **tools.tar**

  a useful set of scripts

You have to unpack these tar files yourself if by using `tar`:
```bash
tar -xvf <archive>.tar
```
For more information on the extension please have a look into the related technical documentation.

## Community
**You found a bug or face an issue running the client? We have a [Forum](https://forum.universal-credit-system.org) and also a [Discord Server](https://discord.gg/5kvCP6kkRn) for troubleshooting and support. If you have any questions, suggestions or critics you are welcome to post it on the forum or the discord server.**
