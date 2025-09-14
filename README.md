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

The script depends on other programs (see list of [programs used](https://github.com/universal-credit-system/wallet/blob/master/control/install.dep)). Most of them are **core utilities**, which means that they should be already installed. But programs like ``bc``, ``openssl``, ``curl`` and others maybe not and need to be installed. The setup script `install.sh` will check if any programs are missing and will install them.

## Installation
**Assuming you use APT as packaging tool, the command `apt-get install` is used. Please note that if you are using any other packaging tool than APT the command for installing a package might be different. This means you have the change `apt-get install` to the command your packaging tool is using!**

Install Git (you may use `sudo` in front)
```bash
apt-get install git
```

Clone this GitHub repository
```bash
git clone https://github.com/universal-credit-system/wallet
```

Step into this directory using `cd`
```bash
cd wallet/
```

Now you can execute the install.sh script. The script will check for depending programs and will install them if necessary
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
The archives in the repository contain the different extensions:

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

You have to unpack these tar files yourself using `tar`:
```bash
tar -xvf <archive>.tar
```
For more information on the extension please have a look into the related technical documentation.

## Community
**You found a bug or face an issue running the client? We have a [Forum](https://forum.universal-credit-system.org) and also a [Discord Server](https://discord.gg/5kvCP6kkRn) for troubleshooting and support. If you have any questions, suggestions or critics you are welcome to post it on the forum or the discord server.**
