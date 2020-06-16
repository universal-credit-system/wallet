#!/bin/sh
pkg install bc
pkg install wget
pkg install curl
pkg install perl
pkg install gnupg2
pkg install openssl
pkg install dialog
chmod 755 install.sh
chmod 755 ucs_client.sh
./install.sh
