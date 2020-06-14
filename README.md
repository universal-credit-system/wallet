# ucs_client_v0.0.1
This is the pre-alpha repository for the UCS Client

The Universal Credit System was written as shell script on a Raspberry Pi 3 with Raspbian.

But you can run it on any machine, just make sure you have the following programs installed before running the UCS Client:


Package dependencies:

-bc (used for floating point calculations)

-wget (used to fetch certificate files of TSA from Internet)

-curl (used to send query to TSA and request response)

-shasum (used to hash files)

-openssl (used for TSA stamp verification)

-gpg (used for transaction signing)

-dialog (used for GUI)



Package installation via APT (Advanced Packaging Tool):


sudo apt-get install bc

sudo apt-get install wget

sudo apt-get install curl

sudo apt-get install perl

sudo apt-get install gnupg2

sudo apt-get install openssl

sudo apt-get install dialog


Now make a directory wherever you want:

mkdir ucs

Step into the directory you just created:

cd ucs


Clone the GitHub repository:

git clone https://github.com/universal-credit-system/ucs_client_v0.0.1


Step into directory git created:

cd ucs_client_v0.0.1/


If you cloned the repository from GitHub you may need to change permissions to make it executable:

chmod 755 install.sh

chmod 755 ucs_client.sh


Now you have to execute the install.sh script that creates required folders:

./install.sh


Now you can run the UCS Client just like you would executed any other script:

./ucs_client.sh


HAVE FUN!

