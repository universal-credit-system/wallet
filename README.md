# ucs_client_v0.0.1
This is the pre-alpha repository for the UCS Client

The Universal Credit System was written as shell script on a Raspberry Pi 3 with Raspbian.

But you can run it on any machine, just make sure you have the following programs installed before running the UCS Client:


Dependencies:

bc	(used for floating point calculations)

wget	(used to fetch certificate files of TSA from Internet)

curl	(used to send query to TSA and request response)

shasum	(used to hash files)

openssl	(used for TSA stamp verification)

gpg	(aka GnuPG e.g. used for transaction signing)

dialog	(used for GUI)



Package installation via APT (Advanced Packaging Tool):

Install >bc< by executing the following command:

sudo apt-get install bc


Install >wget< by executing the following command:

sudo apt-get install wget


Install >curl< by executing the following command:

sudo apt-get install curl


Install >shasum< by executing the following command:

sudo apt-get install perl


Install >gpg< by executing the following command:

sudo apt-get install gnupg2


Install >openssl< by executing the following command:

sudo apt-get install openssl


Install >dialog< by executing the following command:

sudo apt-get install dialog


Now make a directory wherever you want:

mkdir ucs


Clone GitHub repository:

git clone https://github.com/universal-credit-system/ucs_client_v0.0.1


Step into directory:

cd ucs_client_v0.0.1/


If you cloned the repository from GitHub you may need to change permissions to make it executable:

chmod 755 install.sh

chmod 755 ucs_client.sh


Now you have to execute the install.sh script that creates required folders:

./install.sh


Now you can run the UCS Client just like you would executed any other script:

./ucs_client.sh


HAVE FUN!

