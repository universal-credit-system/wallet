#!/bin/sh
script_name=${0}
script_path=$(dirname $(readlink -f ${0}))
umask 0022
mkdir ${script_path}/backup
mkdir ${script_path}/backup/temp
mkdir ${script_path}/control/keys
mkdir ${script_path}/keys
mkdir ${script_path}/proofs
mkdir ${script_path}/trx
mkdir ${script_path}/temp
mkdir ${script_path}/temp/keys
mkdir ${script_path}/temp/proofs
mkdir ${script_path}/temp/trx
chmod +x ${script_path}/ucs_client.sh
