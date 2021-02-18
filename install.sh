#!/bin/sh
script_name=${0}
script_path=$(dirname $(readlink -f ${0}))
mkdir ${script_path}/backup
mkdir ${script_path}/backup/temp
mkdir ${script_path}/control
mkdir ${script_path}/control/keys
mkdir ${script_path}/keys
mkdir ${script_path}/proofs
mkdir ${script_path}/trx
chmod +x ${script_path}/ucs_client.sh
