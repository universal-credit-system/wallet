#!/bin/sh
script_name=${0}
script_path=$(dirname $(readlink -f ${0}))
mkdir ${script_path}/keys
mkdir ${script_path}/trx
mkdir ${script_path}/proofs
