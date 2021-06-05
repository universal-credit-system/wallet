#!/bin/sh

###GET PATH#################
script_path=$(dirname $(readlink -f ${0}))

###CREATE DIRECTORIES#######
mkdir ${script_path}/backup
mkdir ${script_path}/control/keys
mkdir ${script_path}/keys
mkdir ${script_path}/proofs
mkdir ${script_path}/trx
mkdir ${script_path}/userdata

###SAVE UMASK SETTINGS######
user_umask=`umask`
permissions_directories=`echo "777 - ${user_umask}"|bc`
touch ${script_path}/test.tmp
permissions_files=`stat -c '%a' ${script_path}/test.tmp`
rm ${script_path}/test.tmp
sed -i "s/permissions_directories=<permissions_directories>/permissions_directories=${permissions_directories}/g" ${script_path}/control/config.conf
sed -i "s/permissions_files=<permissions_files>/permissions_files=${permissions_files}/g" ${script_path}/control/config.conf

###SET PATHS################
sed -i "s#<trx_path_input>#${script_path}#g" ${script_path}/control/config.conf
sed -i "s#<trx_path_output>#${script_path}#g" ${script_path}/control/config.conf
sed -i "s#<sync_path_input>#${script_path}#g" ${script_path}/control/config.conf
sed -i "s#<sync_path_output>#${script_path}#g" ${script_path}/control/config.conf
