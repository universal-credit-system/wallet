#!/bin/sh

###GET PATH#################
script_path=$(dirname $(readlink -f ${0}))

###CHECK DEPENDENCIES#######
while read line
do
	###CHECK IF PROGRAMM IS UNKNOWN####
        type $line >/dev/null
        rt_query=$?
        if [ $rt_query -gt 0 ]
        then
                echo $line >>${script_path}/install_dep.tmp
        fi
done <${script_path}/control/install.dep
if [ ! -s ${script_path}/install_dep.tmp ]
then	############################
	###IF ALL ARE INSTALLED#####
	###########SETUP############

	###CREATE DIRECTORIES#######
	mkdir ${script_path}/backup
	mkdir ${script_path}/control/keys
	mkdir ${script_path}/keys
	mkdir ${script_path}/proofs
	mkdir ${script_path}/trx
	mkdir ${script_path}/userdata

	###SAVE UMASK SETTINGS######
	user_umask=$(umask)
	permissions_directories=$(echo "777 - ${user_umask}"|bc)
	touch ${script_path}/test.tmp
	permissions_files=$(stat -c '%a' ${script_path}/test.tmp)
	rm ${script_path}/test.tmp
	cp ${script_path}/control/install_config.conf ${script_path}/control/config.conf
	sed -i "s/permissions_directories=permissions_directories/permissions_directories=${permissions_directories}/g" ${script_path}/control/config.conf
	sed -i "s/permissions_files=permissions_files/permissions_files=${permissions_files}/g" ${script_path}/control/config.conf

	###SET DEFAULT THEME########
	sed -i "s#theme_file=theme_file#theme_file=debian.rc#g" ${script_path}/control/config.conf

	###SET PATHS################
	sed -i "s#trx_path_input=trx_path_input#trx_path_input=${script_path}#g" ${script_path}/control/config.conf
	sed -i "s#trx_path_output=trx_path_output#trx_path_output=${script_path}#g" ${script_path}/control/config.conf
	sed -i "s#sync_path_input=sync_path_input#sync_path_input=${script_path}#g" ${script_path}/control/config.conf
	sed -i "s#sync_path_output=sync_path_output#sync_path_output=${script_path}#g" ${script_path}/control/config.conf

	###GPG AGENT################
	if [ -s ~/.gnupg/gpg-agent.conf ]
	then
		while read config_line
		do
			if [ $(grep -c "${config_line}" ~/.gnupg/gpg-agent.conf) -eq 0 ]
			then
				echo "${config_line}" >>~/.gnupg/gpg-agent.conf
			fi
		done <${script_path}/control/gpg-agent.conf
	else
		cat ${script_path}/control/gpg-agent.conf >~/.gnupg/gpg-agent.conf
	fi
else
	############################
	###IF APPS ARE TO INSTALL###
	###########ABORT############

	###DISPLAY APPS TO INSTALL##
	no_of_programs=$(wc -l <${script_path}/install_dep.tmp)
        echo "Found ${no_of_programs} programs that need to be installed:"
        cat ${script_path}/install_dep.tmp
	echo "Install these programms first, then run install.sh again."

	###REMOVE TMP FILE##########
        rm ${script_path}/install_dep.tmp
fi
