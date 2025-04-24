#!/bin/sh

### GET PATH #################
script_path=$(dirname "$(readlink -f "${0}")")

### CHECK DEPENDENCIES #######
printf "%b" "INFO: Checking for dependencies..."
while read program
do
	### CHECK IF PROGRAMM IS UNKNOWN ####
        type "$program" >/dev/null
        rt_query=$?
        if [ $rt_query -gt 0 ]
        then
        	### QUERY TO REPLACE COMMANDS WITH PACKAGE NAME ###########
        	case $program in
        		"netcat")	echo "netcat-openbsd" >>"${script_path}"/install_dep.tmp
        				;;
        		"gpg")		echo "gnupg"  >>"${script_path}"/install_dep.tmp
        				;;
        		*)		echo "${program}"  >>"${script_path}"/install_dep.tmp
        				;;
        	esac
        fi
done <"${script_path}"/control/install.dep
printf "%b" "DONE\n"

if [ ! -s "${script_path}"/install_dep.tmp ]
then	##############################
	### IF ALL ARE INSTALLED #####
	########### SETUP ############

	### CREATE DIRECTORIES #######
	printf "%b" "INFO: Creating directories..."
	mkdir -p "${script_path}"/backup
	mkdir -p "${script_path}"/control/keys
	mkdir -p "${script_path}"/keys
	mkdir -p "${script_path}"/proofs
	mkdir -p "${script_path}"/trx
	mkdir -p "${script_path}"/userdata
	printf "%b" "DONE\n"

	### SAVE UMASK SETTINGS ######
	printf "%b" "INFO: Getting umask..."
	user_umask=$(umask)
	permissions_directories=$(echo "777 - ${user_umask}"|bc)
	touch "${script_path}"/test.tmp
	permissions_files=$(stat -c '%a' "${script_path}"/test.tmp)
	rm "${script_path}"/test.tmp
	printf "%b" "DONE\n"
	
	### IF OLD CONFIG THERE ######
	if [ -s "${script_path}"/control/config.conf ]
	then
		printf "%b" "INFO: Backup old config ( ->control/config.bak )..."
		mv "${script_path}"/control/config.conf "${script_path}"/control/config.bak
		printf "%b" "DONE\n"
	fi
	
	### COPY TO PLACE ############
	printf "%b" "INFO: Copy install_config.conf to config.conf..."
	cp "${script_path}"/control/install_config.conf "${script_path}"/control/config.conf
	printf "%b" "DONE\n"
	
	printf "%b" "INFO: Write umask to config.conf..."
	sed -i "s/permissions_directories=permissions_directories/permissions_directories=${permissions_directories}/g" "${script_path}"/control/config.conf
	sed -i "s/permissions_files=permissions_files/permissions_files=${permissions_files}/g" "${script_path}"/control/config.conf
	printf "%b" "DONE\n"

	### SET DEFAULT THEME ########
	printf "%b" "INFO: Set default theme 'debian.rc' in config.conf..."
	sed -i "s#theme_file=theme_file#theme_file=debian.rc#g" "${script_path}"/control/config.conf
	printf "%b" "DONE\n"

	### SET PATHS ################
	printf "%b" "INFO: Define paths in config.conf..."
	sed -i "s#trx_path_input=trx_path_input#trx_path_input=${script_path}#g" "${script_path}"/control/config.conf
	sed -i "s#trx_path_output=trx_path_output#trx_path_output=${script_path}#g" "${script_path}"/control/config.conf
	sed -i "s#sync_path_input=sync_path_input#sync_path_input=${script_path}#g" "${script_path}"/control/config.conf
	sed -i "s#sync_path_output=sync_path_output#sync_path_output=${script_path}#g" "${script_path}"/control/config.conf
	printf "%b" "DONE\n"

	### REWRITE CONFIG ###########
	if [ -s "${script_path}"/control/config.bak ]
	then
		### GET VARIABLES ###########
		printf "%b" "INFO: Get old configuration of config.bak..."
		grep "\path_input\|path_output\|theme_file" "${script_path}"/control/config.bak >"${script_path}"/control/config.tmp
		printf "%b" "DONE\n"

		### READ OLD CONFIG #########
		while read config_line
		do
			if [ ! "${config_line}" = "" ]
			then
				conf_var=$(echo "${config_line}"|cut -d '=' -f1)
				conf_var_val=$(echo "${config_line}"|cut -d '=' -f2)
				if [ "$(grep -c "${conf_var}" "${script_path}"/control/config.conf)" -gt 0 ]
				then
					printf "%b" "INFO: Configure var ${conf_var} in config.conf..."
					conf_line=$(grep "${conf_var}" "${script_path}"/control/config.conf)
					if [ ! "${conf_line}" = "${conf_var}=${conf_var_val}" ]
					then
						sed -i "s/${conf_line}/${conf_var}=${conf_var_val}/g" "${script_path}"/control/config.conf
					fi
					printf "%b" "DONE\n"
				fi
			fi
		done <"${script_path}"/control/config.tmp
		rm "${script_path}"/control/config.tmp
	fi

	### IF USER NEVER RAN GPG UNTIL NOW ######
	if [ ! -d ~/.gnupg/ ]
	then
		### RUN GPG ###################
		printf "%b" "INFO: Running GPG to wake up agent..."
		gpg '?' 2>/dev/null
		printf "%b" "DONE\n"
	fi
	if [ -s ~/.gnupg/gpg-agent.conf ]
	then
		printf "%b" "INFO: Checking gpg-agent.conf configuration..."
		while read config_line
		do
			if [ "$(grep -c "${config_line}" ~/.gnupg/gpg-agent.conf)" -eq 0 ]
			then
				echo "${config_line}" >>~/.gnupg/gpg-agent.conf
			fi
		done <"${script_path}"/control/gpg-agent.conf
		printf "%b" "DONE\n"
	else
		printf "%b" "INFO: Copy gpg-agent.conf to ~/.gnupg/ folder..."
		cp "${script_path}"/control/gpg-agent.conf ~/.gnupg/gpg-agent.conf
		printf "%b" "DONE\n"
	fi
else
	##############################
	### IF APPS ARE TO INSTALL ###
	########### ABORT ############

	### DISPLAY APPS TO INSTALL ##
	no_of_programs=$(wc -l <"${script_path}"/install_dep.tmp)
        echo "INFO: Found ${no_of_programs} program(s) that need to be installed:"
        awk '{print "INFO: -> " $1}' "${script_path}"/install_dep.tmp
	echo "INFO: Install these programms first, then run install.sh again."

	### REMOVE TMP FILE ##########
        rm "${script_path}"/install_dep.tmp
fi
