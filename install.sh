#!/bin/sh
print_message(){
		if [ "$rt_query" -eq 0 ]
		then
			printf "%b" "DONE\n"
		else
			printf "%b" "FAILED\n"
			error_detected=1
			error_counter=$(( error_counter + 1 ))
		fi
		rt_query=0
}

### SET VARIABLES ##############
script_path=$(dirname "$(readlink -f "${0}")")
script_name=$(basename "${0}")
error_detected=0
error_counter=0
cmd_env=""
cmd_user=""

### CHECK FOR STDIN INPUT ######
if [ ! -t 0 ]
then
	set -- $(cat) "$@"
fi

### ASSIGN VARIABLES ###########
if [ $# -gt 0 ]
then
	cmd_var=""

	### GO THROUGH PARAMETERS ######
	while [ $# -gt 0 ]
	do
		### GET TARGET VARIABLES #######
		case $1 in
			"-env")		cmd_var=$1
					;;
			"-user")	cmd_var=$1
					;;
			"-debug")	set -x
					set -v
					;;
			"-help")	more "${script_path}"/control/install_HELP.txt
					exit 0
					;;
			*)		### SET TARGET VARIABLES #######
					case $cmd_var in
						"-env")		cmd_env=$(echo "${1}"|tr 'A-Z' 'a-z')
								;;
						"-user")	cmd_user=$1
								;;
						*)		cmd_var=$1
								echo "Wrong Syntax -> $cmd_var !"
								echo ""
								echo "To display the HELP run:"
								echo "./install.sh -help"
								exit 1
								;;
					esac
					cmd_var=""
					;;
		esac
		shift
	done

fi

### CHECK DEPENDENCIES #######
while read program
do
	### CHECK IF PROGRAMM IS UNKNOWN ####
        type "$program" >/dev/null 2>/dev/null
        rt_query=$?
        if [ "$rt_query" -gt 0 ]
        then
        	### QUERY TO REPLACE COMMANDS WITH PACKAGE NAME ###########
        	case "$program" in
        		"netcat")	echo "netcat-openbsd" >>"${script_path}"/install_dep.tmp
        				;;
        		"gpg")		echo "gnupg"  >>"${script_path}"/install_dep.tmp
        				;;
        		"openssl")	if [ "${cmd_env}" = "termux" ]
        				then
        					echo "openssl-tool"  >>"${script_path}"/install_dep.tmp
        				else
        					echo "${program}"  >>"${script_path}"/install_dep.tmp
        				fi
        				;;
        		*)		echo "${program}"  >>"${script_path}"/install_dep.tmp
        				;;
        	esac
        fi
done <"${script_path}"/control/install.dep
if [ -f "${script_path}"/install_dep.tmp ] && [ -s "${script_path}"/install_dep.tmp ]
then
	############################
	###IF APPS ARE TO INSTALL###
	###GET PACKAGE MANAGER######
	case "$cmd_env" in
		"termux")	pkg_mngr="pkg"
				;;
		*)		pkg_mngr=""
				if [ -x "$(command -v apk)" ]
				then
					pkg_mngr="apk";
				else
					if [ -x "$(command -v apt-get)" ]
					then
						pkg_mngr="apt-get";
					else
						if [ -x "$(command -v dnf)" ]
						then
							pkg_mngr="dnf";
						else
							if [ -x "$(command -v pacman)" ]
							then
								pkg_mngr="pacman";
							else
								if [ -x "$(command -v pkg)" ]
								then
									pkg_mngr="pkg";
								else
									if [ -x "$(command -v yum)" ]
									then
										pkg_mngr="yum";
									else
										if [ -x "$(command -v zypper)" ]
										then
											pkg_mngr="zypper";
										else
											###IF PACKAGING MANAGER DETECTION FAILED####
											error_detected=1
											error_counter=1
											no_of_programs=$(wc -l <"${script_path}"/install_dep.tmp)
											echo "[ ERROR ] Couldn't detect the package management system used on this machine!"
											echo "[ ERROR ] Found ${no_of_programs} programs that need to be installed:"
											cat "${script_path}"/install_dep.tmp
											echo "[ ERROR ] Install these programms first using your package management system and then run install.sh again."
											############################################
										fi
									fi
								fi
							fi
						fi
					fi
				fi
				;;
	esac

	if [ -n "${pkg_mngr}" ] && [ "$error_detected" -eq 0 ]
	then
		### INSTALL MISSING PKGS #####
		while read program
		do
			printf "%b" "[ INFO ] Trying to install ${program} using ${pkg_mngr}...\n"
			case "$pkg_mngr" in
				"apk")		apk add "$program" ;;
				"apt-get")	apt-get -y install "$program" ;;
				"dnf")		dnf -y install "$program" ;;
				"pacman")	pacman --noconfirm -S "$program" ;;
				"pkg")		pkg install -y "$program" ;;
				"yum")		yum -y install "$program" ;;
				"zypper")	zypper -n install "$program" ;;
			esac
			rt_query=$?
			if [ "$rt_query" -gt 0 ]
			then
				echo "[ ERROR ] Error during installation of ${program} using ${pkg_mngr}"
				echo "[ ERROR ] Maybe the program ${program} is available in a package with different name."
				error_detected=1
				error_counter=$(( error_counter + 1 ))
			fi
		done <"${script_path}"/install_dep.tmp
		############################
	fi
fi
###REMOVE TMP FILE##########
rm "${script_path}"/install_dep.tmp 2>/dev/null
if [ "$error_detected" -eq 0 ]
then
	rt_query=0
	if [ -n "${cmd_user}" ]
	then
		su - "${cmd_user}" || exit 1
	fi
	### CREATE DIRECTORIES #######
	printf "%b" "[ INFO ] Creating directories..."
	mkdir -p "${script_path}"/backup || rt_query=1
	mkdir -p "${script_path}"/control/keys || rt_query=1
	mkdir -p "${script_path}"/keys || rt_query=1
	mkdir -p "${script_path}"/proofs || rt_query=1
	mkdir -p "${script_path}"/trx || rt_query=1
	mkdir -p "${script_path}"/userdata || rt_query=1
	print_message

	### SAVE UMASK SETTINGS ######
	printf "%b" "[ INFO ] Getting umask..."
	user_umask=$(umask) || rt_query=1
	permissions_directories=$(echo "777 - ${user_umask}"|bc) || rt_query=1
	touch "${script_path}"/test.tmp || rt_query=1
	permissions_files=$(stat -c '%a' "${script_path}"/test.tmp) || rt_query=1
	rm "${script_path}"/test.tmp || rt_query=1
	print_message

	### IF OLD CONFIG THERE ######
	if [ -s "${script_path}"/control/config.conf ]
	then
		printf "%b" "[ INFO ] Backup old config ( ->control/config.bak )..."
		mv "${script_path}"/control/config.conf "${script_path}"/control/config.bak || rt_query=1
		print_message
	fi

	### COPY TO PLACE ############
	printf "%b" "[ INFO ] Copy install_config.conf to config.conf..."
	cp "${script_path}"/control/install_config.conf "${script_path}"/control/config.conf || rt_query=1
	print_message

	### WRITE PERMISSIONS ########
	printf "%b" "[ INFO ] Write umask to config.conf..."
	sed -i "s/permissions_directories=permissions_directories/permissions_directories=${permissions_directories}/g" "${script_path}"/control/config.conf || rt_query=1
	sed -i "s/permissions_files=permissions_files/permissions_files=${permissions_files}/g" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### SET DEFAULT THEME ########
	printf "%b" "[ INFO ] Set default theme 'debian.rc' in config.conf..."
	sed -i "s#theme_file=theme_file#theme_file=debian.rc#g" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### SET PATHS ################
	printf "%b" "[ INFO ] Define paths in config.conf..."
	sed -i "s#trx_path_input=trx_path_input#trx_path_input=${script_path}#g" "${script_path}"/control/config.conf || rt_query=1
	sed -i "s#trx_path_output=trx_path_output#trx_path_output=${script_path}#g" "${script_path}"/control/config.conf || rt_query=1
	sed -i "s#sync_path_input=sync_path_input#sync_path_input=${script_path}#g" "${script_path}"/control/config.conf || rt_query=1
	sed -i "s#sync_path_output=sync_path_output#sync_path_output=${script_path}#g" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### REWRITE CONFIG ###########
	if [ -s "${script_path}"/control/config.bak ]
	then
		### GET VARIABLES ###########
		printf "%b" "[ INFO ] Get old configuration of config.bak..."
		grep "\path_input\|path_output\|theme_file" "${script_path}"/control/config.bak >"${script_path}"/control/config.tmp || rt_query=1
		print_message

		### READ OLD CONFIG #########
		while read config_line
		do
			if [ -n "${config_line}" ]
			then
				conf_var=$(echo "${config_line}"|cut -d '=' -f1)
				conf_var_val=$(echo "${config_line}"|cut -d '=' -f2)
				if [ "$(grep -c "${conf_var}" "${script_path}"/control/config.conf)" -gt 0 ]
				then
					printf "%b" "[ INFO ] Configure var \$${conf_var} in config.conf..."
					conf_line=$(grep "${conf_var}" "${script_path}"/control/config.conf)
					if [ ! "${conf_line}" = "${conf_var}=${conf_var_val}" ]
					then
						sed -i "s/${conf_line}/${conf_var}=${conf_var_val}/g" "${script_path}"/control/config.conf || rt_query=1
					fi
					print_message
				fi
			fi
		done <"${script_path}"/control/config.tmp
		rm "${script_path}"/control/config.tmp
	fi

	### IF USER NEVER RAN GPG UNTIL NOW ######
	if [ ! -d ~/.gnupg/ ]
	then
		### RUN GPG ###################
		printf "%b" "[ INFO ] Wake up gpg-agent..."
		gpgconf --launch gpg-agent >/dev/null 2>/dev/null || rt_query=1
		print_message
	fi

	### CONFIGURE GPG ########################
	if [ -s ~/.gnupg/gpg-agent.conf ]
	then
		printf "%b" "[ INFO ] Checking gpg-agent.conf configuration..."
		while read config_line
		do
			if [ "$(grep -c "${config_line}" ~/.gnupg/gpg-agent.conf)" -eq 0 ]
			then
				echo "${config_line}" >>~/.gnupg/gpg-agent.conf
			fi
		done <"${script_path}"/control/gpg-agent.conf
		print_message
	else
		printf "%b" "[ INFO ] Copy gpg-agent.conf to ~/.gnupg/ folder..."
		cp "${script_path}"/control/gpg-agent.conf ~/.gnupg/gpg-agent.conf || rt_query=1
		print_message
	fi

	### REMOVE USAGE OF KEYBOX ###############
	if [ -s ~/.gnupg/common.conf ]
	then
		printf "%b" "[ INFO ] Remove 'use-keyboxd' entry in ~/.gnupg/common.conf..."
		sed -i 's/use-keyboxd//g' ~/.gnupg/common.conf || rt_query=1
		print_message
	fi
fi
### DISPLAY OUTPUT #######################
printf "%b" "[ INFO ] $script_name finished (errors:$error_counter)\n"

