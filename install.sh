#!/bin/sh
add_trap_command(){
		    	command_to_add="$1"
			if [ -n "${command_to_add:-}" ]
			then
				if [ -z "${current_trap:-}" ]
			    	then
			    		### IF EMPTY SET TRAP #########################
			    		current_trap=${command_to_add}
			    		trap "${command_to_add}" EXIT
			    	else
			    		### IF NOT EMPTY APPEND #######################
					trap "${current_trap}; ${command_to_add}" EXIT
					current_trap="${current_trap}; ${command_to_add}"
				fi
			fi
}
print_message(){
			if [ "${rt_query}" -eq 0 ]
			then
				printf "%b" "DONE\n"
			else
				printf "%b" "FAILED\n"
				error_counter=$(( error_counter + 1 ))
			fi
			rt_query=0
}
### SET VARIABLES ##############
script_path=$(cd "$(dirname "$0")" && pwd)
script_name=$(basename "$0")
current_trap=""
my_pid=$$
error_counter=0
cmd_env=""
cmd_user=""

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
			"-debug")	set -v
					;;
			"-trace")	set -x
					;;
			"-help")	more "${script_path}"/control/install_HELP.txt
					exit 0
					;;
			*)		### SET TARGET VARIABLES #######
					case "${cmd_var}" in
						"-env")		cmd_env=$(printf "%b" "${1}"|tr 'A-Z' 'a-z')
								;;
						"-user")	cmd_user=$1
								;;
						*)		printf "%b" "[ERROR][parser] Unexpected argument $1\n"
								printf "%b" "[INFO] To display the HELP run:\n./install.sh -help\n"
								exit 1
								;;
					esac
					cmd_var=""
					;;
		esac
		shift
	done

fi

### CREATE TMP ##############
add_trap_command '[ -n "${install_dep:-}" ] && rm -f -- "${install_dep}"'
install_dep=$(mktemp "${script_path}/install_dep.XXXXXX") || exit 1

### CHECK DEPENDENCIES #######
while read program
do
	### CHECK IF PROGRAMM IS UNKNOWN ####
        type "${program}" >/dev/null 2>/dev/null
        rt_query=$?
        if [ "${rt_query}" -gt 0 ]
        then
        	### QUERY TO REPLACE COMMANDS WITH PACKAGE NAME ###########
        	case "${program}" in
        		"netcat")	printf "%b" "netcat-openbsd\n" >>"${install_dep}"
        				;;
        		"gpg")		printf "%b" "gnupg\n"  >>"${install_dep}"
        				;;
        		"openssl")	if [ "${cmd_env}" = "termux" ]
        				then
        					printf "%b" "openssl-tool\n"  >>"${install_dep}"
        				else
        					printf "%b" "${program}\n"  >>"${install_dep}"
        				fi
        				;;
        		*)		printf "%b" "${program}\n"  >>"${install_dep}"
        				;;
        	esac
        fi
done <"${script_path}"/control/install.dep
if [ -f "${install_dep}" ] && [ -s "${install_dep}" ]
then
	############################
	###IF APPS ARE TO INSTALL###
	###GET PACKAGE MANAGER######
	case "${cmd_env}" in
		"termux")	pkg_mngr="pkg"
				;;
		*)		pkg_mngr=""
				for pmgr in apk apt-get dnf pacman pkg yum zipper
				do
					if [ -x "$(command -v "${pmgr}")" ]
					then
						pkg_mngr="${pmgr}";
					fi
				done
				if [ -z "${pkg_mngr}" ]
				then
					###IF PACKAGING MANAGER DETECTION FAILED####
					error_counter=1
					no_of_programs=$(wc -l <"${install_dep}")
					printf "%b" "[ ERROR ][package] Couldn't detect the package management system used on this machine!\n"
					printf "%b" "[ ERROR ][package] Found ${no_of_programs} programs that need to be installed:\n"
					awk '{print "[ ERROR ][package] -> " $1}' "${install_dep}"
					printf "%b" "[ ERROR ][package] Install these programms first using your package management system and then run install.sh again.\n"
					############################################
				fi
				;;
	esac

	if [ -n "${pkg_mngr}" ] && [ "${error_counter}" -eq 0 ]
	then
		### INSTALL MISSING PKGS #####
		while IFS= read -r program
		do
			printf "%b" "[ INFO ] Trying to install ${program} using ${pkg_mngr}...\n"
			case "${pkg_mngr}" in
				"apk")		apk add "${program}" ;;
				"apt-get")	apt-get -y install "${program}" ;;
				"dnf")		dnf -y install "${program}" ;;
				"pacman")	pacman --noconfirm -S "${program}" ;;
				"pkg")		pkg install -y "${program}" ;;
				"yum")		yum -y install "${program}" ;;
				"zypper")	zypper -n install "${program}" ;;
			esac
			rt_query=$?
			if [ "${rt_query}" -gt 0 ]
			then
				printf "%b" "[ ERROR ][packages] Error during installation of ${program} using ${pkg_mngr}\n"
				printf "%b" "[ ERROR ][packages] Maybe the program ${program} is available in a package with different name.\n"
				error_counter=$(( error_counter + 1 ))
			fi
		done <"${install_dep}"
		############################
	fi
fi
if [ "${error_counter}" -eq 0 ]
then
	rt_query=0
	if [ -n "${cmd_user}" ]
	then
		### DOCUMENT SU COMMAND ######
		printf "%b" "[INFO] Switch to user ${cmd_user}\n"
		su - "${cmd_user}" || exit 1
	fi
	### CREATE DIRECTORIES #######
	printf "%b" "[ INFO ] Creating directories..."
	mkdir -p "${script_path}"/backup \
		"${script_path}"/control/keys \
		"${script_path}"/keys \
		"${script_path}"/proofs \
		"${script_path}"/tmp \
		"${script_path}"/trx \
		"${script_path}"/userdata || rt_query=1
	print_message

	### SAVE UMASK SETTINGS ######
	printf "%b" "[ INFO ] Getting umask..."
	permissions_directories=$(printf "%03o" $(( 0777 & ~$(umask) ))) || rt_query=1
	permissions_files=$(printf "%03o" $(( 0666 & ~$(umask) ))) || rt_query=1
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
	sed -i."${my_pid}".bak "s/permissions_directories=permissions_directories/permissions_directories=${permissions_directories}/g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	sed -i."${my_pid}".bak "s/permissions_files=permissions_files/permissions_files=${permissions_files}/g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	print_message

	### SET DEFAULT THEME ########
	printf "%b" "[ INFO ] Set default theme 'debian.rc' in config.conf..."
	sed -i."${my_pid}".bak "s#theme_file=theme_file#theme_file=debian.rc#g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	print_message

	### SET PATHS ################
	printf "%b" "[ INFO ] Define paths in config.conf..."
	sed -i."${my_pid}".bak "s#trx_path_input=trx_path_input#trx_path_input=${script_path}#g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	sed -i."${my_pid}".bak "s#trx_path_output=trx_path_output#trx_path_output=${script_path}#g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	sed -i."${my_pid}".bak "s#sync_path_input=sync_path_input#sync_path_input=${script_path}#g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	sed -i."${my_pid}".bak "s#sync_path_output=sync_path_output#sync_path_output=${script_path}#g" "${script_path}"/control/config.conf && rm "${script_path}"/control/config.conf."${my_pid}".bak 2>/dev/null || rt_query=1
	print_message

	### REWRITE CONFIG ###########
	if [ -s "${script_path}"/control/config.bak ]
	then
		### CREATE TMP FILE ##########
		add_trap_command '[ -n "${config_tmp:-}" ] && rm -f -- "${config_tmp}"'
		config_tmp=$(mktemp "${script_path}/control/config_tmp.XXXXXX") || exit 1
		
		### READ OLD CONFIG #########
		grep "path_input\|path_output\|theme_file\|small_trx\|cmd_" "${script_path}"/control/config.bak | while IFS= read -r config_line
		do
			if [ -n "${config_line:-}" ]
			then
				conf_var="${config_line%%=*}"
				conf_var_val="${config_line#*=}"
				if grep -q "^$(printf '%s\n' "${conf_var}"|sed 's/[.[\*^$]/\\&/g')=" "${script_path}"/control/config.conf
				then
					printf "%b" "[ INFO ] Configure var \$${conf_var} in config.conf..."
					conf_line=$(grep "^${conf_var}" "${script_path}"/control/config.conf)
					if [ ! "${conf_line:-}" = "${conf_var}=${conf_var_val}" ]
					then
						sed -i."${my_pid}".bak "s#${conf_line}#${conf_var}=${conf_var_val}#g" "${script_path}"/control/config.conf && rm -f -- "${script_path}"/control/config.conf."${my_pid}".bak || rt_query=1
					fi
					print_message
				fi
			fi
		done
	fi
	
	### CHECK FOR ERRORS #####################
	if [ "${error_counter}" -gt 0 ] && [ -s "${script_path}"/control/config.bak ]
	then
		printf "%b" "[ INFO ] Restoring old config ( ->rename control/config.bak back to control/config.conf )..."
		mv "${script_path}"/control/config.bak "${script_path}"/control/config.conf || rt_query=1
		print_message
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
		sed -i."${my_pid}".bak 's/use-keyboxd//g' ~/.gnupg/common.conf && rm ~/.gnupg/common.conf."${my_pid}".bak || rt_query=1
		print_message
	fi
fi
### DISPLAY OUTPUT #######################
printf "%b" "[ INFO ] ${script_name} finished (errors:${error_counter})\n"

