#!/bin/sh
trap_command(){
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
check_program() {
		prog="$1"

		### CHECK IF THEY EXIST ####
		status=1
		if command -v "${prog}" >/dev/null 2>&1
		then
			case "${prog}" in
				### EXLCLUE BUILTINS
				umask|test|echo|printf)
					status=0
					;;
				### EXLCLUE NON COREUTILS
				curl|flock|wget|gpg|openssl|dialog|file|bc|netcat)
					status=0
					;;
				### ALL OTHER CHECK IF GNU
				*)	if "${prog}" --version 2>&1|grep -q "GNU"
					then
						status=0							
					fi
					;;
			esac
		fi
		return $status
}
print_message(){
		message="$1"
		if [ -n "${message}" ]
		then
			printf "%s" "${message}"|tee -a "${script_path}/install_${timestamp}.log"
		else
			if [ "${rt_query}" -eq 0 ]
			then
				printf "%s\n" "DONE"|tee -a "${script_path}/install_${timestamp}.log"
			else
				printf "%s\n" "FAILED"|tee -a "${script_path}/install_${timestamp}.log"
				error_counter=$(( error_counter + 1 ))
			fi
		fi
		rt_query=0
}
### SET VARIABLES ##############
timestamp=$(date -u +%Y%m%d_%H%M%S)
script_path=$(cd "$(dirname "$0")" && pwd)
script_name=$(basename "$0")
current_trap=""
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
						"-env")	cmd_env=$(printf "%b" "${1}"|tr '[:upper:]' '[:lower:]')
							;;
						"-user")cmd_user=$1
							;;
						*)	printf "%s\n" "[${script_name}][ERROR][parser] Unexpected argument $1"
							printf "%s\n" "[${script_name}][INFO] To display the HELP run: ./install.sh -help"
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
trap_command '[ -n "${install_dep:-}" ] && rm -f -- "${install_dep}"'
install_dep=$(mktemp "${script_path}/install_dep.XXXXXX") || exit 1

### DISPLAY OUTPUT #######################
printf "%s\n" "[${script_name}][INFO] Start installation"|tee -a "${script_path}/install_${timestamp}.log"

### DETECT OS AND SET PATH ##
print_message "[${script_name}][INFO] Detecting operating system (uname -s)..."
os_uname=$(uname -s|tr '[:upper:]' '[:lower:]')
case "${os_uname}" in
	linux*)		rt_query=0
			;;
	darwin*)	rt_query=0
			if [ -d "/opt/homebrew" ]
			then
				install_prefix="/opt/homebrew"
			else
				install_prefix="/usr/local"
			fi
			gnu_path=""
			for pkg in coreutils gnu-sed grep findutils gawk diffutils gnu-tar
			do
				if [ -d "${install_prefix}/opt/${pkg}/libexec/gnubin" ]
				then
					gnu_path="${gnu_path}:${install_prefix}/opt/${pkg}/libexec/gnubin"
				fi
			done
			gnu_path=$(echo "${gnu_path}" | sed 's/^://')
			PATH="${gnu_path}:${PATH}"
			export PATH
						;;
	freebsd*|openbsd*|netbsd*|dragonfly*)
			rt_query=0
			gnu_path="/usr/local/gnu/bin:/usr/local/libexec/gnu"
			PATH="${gnu_path}:${PATH}"
			export PATH
			;;
	sunos*)		rt_query=0
			gnu_path="/usr/gnu/bin"
			PATH="${gnu_path}:${PATH}"
			export PATH
			;;
	aix*)		rt_query=0
			gnu_path="/opt/freeware/bin:/usr/linux/bin"
			PATH="${gnu_path}:${PATH}"
			export PATH
			;;
	hp-ux*|cygwin*|mingw*|msys*)
			rt_query=0
			;;
	*)	rt_query=1;;
esac
print_message

### CHECK DEPENDENCIES ######
while read program
do
	### CHECK IF PROGRAMM IS UNKNOWN ####
        check_program "${program}"
        rt_query=$?
        if [ "${rt_query}" -gt 0 ]
        then
        	### QUERY TO REPLACE COMMANDS WITH PACKAGE NAME ###########
        	case "${program}" in
        		"cmp")		printf "%s\n" "diffutils"  >>"${install_dep}"
        				;;
        		"flock")	case "${os_uname}" in
						darwin*) printf "%s\n" "flock" >>"${install_dep}" ;;
						*)       printf "%s\n" "util-linux" >>"${install_dep}" ;;
					esac
        				;;
        		"find"|"xargs")	printf "%s\n" "findutils"  >>"${install_dep}"
        				;;
        		"gpg")		printf "%s\n" "gnupg"  >>"${install_dep}"
        				;;
        		"netcat")	case "${os_uname}" in
						darwin*)	netcat_pkg="netcat"
								;;
						linux*)		### GET DISTRIBUTION
								if [ -f /etc/os-release ]
								then
									. /etc/os-release
								fi
								### SET PACKAGE NAME
								case "${ID}" in
									rhel|centos|rocky|almalinux)	netcat_pkg="nc" ;;
									fedora)                  	netcat_pkg="nmap-ncat" ;;
									arch|manjaro)            	netcat_pkg="openbsd-netcat" ;;
									*)                       	netcat_pkg="netcat-openbsd" ;;
								esac
								;;
						sunos*) 	netcat_pkg="gnu-netcat"
								;;
						*)		netcat_pkg="netcat"
								;;
					esac
        				printf "%s\n" "${netcat_pkg}" >>"${install_dep}"
        				;;
        		"openssl")	if [ "${cmd_env}" = "termux" ]
        				then
        					printf "%s\n" "openssl-tool"  >>"${install_dep}"
        				else
        					printf "%s\n" "${program}"  >>"${install_dep}"
        				fi
        				;;
        		*)		if grep -q "${program}" "${script_path}/config/coreutils.dep" && ! grep -q "coreutils" "${install_dep}"
					then
						printf "%s\n" "coreutils"  >>"${install_dep}"
					else
						printf "%s\n" "${program}"  >>"${install_dep}"
					fi
					;;
        	esac
        fi
done <"${script_path}"/control/install.dep
if [ -f "${install_dep}" ] && [ -s "${install_dep}" ]
then
	############################
	###IF APPS ARE TO INSTALL###
	###GET PACKAGE MANAGER######
	
	### CHECK PACKAGE MANAGERS #
	case "${cmd_env}" in
		"termux")	pkg_mngr="pkg"
				;;
		*)		pkg_mngr=""
				for pmgr in apk apt-get brew dnf pacman pkg pkg_add pkgin swinstall yum zypper
				do
					if [ -x "$(command -v "${pmgr}")" ]
					then
						pkg_mngr="${pmgr}";
						break
					fi
				done
				if [ -z "${pkg_mngr}" ]
				then
					###IF PACKAGING MANAGER DETECTION FAILED####
					error_counter=1
					no_of_programs=$(wc -l <"${install_dep}")
					printf "%s\n" "[${script_name}][ERROR][package] Couldn't detect the package management system used on this machine!"
					printf "%s\n" "[${script_name}][ERROR][package] Found ${no_of_programs} programs that need to be installed:"
					awk -v script_name="${script_name}" '{print "[" script_name "][ERROR][package] -> " $1}' "${install_dep}"
					printf "%s\n" "[${script_name}][ERROR][package] Install these programms first using your package management system and then run ${script_name} again."
					############################################
				fi
				;;
	esac

	if [ -n "${pkg_mngr}" ] && [ "${error_counter}" -eq 0 ]
	then
		### INSTALL MISSING PKGS #####
		while IFS= read -r program
		do
			printf "%s\n" "[${script_name}][INFO] Trying to install ${program} using ${pkg_mngr}..."
			case "${pkg_mngr}" in
				"apk")		apk add "${program}" ;;
				"apt-get")	apt-get -y install "${program}" ;;
				"brew")		brew install "${program}" ;;
				"dnf")		dnf -y install "${program}" ;;
				"pacman")	pacman --noconfirm -S "${program}" ;;
				"pkg")		pkg install -y "${program}" ;;
				"pkg_add")	env BATCH=Yes pkg_add -I -D automated "${program}" ;;
				"pkgin")	pkgin -y install "${program}" ;;
				"swinstall")	swinstall -x autoreboot=false "${program}" ;;
				"yum")		yum -y install "${program}" ;;
				"zypper")	zypper -n install "${program}" ;;
			esac
			rt_query=$?
			if [ "${rt_query}" -gt 0 ]
			then
				printf "%s\n" "[${script_name}][ERROR][packages] Error during installation of ${program} using ${pkg_mngr}"
				printf "%s\n" "[${script_name}][ERROR][packages] Maybe the program ${program} is available in a package with different name"
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
		printf "%s\n" "[${script_name}][INFO] Switch to user ${cmd_user}"
		su - "${cmd_user}" || exit 1
	fi
	### CREATE DIRECTORIES #######
	print_message "[${script_name}][INFO] Creating directories..."
	mkdir -p "${script_path}"/backup \
		"${script_path}"/control/keys \
		"${script_path}"/keys \
		"${script_path}"/proofs \
		"${script_path}"/tmp \
		"${script_path}"/trx \
		"${script_path}"/userdata || rt_query=1
	print_message

	### SAVE UMASK SETTINGS ######
	print_message "[${script_name}][INFO] Getting umask..."
	permissions_directories=$(printf "%03o" $(( 0777 & ~$(umask) ))) || rt_query=1
	permissions_files=$(printf "%03o" $(( 0666 & ~$(umask) ))) || rt_query=1
	print_message

	### IF OLD CONFIG THERE ######
	if [ -s "${script_path}"/control/config.conf ]
	then
		print_message "[${script_name}][INFO] Backup old config ( ->control/config.bak )..."
		mv -- "${script_path}"/control/config.conf "${script_path}"/control/config.bak || rt_query=1
		print_message
	fi

	### COPY TO PLACE ############
	print_message "[${script_name}][INFO] Copy install_config.conf to config.conf..."
	cp -- "${script_path}"/control/install_config.conf "${script_path}"/control/config.conf || rt_query=1
	print_message

	### CREATE TMP FILE ##########
	trap_command '[ -n "${config_tmp:-}" ] && rm -f -- "${config_tmp}"'
	config_tmp=$(mktemp "${script_path}/tmp/config_tmp.XXXXXX") || exit 1

	### WRITE PERMISSIONS ########
	print_message "[${script_name}][INFO] Write umask to config.conf..."
	sed "s/permissions_directories=permissions_directories/permissions_directories=${permissions_directories}/g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	sed "s/permissions_files=permissions_files/permissions_files=${permissions_files}/g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### SET DEFAULT THEME ########
	print_message "[${script_name}][INFO] Set default theme 'debian.rc' in config.conf..."
	sed "s#theme_file=theme_file#theme_file=debian.rc#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### SET PATHS ################
	print_message "[${script_name}][INFO] Define paths in config.conf..."
	sed "s#trx_path_input=trx_path_input#trx_path_input=${script_path}#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	sed "s#trx_path_output=trx_path_output#trx_path_output=${script_path}/tmp#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	sed "s#sync_path_input=sync_path_input#sync_path_input=${script_path}#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	sed "s#sync_path_output=sync_path_output#sync_path_output=${script_path}/tmp#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
	print_message

	### REWRITE CONFIG ###########
	if [ -s "${script_path}"/control/config.bak ]
	then
		### READ OLD CONFIG #########
		grep "path_input\|path_output\|theme_file\|small_trx\|cmd_" "${script_path}"/control/config.bak | while IFS= read -r config_line
		do
			if [ -n "${config_line:-}" ]
			then
				### EXTRACT CONFIG LINES ###############
				conf_var="${config_line%%=*}"
				conf_var_val="${config_line#*=}"
				if grep -q "^$(printf '%s\n' "${conf_var}"|sed 's/[.[\*^$]/\\&/g')=" "${script_path}"/control/config.conf
				then
					### IF OLD CONFIG LINES STILL EXISTS IN NEW CONFIG.CONF ####
					print_message "[${script_name}][INFO] Configure var \$${conf_var} in config.conf..."
					conf_line=$(grep "^${conf_var}" "${script_path}"/control/config.conf)
					if [ ! "${conf_line:-}" = "${conf_var}=${conf_var_val}" ]
					then
						sed "s#${conf_line}#${conf_var}=${conf_var_val}#g" "${script_path}"/control/config.conf >"${config_tmp}" && mv -- "${config_tmp}" "${script_path}"/control/config.conf || rt_query=1
					fi
					print_message
				else
					### IF OLD CONFIG LINE IS CMD_ VARIABLE ####################
					if echo "${conf_var}"|grep -q "^cmd_"
					then
						printf "%s\n" "${config_line}" >>"${script_path}"/control/config.conf
					fi
				fi
			fi
		done
	fi
	
	### WRITE GNU PATH IF REQUIRED ###########
	if [ -n "${gnu_path}" ]
	then
		print_message "[${script_name}][INFO] Write PATH for GNU tools..."
		printf "%s\n" "gnu_path=\"${gnu_path}\"" >>"${script_path}"/control/config.conf || rt_query=1
		print_message
	fi
	
	### CHECK FOR ERRORS #####################
	if [ "${error_counter}" -gt 0 ] && [ -s "${script_path}"/control/config.bak ]
	then
		print_message "[${script_name}][INFO] Restoring old config ( ->rename control/config.bak back to control/config.conf )..."
		mv -- "${script_path}"/control/config.bak "${script_path}"/control/config.conf || rt_query=1
		print_message
	fi

	### IF USER NEVER RAN GPG UNTIL NOW ######
	if [ ! -d ~/.gnupg/ ]
	then
		### RUN GPG ###################
		print_message "[${script_name}][INFO] Wake up gpg-agent..."
		gpgconf --launch gpg-agent >/dev/null 2>/dev/null || rt_query=1
		print_message
	fi

	### CONFIGURE GPG ########################
	if [ -s ~/.gnupg/gpg-agent.conf ]
	then
		print_message "[${script_name}][INFO] Checking gpg-agent.conf configuration..."
		while read config_line
		do
			if [ "$(grep -c "${config_line}" ~/.gnupg/gpg-agent.conf)" -eq 0 ]
			then
				echo "${config_line}" >>~/.gnupg/gpg-agent.conf
			fi
		done <"${script_path}"/control/gpg-agent.conf
		print_message
	else
		print_message "[${script_name}][INFO] Copy gpg-agent.conf to ~/.gnupg/ folder..."
		cp -- "${script_path}"/control/gpg-agent.conf ~/.gnupg/gpg-agent.conf || rt_query=1
		print_message
	fi

	### REMOVE USAGE OF KEYBOX ###############
	if [ -s ~/.gnupg/common.conf ]
	then
		print_message "[${script_name}][INFO] Remove 'use-keyboxd' entry in ~/.gnupg/common.conf..."
		sed 's/use-keyboxd//g' ~/.gnupg/common.conf >"${config_tmp}" && mv -- "${config_tmp}" ~/.gnupg/common.conf || rt_query=1
		print_message
	fi
fi
### DISPLAY OUTPUT #######################
printf "%s\n" "[${script_name}][INFO] Finished (errors:${error_counter})"|tee -a "${script_path}/install_${timestamp}.log"

