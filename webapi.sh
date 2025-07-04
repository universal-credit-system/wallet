#!/bin/sh
show_balance(){
			### GET BALANCES #####################################
			if [ -z "${cmd_sender}" ]
			then
				out_var=$(echo "-action show_balance -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw} -asset ${cmd_asset}"|./ucs_client.sh 2>/dev/null)
			else
				out_var=$(echo "-action show_balance -sender ${cmd_sender} -password ${cmd_pw} -asset ${cmd_asset}"|./ucs_client.sh 2>/dev/null)
			fi
			rt_query=$?

			### RETURNCODE ######################################
			return $rt_query
}
check_session(){
		### SET RT_QUERY ############################################
		rt_query=1

		### GET NOW STAMP ###########################################
		now_stamp=$(date +%s)

		### CHECK IF VARIABLES ARE EMPTY ############################
		if [ -n "${cmd_session_id}" ] && [ -n "${cmd_session_key}" ] && [ -n "${cmd_ip_address}" ]
		then
			### CHECK IF SESSION FILE EXISTS ############################
			if [ -s ${script_path}/webapi/sessions/${cmd_session_id}.sid ]
			then
				### TRY TO DECRYPT SESSION FILE #############################
				echo "${cmd_session_key}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --output ${script_path}/webapi/tmp/${cmd_session_id}.sid --decrypt ${script_path}/webapi/sessions/${cmd_session_id}.sid 1>/dev/null 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					### CHECK IF SESSION IS TIMED OUT ###########################
					session_string=$(head -1 ${script_path}/webapi/tmp/${cmd_session_id}.sid)
					check_ip=${session_string%%,*}
					if [ "${check_ip}" = "${cmd_ip_address}" ]
					then
						### SET VARIABLES ###########################################
						session_string=${session_string#*,}
						session_stamp=${session_string%%,*}

						### REMOVE SID FILE #########################################
						rm ${script_path}/webapi/sessions/${cmd_session_id}.sid

						### IF SESSION IS NOT EXPIRED ###############################
						if [ $(( now_stamp - session_stamp )) -le $(( minutes_logoff * 60 )) ]
						then
							### SET VARIABLES ###########################################
							session_string=${session_string#*,}
							cmd_user=${session_string%%,*}
							session_string=${session_string#*,}
							cmd_pin=${session_string%%,*}
							session_string=${session_string#*,}
							cmd_pw=${session_string%%,*}
							session_string=${session_string#*,}
							cmd_sender=${session_string%%,*}

							### RENEW STAMP #############################################
							echo "${cmd_ip_address},${now_stamp},${cmd_user},${cmd_pin},${cmd_pw},${cmd_sender}" >${script_path}/webapi/tmp/${cmd_session_id}.sid

							### ENCRYPT AND WRITE NEW SESSION FILE ######################
							echo "${cmd_session_key}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output ${script_path}/webapi/sessions/${cmd_session_id}.sid --passphrase-fd 0 ${script_path}/webapi/tmp/${cmd_session_id}.sid 2>/dev/null
							rt_query=$?
						else
							rt_query=1
						fi
					else
						rt_query=1
					fi
				fi
				rm ${script_path}/webapi/tmp/${cmd_session_id}.sid 2>/dev/null
			fi
		fi
		if [ $rt_query -gt 0 ]
		then
			### SET STATUS CODE ########################################
			status_code=401
		fi
		return $rt_query
}
create_session(){
		### SET RT_QUERY ############################################
		rt_query=1

		### CHECK IF IP_ADDRESS IS EMPTY ############################
		if [ -n "${cmd_ip_address}" ]
		then
			### CREATE A SESSION ID #####################################
			session_id=$(basename --suffix=.sid "$(mktemp XXXXXXXXXXXXXXXXXXXX --suffix=.sid -p ${script_path}/webapi/sessions/)")

			### SET SESSION KEY #########################################
			session_key=$(head -c 100 /dev/urandom|tr -dc A-Za-z0-9|head -c 20|sha224sum)
			session_key=${session_key%% *}

			### GET CURRENT TIMESTAMP ###################################
			now_stamp=$(date +%s)

			### WRITE CREDENTIALS TO FILE################################
			echo "${cmd_ip_address},${now_stamp},${cmd_user},${cmd_pin},${cmd_pw},${cmd_sender}" >${script_path}/webapi/tmp/${session_id}.tmp

			### WRITE SID FILE ##########################################
			echo "${session_key}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output ${script_path}/webapi/tmp/${session_id}.sid --passphrase-fd 0 ${script_path}/webapi/tmp/${session_id}.tmp 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				cmd_session_id=$session_id
				cmd_session_key=$session_key

				### MOVE SESSION FILE INTO SESSION FOLDER ###################
				mv ${script_path}/webapi/tmp/${session_id}.sid ${script_path}/webapi/sessions/${session_id}.sid
			else
				rm ${script_path}/webapi/sessions/${session_id}.sid 2>/dev/null
			fi
			rm ${script_path}/webapi/tmp/${session_id}.tmp 2>/dev/null
		fi
		return $rt_query
}
get_address(){
		### SET RT_QUERY ############################################
		rt_query=1

		###IF CMD SENDER IS SET HAND OVER############################
		if [ -z "${cmd_sender}" ]
		then
			###FOR EACH SECRET###########################################
			for secret_file in $(ls -1 ${script_path}/control/keys/|grep ".sct")
			do
				###GET ADDRESS OF SECRET#####################################
				key_file=${secret_file%%.*}

				###IF CMD_SENDER NOT SET#####################################
				###CALCULATE ADDRESS#########################################
				random_secret=$(cat ${script_path}/control/keys/${secret_file})
				key_login=$(echo "${cmd_user}_${random_secret}_${cmd_pin}"|sha224sum)
				key_login=${key_login%% *}
				key_login=$(echo "${key_login}_${cmd_pin}"|sha224sum)
				key_login=${key_login%% *}

				###IF ACCOUNT MATCHES########################################
				if [ "${key_file}" = "${key_login}" ]
				then
					user_address=$key_file
					rt_query=0
					break
				fi
			done
			#############################################################
		else
			rt_query=0
			user_address=$cmd_sender
		fi

		### SET STATUS CODE ########################################
		if [ $rt_query -gt 0 ]
		then
			status_code=400
		fi

		### RETURN IF FOUND #########################################
		return $rt_query
}
build_json(){
		### GET TOTAL LINES ###########################
		total_lines=$(echo "${out_var}"|wc -l)

		### GET PATTERN FOR FIRST ITEM ################
		entity_start=$(echo "${out_var}"|head -1)
		entity_start=${entity_start%%:*}
		entity_start=${entity_start%% *}

		if [ -n "${entity_start}" ]
		then
			### CALCULATE TOTAL NUMBER OF ENTITIES ########
			number_entities=$(echo "${out_var}"|grep -c "${entity_start}")
			number_last=$(( $total_lines / $number_entities ))

			### GET PATTERN FOR LAST ITEM #################
			entity_end=$(echo "${out_var}"|head -$number_last|tail -1)
			entity_end=${entity_end%%:*}
			entity_end=${entity_end%% *}

			### BUILD JSON ################################
			json_object_end=""
			json_array_end=""
			json_array_placeh=""
			if [ $number_entities -gt 1 ]
			then
				json_array_placeh="  "
				json_array_start="["
				json_array_end="${json_array_placeh}]\n"
			else
				json_array_start="{"
			fi
			json_body="  \"${cmd_action}\": ${json_array_start}\n"

			### SET INITAL VALUES OF COUNTER VARIABLES ####
			line_counter=0
			entity_counter=0

			### GO TROUGH OUTPUT LINE BY LINE #############
			for output_line in $(echo "${out_var}"|sed 's/ //g')
			do
				### RAISE COUNTER #############################
				line_counter=$(( line_counter + 1 ))

				### GET TAG AND VALUE #########################
				tag=${output_line%%:*}
				value=${output_line#*:}
				if [ $(echo $output_line|grep -c "${entity_start}") = 1 ] && [ $number_entities -gt 1 ]
				then
					json_body="${json_body}${json_array_placeh}  {\n"
				fi

				if [ ! $(echo $output_line|grep -c "${entity_end}") = 1 ]
				then
					### CHECK IF STRING OR NUMBER #################
					if [ $(echo "${value}"|grep -c '[^0-9.,]') = 0 ] && [ $(echo "${value}"|grep -c "^0.") = 0 ]
					then
						json_body="${json_body}${json_array_placeh}    \"$tag\": $value,\n"
					else
						json_body="${json_body}${json_array_placeh}    \"$tag\": \"$value\",\n"
					fi
				else
					entity_counter=$(( entity_counter + 1 ))
					if [ $number_entities -gt 1 ] && [ $entity_counter -lt $number_entities ]
					then
						json_object_end=","
					else
						if [ $number_entities -gt 1 ]
						then
							json_array_end="${json_array_placeh}],\n"
							json_object_end=""
						else
							json_object_end=","
						fi
					fi
					### CHECK IF STRING OR NUMBER #################
					if [ $(echo "${value}"|grep -c '[^0-9.,]') = 0 ] && [ $(echo "${value}"|grep -c "^0.") = 0 ]
					then
						json_body="${json_body}${json_array_placeh}    \"$tag\": $value\n${json_array_placeh}  }${json_object_end}\n"
					else
						json_body="${json_body}${json_array_placeh}    \"$tag\": \"$value\"\n${json_array_placeh}  }${json_object_end}\n"
					fi
				fi
			done
			out_json="${json_body}${json_array_end}"
		else
			out_json="  \"${cmd_action}\": {\n  },\n" 
		fi
}
print_json(){
		printf "%b" "{\n${out_json}  \"status\": {\n    \"status_code\": $status_code\n  }\n}\n"
}
### GET SCRIPT PATH ##################################
script_path=$(dirname $(readlink -f "${0}"))

### SOURCE CONFIG FILE ###############################
. ${script_path}/control/webapi.conf

### GET PID FOR TMP FILES ############################
my_pid=$$

### DEFINE DEFAULT HTTP RT CODE ######################
status_code=200

### DEFINE DEFAULT OUTPUT VARIABLE ###################
out_var=""
out_json=""

###CHECK FOR STDIN INPUT##############################
if [ ! -t 0 ]
then
	set -- $(cat) "$@"
fi

### CHECK IF GUI MODE OR CMD MODE AND ASSIGN VARIABLES ###
if [ $# -gt 0 ]
then
	### IF ANY VARIABLES ARE HANDED OVER SET INITIAL VALUES #######
	cmd_var=""
	cmd_action=""
	cmd_user=""
	cmd_pin=""
	cmd_pw=""
	cmd_sender=""
	cmd_receiver=""
	cmd_amount=""
	cmd_asset=""
	cmd_purpose=""
	cmd_path=""
	cmd_file=""
	cmd_session_id=""
	cmd_session_key=""
	cmd_ip_address=""
	cmd_node=0

	### GO THROUGH PARAMETERS ONE BY ONE ##########################
	while [ $# -gt 0 ]
	do
		### GET TARGET VARIABLES ######################################
		case $1 in
			"-action")	cmd_var=$1
					;;
			"-user")	cmd_var=$1
					;;
			"-pin")		cmd_var=$1
					;;
			"-password")	cmd_var=$1
					;;
			"-sender")	cmd_var=$1
					;;
			"-receiver")	cmd_var=$1
					;;
			"-amount")	cmd_var=$1
					;;
			"-asset")	cmd_var=$1
					;;
			"-purpose")	cmd_var=$1
					;;
			"-path")	cmd_var=$1
					;;
			"-file")	cmd_var=$1
					;;
			"-session_id")	cmd_var=$1
					;;
			"-session_key")	cmd_var=$1
					;;
			"-ip")		cmd_var=$1
					;;
			"-debug")	set -x
					set -v
					;;
			"-help")	more ${script_path}/control/webapi_HELP.txt
					exit 0
					;;
			*)		### SET TARGET VARIABLES ######################################
					case $cmd_var in
						"-action")	cmd_action=$1
								;;
						"-user")	cmd_user=$1
								;;
						"-pin")		cmd_pin=$1
								;;
						"-password")	cmd_pw=$1
								;;
						"-sender")	cmd_sender=$1
								;;
						"-receiver")	cmd_receiver=$1
								;;
						"-amount")	cmd_amount=$1
								;;
						"-asset")	cmd_asset=$1
								;;
						"-purpose")	cmd_purpose=$1
								;;
						"-path")	cmd_path=$1
								;;
						"-file")	cmd_file=$1
								;;
						"-session_id")	cmd_session_id=$1
								;;
						"-session_key")	cmd_session_key=$1
								;;
						"-ip")		cmd_ip_address=$1
								;;
						*)		### SET STATUS CODE ########################################
								status_code=400

								### DISPLAY JSON RESPONSE ################################
								print_json
								exit
								;;
					esac
					cmd_var=""
					;;
		esac
		shift
	done

	### SET USER ADDRESS ###############################
	user_address=""

	### STEP INTO SCRIPT HOMEDIR #######################
	cd ${script_path}/ || exit 2

	### CHECK USER ACTION ##############################
	case $cmd_action in
		"check_name")		### CHECK USERNAME IS STILL AVAILABLE ######################
					if [ -n "${cmd_user}" ]
					then
						name_hash=$(echo "${cmd_user}"|sha224sum)
						name_hash=${name_hash%% *}
						already_there=$(grep -c -w "${name_hash}" ${script_path}/control/accounts.db)

						### ANSWER IS FOR AJAX #####################################
						if [ $already_there = 0 ]
						then
							### SET STATUS CODE ########################################
							status_code=200
						else
							### SET STATUS CODE ########################################
							status_code=208
						fi
					else
						### SET STATUS CODE ########################################
						status_code=400
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"create_account")	### IF ENABLED ############################################
					if [ $enable_create_account = 1 ]
					then
						### TRIGGER USER CREATION #################################
						out_var=$(echo "-action create_user -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw}"|./ucs_client.sh 2>/dev/null)
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### BUILDOBJECT ##########################################
							build_json

							### SET STATUS CODE ########################################
							status_code=201
						else
							### SET STATUS CODE ########################################
							status_code=500
						fi
					else
						### SET STATUS CODE ########################################
						status_code=403
					fi
					### DISPLAY JSON RESPONSE ##################################
					print_json
					;;
		"create_trx")		### IF ENABLED ############################################
					if [ $enable_create_trx = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							if [ -e "${cmd_path}" ]
							then
								### STRIP SINGLE QUOTES FROM WALLET.PHP ESCAPESHELLARG ####
								cmd_purpose=$(cat ${cmd_path}|php -R 'echo urldecode($argn);') || rt_query=1
								if [ $rt_query = 0 ]
								then
									### WRITE PURPOSE TO FILE AND CONVERT######################
									echo "${cmd_purpose}" >${script_path}/webapi/tmp/decoded_purpose_${my_pid}.tmp
									dos2unix -f ${script_path}/webapi/tmp/decoded_purpose_${my_pid}.tmp 2>/dev/null

									### TRIGGER CLIENT ACTION #################################
									out_var=$(echo "-action create_trx -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw} -asset ${cmd_asset} -amount ${cmd_amount} -receiver ${cmd_receiver} -file ${script_path}/webapi/tmp/decoded_purpose_${my_pid}.tmp"|./ucs_client.sh 2>/dev/null)
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										### BUILDOBJECT ##########################################
										build_json

										### SET STATUS CODE ########################################
										http_rt=201
									fi
									
									### DELETE TMP FILE #######################################
									rm ${script_path}/webapi/tmp/decoded_purpose_${my_pid}.tmp 2>/dev/null
								fi
								if [ ! $rt_query = 0 ]
								then
									### SET STATUS CODE ########################################
									status_code=500
								fi
							else
								### SET STATUS CODE ########################################
								status_code=400
							fi
						fi
					else
						### SET STATUS CODE ########################################
						status_code=403
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"delete_account")	### IF ENABLED ############################################
					if [ $enable_delete_account = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### GET USER ADDRESS ######################################
							get_address
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								if [ -n "${cmd_sender}" ] && [ "${cmd_sender}" = "${user_address}" ]
								then
									### IF ONLY CMD_SENDER PROVIDE TRY TO FIND OUT USER################
									pubkey=$(ls -1 ${script_path}/userdata/${cmd_sender}/*pub.asc 2>/dev/null)
									if [ -z "${pubkey}" ]
									then
										cmd_user=$(echo "${pubkey}"|cut -d '_' -f2)
									fi
								fi
								### REMOVE USER ENTRY FROM ACCOUNTS.DB ###################
								### TO WORK WITH BSD SED -i IS NOT USED ##################
								cmd_user_hash=$(echo "${cmd_user}"|sha224sum)
								cmd_user_hash=${cmd_user_hash%% *}
								if [ $(grep -c "${cmd_user_hash}" ${script_path}/control/accounts.db) -gt 0 ]
								then
									sed "/${cmd_user_hash}/d" ${script_path}/control/accounts.db >${script_path}/control/${my_pid}_accounts.db
									mv ${script_path}/control/${my_pid}_accounts.db ${script_path}/control/accounts.db
								fi

								### GET FINGERPRINT OF PRIVATE KEY #######################
								key_fp=$(gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${user_address} 2>/dev/null|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p')
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									### DELETE PRIVATE KEY FROM KEYRING ######################
									gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										### DELETE ################################################
										rm ${script_path}/control/keys/${user_address} 2>/dev/null
										rm ${script_path}/control/keys/${user_address}.sct 2>/dev/null
										rm -R ${script_path}/userdata/${user_address} 2>/dev/null

										### DELETE SESSION ########################################
										rm ${script_path}/webapi/sessions/${cmd_session_id}.sid
									else
										### SET STATUS CODE ########################################
										status_code=500
									fi
								else
									### SET STATUS CODE ########################################
									status_code=500
								fi
							else
								### SET STATUS CODE ########################################
								status_code=500
							fi
						fi
					else
						### SET STATUS CODE ########################################
						status_code=403
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"download_account")	### IF ENABLED ############################################
					if [ $enable_download_account = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### GET USER ADDRESS ######################################
							get_address
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### PACK TAR FILE #########################################
								trxlist=$(ls -1 trx/${user_address}.* 2>/dev/null)
								tar -czf ${script_path}/webapi/tmp/${user_address}_profile.tar keys/${user_address} control/keys/${user_address} control/keys/${user_address}.sct proofs/${user_address} userdata/${user_address} $trxlist 2>/dev/null
								rt_query=$?
								###########################################################
								if [ $rt_query = 0 ]
								then
									### HANDOVER FILE PATH TO TRIGGER DOWNLOAD ################
									echo "${script_path}/webapi/tmp/${user_address}_profile.tar"
								else
									rt_query=1
								fi
							else
								rt_query=2
							fi
						else
							rt_query=3
						fi
					else
						rt_query=4
					fi
					if [ $rt_query -gt 0 ]
					then
						exit $rt_query
					fi
					;;
		"download_purpose")	### IF ENABLED ############################################
					if [ $enable_download_purpose = 1 ]
					then
						### CHECK IF PATH IS SET ##################################
						if [ -n "${cmd_path}" ]
						then
							exists=1
							if [ -s "${script_path}"/trx/"${cmd_path}" ] && [ -f "${script_path}/trx/${cmd_path}" ]
							then
								trx_file_path="${script_path}"/trx/"${cmd_path}"
							else
								if [ -s "${script_path}/${cmd_path}" ] && [ -f "${script_path}/${cmd_path}" ]
								then
									trx_file_path="${script_path}"/"${cmd_path}"
								else
									if [ -s "${cmd_path}" ] && [ -f "${cmd_path}" ]
									then
										trx_file_path="${cmd_path}"
									else
										exists=0
									fi
								fi
							fi
							if [ $exist = 1 ]
							then
								### CHECK IF SESSION IS ACTIVE ############################
								check_session
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									get_address
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										is_own_trx=$(grep -c "RCVR:${user_address}" $trx_file_path)
										if [ $is_own_trx = 1 ]
										then
											purpose_key_start=$(awk -F: '/:PRPK:/{print NR}' $trx_file_path)
											purpose_key_start=$(( purpose_key_start + 1 ))
											purpose_key_end=$(awk -F: '/:PRPS:/{print NR}' $trx_file_path)
											purpose_key_end=$(( purpose_key_end - 1 ))
											purpose_key_encrypted=$(sed -n "${purpose_key_start},${purpose_key_end}p" $trx_file_path)
											###GROUP COMMANDS TO OPEN FILE ONLY ONCE###################
											{
												echo "-----BEGIN PGP MESSAGE-----"
												echo ""
												echo "${purpose_key_encrypted}"
												echo "-----END PGP MESSAGE-----"
											} >"${script_path}"/webapi/tmp/history_purpose_key_encrypted_${my_pid}.tmp
											echo "${cmd_pw}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --output "${script_path}"/webapi/tmp/history_purpose_key_decrypted_${my_pid}.tmp --decrypt "${script_path}"/webapi/tmp/history_purpose_key_encrypted_${my_pid}.tmp 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												purpose_key=$(cat "${script_path}"/webapi/tmp/history_purpose_key_decrypted_${my_pid}.tmp)
												purpose_start=$(awk -F: '/:PRPS:/{print NR}' $trx_file_path)
												purpose_start=$(( purpose_start + 1 ))
												purpose_end=$(awk -F: '/BEGIN PGP SIGNATURE/{print NR}' $trx_file_path)
												purpose_end=$(( purpose_end - 1 ))
												purpose_encrypted=$(sed -n "${purpose_start},${purpose_end}p" $trx_file_path)
												###GROUP COMMANDS TO OPEN FILE ONLY ONCE###################
												{
													echo "-----BEGIN PGP MESSAGE-----"
													echo ""
													echo "${purpose_encrypted}"
													echo "-----END PGP MESSAGE-----"
												} >"${script_path}"/webapi/tmp/history_purpose_encrypted_${my_pid}.tmp
												file_name=$(basename "$trx_file_path")
												echo "${purpose_key}"|gpg --batch --no-tty --pinentry-mode loopback --output "${script_path}/webapi/tmp/purpose_decrypted_${file_name}" --passphrase-fd 0 --decrypt "${script_path}"/webapi/tmp/history_purpose_encrypted_${my_pid}.tmp 2>/dev/null
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													echo "${script_path}/webapi/tmp/purpose_decrypted_${file_name}"
												else
													rt_query=1
												fi
											else
												rt_query=2
											fi
											rm "${script_path}"/webapi/tmp/history_purpose_key_decrypted_${my_pid}.tmp 2>/dev/null
											rm "${script_path}"/webapi/tmp/history_purpose_key_encrypted_${my_pid}.tmp 2>/dev/null
											rm "${script_path}"/webapi/tmp/history_purpose_encrypted_${my_pid}.tmp 2>/dev/null
										else
											rt_query=3
										fi
									else
										rt_query=4
									fi
								else
									rt_query=5
								fi
							else
								rt_query=6
							fi
						else
							rt_query=7
						fi
					else
						rt_query=8
					fi
					if [ $rt_query -gt 0 ]
					then
						exit $rt_query
					fi
					;;
		"download_sync")	### IF ENABLED ############################################
					if [ $enable_download_sync = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							if [ -z "${cmd_sender}" ]
							then
								### TRIGGER CLIENT ACTION #################################
								syncfile=$(echo "-action create_sync -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw} -type partial"|./ucs_client.sh 2>/dev/null|tail -1|cut -d ':' -f2)
							else
								### TRIGGER CLIENT ACTION #################################
								syncfile=$(echo "-action create_sync -sender ${cmd_sender} -password ${cmd_pw} -type partial"|./ucs_client.sh 2>/dev/null|tail -1|cut -d ':' -f2)
							fi
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### HANDOVER PATH TO WEBAPI.PHP TO TRIGGER DOWNLOAD #######
								echo "${syncfile}"
							else
								rt_query=1
							fi
						else
							rt_query=2
						fi
					else
						rt_query=3
					fi
					if [ $rt_query -gt 0 ]
					then
						exit $rt_query
					fi
					;;
		"login_account")	### BUILD STRING TO IDENTIFY USER ##########################
					logger_string=$(echo "${cmd_ip_address}_${cmd_user}${cmd_sender}"|sha224sum)
					logger_string=${logger_string%% *}

					### GET STAMP FOR SESSION LOGGER FILE EXTENSION ############
					now_stamp=$(date +%s)

					### DELETE ALL LOCKS OF THE USER OLDER THAN ################
					find ${script_path}/webapi/logger/${logger_string}.* -maxdepth 1 -type f -mmin +${minutes_to_block} -delete >/dev/null 2>/dev/null

					### DELETE ALL LOGGER FILES OF THE USER OLDER THAN #########
					find ${script_path}/webapi/logger/tmp/${logger_string}.* -maxdepth 1 -type f -mmin +${minutes_to_watch} -delete >/dev/null 2>/dev/null

					### GET NUMBER OF SESSION LOGGER FILES FOR THIS USER #######
					total_failed_logons=$(ls -1 ${script_path}/webapi/logger/tmp 2>/dev/null|grep -c "${logger_string}")
					if [ $total_failed_logons -gt $max_failed_logons ]
					then
						touch ${script_path}/webapi/logger/${logger_string}.${now_stamp}
						rm ${script_path}/webapi/logger/tmp/${logger_string}.* 2>/dev/null
					fi

					### CHECK IF USER IS LOCKED ################################
					rt_query=$(find ${script_path}/webapi/logger/${logger_string}.* -maxdepth 1 -type f 2>/dev/null|wc -l)
					if [ $rt_query = 0 ]
					then
						show_balance
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### CREATE SESSION ########################################
							create_session
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### BUILD OBJECT ##########################################
								build_json
								
								### DELETE LOGGER SESSION FILES ###########################
								rm ${script_path}/webapi/logger/tmp/${logger_string}.* 2>/dev/null

								### DISPLAY SESSION INFO ##################################
								out_json="${out_json}  \"session\": {\n"
								out_json="${out_json}    \"session_id\": \"$cmd_session_id\",\n"
								out_json="${out_json}    \"session_key\": \"$cmd_session_key\"\n"
								out_json="${out_json}  },\n"
							else
								### SET STATUS CODE ########################################
								status_code=500
							fi
						else
							### WRITE SESSION LOGGER FILE FOR FAILED LOGON ############
							touch ${script_path}/webapi/logger/tmp/${logger_string}.${now_stamp}

							### SET STATUS CODE ########################################
							status_code=401
						fi
					else
						### SET STATUS CODE ########################################
						status_code=423
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"logout_account")	### CHECK IF SESSION IS ACTIVE ############################
					check_session
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### REMOVE SESSION ########################################
						rm ${script_path}/webapi/sessions/${cmd_session_id}.sid
					fi
					### DISPLAY JSON RESPONSE ################################
					print_json
					;;
		"print_status")		### SET STATUS CODE ########################################
					if [ -z "${cmd_purpose}" ]
					then
						status_code=400
					else
						status_code="${cmd_purpose}"
					fi

					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"read_sync")		### IF ENABLED ############################################
					if [ $enable_read_sync = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							if [ -z "${cmd_sender}" ]
							then
								### TRIGGER CLIENT ACTION #################################
								out_var=$(echo "-action read_sync -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw} -path ${cmd_path}"|./ucs_client.sh 2>/dev/null)
							else
								### TRIGGER CLIENT ACTION #################################
								out_var=$(echo "-action read_sync -sender ${cmd_sender} -password ${cmd_pw} -path ${cmd_path}"|./ucs_client.sh 2>/dev/null)
							fi
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### BUILD OBJECT ##########################################
								build_json
							else
								### SET STATUS CODE ########################################
								status_code=500
							fi
						fi
					else
						### SET STATUS CODE ########################################
						status_code=403
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"read_trx")		### IF ENABLED ############################################
					if [ $enable_read_trx = 1 ]
					then
						### CHECK IF SESSION IS ACTIVE ############################
						check_session
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							if [ -z "${cmd_sender}" ]
							then
								### TRIGGER CLIENT ACTION #################################
								out_var=$(echo "-action read_trx -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw} -path ${cmd_path}"|./ucs_client.sh 2>/dev/null)
							else
								### TRIGGER CLIENT ACTION #################################
								out_var=$(echo "-action read_trx -sender ${cmd_sender} -password ${cmd_pw} -path ${cmd_path}"|./ucs_client.sh 2>/dev/null)
							fi
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### BUILD OBJECT ##########################################
								build_json
							else
								### SET STATUS CODE ########################################
								status_code=500
							fi
						fi
					else
						### SET STATUS CODE ########################################
						status_code=403
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"show_addressbook")	### CHECK IF SESSION IS ACTIVE ############################
					out_var=$(echo "-action show_addressbook"|./ucs_client.sh 2>/dev/null)
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### BUILD OBJECT ##########################################
						build_json
					else
						### SET STATUS CODE ########################################
						status_code=500
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"show_balance")		### CHECK IF SESSION IS ACTIVE ############################
					check_session
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### SHOW BALANCE ##########################################
						show_balance
						
						### BUILD OBJECT ##########################################
						build_json
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"show_stats")		out_var=$(echo "-action show_stats"|./ucs_client.sh 2>/dev/null)
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### BUILD OBJECT ##########################################
						build_json
					else
						### SET STATUS CODE ########################################
						status_code=500
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"show_trx")		out_var=$(echo "-action show_trx -asset ${cmd_asset} -amount ${cmd_amount} -sender ${cmd_sender} -receiver ${cmd_receiver} -file ${cmd_path}"|./ucs_client.sh 2>/dev/null)
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### BUILD OBJECT ##########################################
						build_json
					else
						### SET STATUS CODE ########################################
						status_code=500
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		"sync_uca")		### CHECK IF SESSION IS ACTIVE ############################
					check_session
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						if [ -z "${cmd_sender}" ]
						then
							### TRIGGER CLIENT ACTION #################################
							out_var=$(echo "-action sync_uca -user ${cmd_user} -pin ${cmd_pin} -password ${cmd_pw}"|./ucs_client.sh 2>/dev/null)
						else
							### TRIGGER CLIENT ACTION #################################
							out_var=$(echo "-action sync_uca -sender ${cmd_sender} -password ${cmd_pw}"|./ucs_client.sh 2>/dev/null)
						fi
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### BUILD OBJECT ##########################################
							build_json
						else
							### SET STATUS CODE ########################################
							status_code=500
						fi
					fi
					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
		*)			### SET STATUS CODE ########################################
					status_code=400

					### DISPLAY JSON RESPONSE #################################
					print_json
					;;
	esac

	### AUTO LOGOFF ################################################################################
	find ${script_path}/webapi/sessions/ -maxdepth 1 -type f -mmin +${minutes_logoff} -delete >/dev/null 2>/dev/null

	### DO HOUSEKEEPING AND DELETE ALL TMP SESSION FILES OLDER THAN 5 MINUTES ######################
	find ${script_path}/webapi/tmp/ -maxdepth 1 -type f -mmin +${minutes_housekeeping} -delete >/dev/null 2>/dev/null
else
	### SET STATUS CODE ########################################
	status_code=400

	### DISPLAY STATUS IN JSON ################################
	print_json
fi

