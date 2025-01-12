#!/bin/sh
login_account(){
		login_name=$1
		login_pin=$2
		login_password=$3
		account_found=0
		handover_account=""

		###CALCULATE ADDRESS#########################################
		if [ ! "${cmd_sender}" = "" ]
		then
			key_login=${cmd_sender}
		fi

		###FOR EACH SECRET###########################################
		for secret_file in $(ls -1 -X ${script_path}/control/keys/|grep ".sct")
		do
			###GET ADDRESS OF SECRET#####################################
			key_file=${secret_file%%.*}

			###IF CMD_SENDER NOT SET#####################################
			if [ "${cmd_sender}" = "" ]
			then
				###CALCULATE ADDRESS#########################################
				random_secret=$(cat ${script_path}/control/keys/${secret_file})
				key_login=$(echo "${login_name}_${random_secret}_${login_pin}"|sha224sum)
				key_login=${key_login%% *}
				key_login=$(echo "${key_login}_${login_pin}"|sha224sum)
				key_login=${key_login%% *}
			fi

			###IF ACCOUNT MATCHES########################################
			if [ "${key_file}" = "${key_login}" ]
			then
				account_found=1
				echo "${key_file}" >>${script_path}/logon_${my_pid}.tmp
			fi
		done

		###CHECK IF ACCOUNT HAS BEEN FOUND###########################
		if [ $account_found = 1 ]
		then
			for user in $(cat ${script_path}/logon_${my_pid}.tmp)
			do
				###TEST KEY BY ENCRYPTING A MESSAGE##########################
				echo $login_name >${script_path}/account_${my_pid}.tmp
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --local-user ${user} -r ${user} --passphrase ${login_password} --pinentry-mode loopback --encrypt --sign ${script_path}/account_${my_pid}.tmp 1>/dev/null 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###REMOVE ENCRYPTION SOURCE FILE#############################
					rm ${script_path}/account_${my_pid}.tmp

					####TEST KEY BY DECRYPTING THE MESSAGE#######################
					gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase ${login_password} --pinentry-mode loopback --output ${script_path}/account_${my_pid}.tmp --decrypt ${script_path}/account_${my_pid}.tmp.gpg 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						extracted_name=$(cat ${script_path}/account_${my_pid}.tmp)
						if [ "${extracted_name}" = "${login_name}" ]
						then
							handover_account=$user
							user_logged_in=1
							break
						fi
					fi
				else
					rm ${script_path}/account_${my_pid}.tmp.gpg 2>/dev/null
				fi
			done
			###REMOVE TMP FILES##########################################
			rm ${script_path}/account_${my_pid}.tmp 2>/dev/null
			rm ${script_path}/account_${my_pid}.tmp.gpg 2>/dev/null
			rm ${script_path}/logon_${my_pid}.tmp 2>/dev/null

			###IF USER LOGGED IN#########################################
			if [ $user_logged_in = 1 ]
			then
				###SET USERPATH##############################################
				user_path="${script_path}/userdata/${handover_account}"

				###CHECK IF USERPATH EXISTS IF NOT SET UP####################
				if [ ! -d ${script_path}/userdata/${handover_account} ]
				then
					mkdir ${script_path}/userdata/${handover_account}
					mkdir ${script_path}/userdata/${handover_account}/temp
					mkdir ${script_path}/userdata/${handover_account}/temp/assets
					mkdir ${script_path}/userdata/${handover_account}/temp/keys
					mkdir ${script_path}/userdata/${handover_account}/temp/proofs
					mkdir ${script_path}/userdata/${handover_account}/temp/trx
				fi

				####DISPLAY WELCOME MESSAGE################################################
				if [ $gui_mode = 1 ]
				then
					###IF SUCCESSFULL DISPLAY WELCOME MESSAGE AND SET LOGIN VARIABLE###########
					dialog_login_welcome_display=$(echo $dialog_login_welcome|sed "s/<login_name>/${login_name}/g")
					dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --infobox "$dialog_login_welcome_display" 0 0
					sleep 1
				fi
			else
				if [ $gui_mode = 1 ]
				then
					###DISPLAY MESSAGE THAT LOGIN FAILED#######################################
					dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_login_fail" 0 0
					clear
				else
					exit 1
				fi
			fi
		else
			if [ $gui_mode = 1 ]
			then
				###DISPLAY MESSAGE THAT LOGIN FAILED#######################################
				dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_login_fail" 0 0
				clear
			else
				exit 1
			fi
		fi
		action_done=1
		make_ledger=1
}
create_keys(){
		create_name=$1
		create_pin=$2
		create_password=$3

		###SET REMOVE TRIGGER TO 0###################################
		key_remove=0

		###CREATE ADDRESS BY HASHING NAME,PASSWORD AND PIN###########
		random_secret=$(head -100 /dev/urandom|tr -dc "[:alnum:]"|head -c 512)
		create_name_hashed=$(echo "${create_name}_${random_secret}_${create_pin}"|sha224sum)
		create_name_hashed=${create_name_hashed%% *}
		verify_secret=$create_name_hashed
		create_name_hashed=$(echo "${create_name_hashed}_${create_pin}"|sha224sum)
		create_name_hashed=${create_name_hashed%% *}

		if [ $gui_mode = 1 ]
		then
			###DISPLAY PROGRESS BAR######################################
			echo "0"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create1" 0 0 0
		fi

		###GENERATE KEY##############################################
		gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --no-default-keyring --keyring=${script_path}/control/keyring.file --passphrase ${create_password} --pinentry-mode loopback --quick-gen-key ${create_name_hashed} rsa4096 sign,auth,encr none 1>/dev/null 2>/dev/null
		rt_query=$?
		if [ $rt_query = 0 ]
		then
			if [ $gui_mode = 1 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR############################
				echo "33"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create2" 0 0 0
			fi

			###CREATE USER DIRECTORY AND SET USER_PATH###########
			mkdir ${script_path}/userdata/${create_name_hashed}
			mkdir ${script_path}/userdata/${create_name_hashed}/temp
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/assets
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/keys
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/proofs
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/trx
			user_path="${script_path}/userdata/${create_name_hashed}"

			###EXPORT PUBLIC KEY#########################################
			key_remove=1
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc --passphrase ${create_password} --pinentry-mode loopback --export ${create_name_hashed}
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				if [ $gui_mode = 1 ]
				then
					###DISPLAY PROGRESS ON STATUS BAR############################
					echo "66"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create3" 0 0 0

					###CLEAR SCREEN
					clear
				fi

				###EXPORT PRIVATE KEY########################################
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_priv.asc --pinentry-mode loopback --passphrase ${create_password} --export-secret-keys ${create_name_hashed}
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###STEP INTO USER DIRECTORY##################################
					cd ${user_path}

					###CREATE TSA QUERY FILE#####################################
					openssl ts -query -data ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc -no_nonce -sha512 -out ${user_path}/${default_tsa}.tsq 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###GET TSA DATA##############################################
						tsa_config_line=$(grep "${default_tsa}" ${script_path}/control/tsa.conf)
						tsa_connect_string=$(echo "${tsa_config_line}"|cut -d ',' -f5)

						###SENT QUERY TO TSA#########################################
						curl --silent -H "Content-Type: application/timestamp-query" --data-binary @${default_tsa}.tsq ${tsa_connect_string} >${user_path}/${default_tsa}.tsr
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###STEP INTO CERTS DIRECTORY#################################
							cd ${script_path}/certs

							###DOWNLOAD LATEST TSA CERTIFICATES##########################
							tsa_cert_url=$(echo "${tsa_config_line}"|cut -d ',' -f2)
							wget -q -O tsa.crt ${tsa_cert_url}
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								tsa_cert_url=$(echo "${tsa_config_line}"|cut -d ',' -f3)
								wget -q -O cacert.pem ${tsa_cert_url}
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									###MOVE LATEST CERTIFICATES INTO TSA FOLDER##############
									mv ${script_path}/certs/tsa.crt ${script_path}/certs/${default_tsa}/tsa.crt
									mv ${script_path}/certs/cacert.pem ${script_path}/certs/${default_tsa}/cacert.pem

									###VERIFY TSA RESPONSE###################################
									openssl ts -verify -queryfile ${user_path}/${default_tsa}.tsq -in ${user_path}/${default_tsa}.tsr -CAfile ${script_path}/certs/${default_tsa}/cacert.pem -untrusted ${script_path}/certs/${default_tsa}/tsa.crt 1>/dev/null 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										###WRITE OUTPUT OF RESPONSE TO FILE######################
										openssl ts -reply -in ${user_path}/${default_tsa}.tsr -text >${user_path}/timestamp_check.tmp 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											###GET FILE STAMP###########################################
											file_stamp=$(date -u +%s --date="$(grep "Time stamp" ${user_path}/timestamp_check.tmp|cut -c 13-37)")
											if [ $gui_mode = 1 ]
											then
												###DISPLAY PROGRESS ON STATUS BAR###########################
												echo "100"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create4" 0 0 0
												clear
											fi
											rm ${user_path}/timestamp_check.tmp

											###CREATE PROOFS DIRECTORY AND COPY TSA FILES#######################
											mkdir ${script_path}/proofs/${create_name_hashed}
											mv ${user_path}/${default_tsa}.tsq ${script_path}/proofs/${create_name_hashed}/${default_tsa}.tsq
											mv ${user_path}/${default_tsa}.tsr ${script_path}/proofs/${create_name_hashed}/${default_tsa}.tsr

											###COPY EXPORTED PUB-KEY INTO KEYS-FOLDER###########################
											cp ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc ${script_path}/keys/${create_name_hashed}

											###COPY EXPORTED PRIV-KEY INTO CONTROL-FOLDER#######################
											cp ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_priv.asc ${script_path}/control/keys/${create_name_hashed}

											###WRITE SECRETS####################################################
											echo "${random_secret}" >${user_path}/${create_name_hashed}.sct
											echo "${verify_secret}" >${user_path}/${create_name_hashed}.scv

											###ONLY COPY RANDOM SECRET (VERIFY CAN BE RECALCULATED##############
											cp ${user_path}/${create_name_hashed}.sct ${script_path}/control/keys/${create_name_hashed}.sct 

											if [ $gui_mode = 1 ]
											then
												###DISPLAY NOTIFICATION THAT EVERYTHING WAS FINE#############
												dialog_keys_final_display=$(echo $dialog_keys_final|sed -e "s/<create_name>/${create_name}/g" -e "s/<create_name_hashed>/${create_name_hashed}/g" -e "s/<create_pin>/${create_pin}/g" -e "s/<file_stamp>/${file_stamp}/g")
												dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_final_display" 0 0
												key_remove=0
											else
												echo "USER:${create_name}"
												echo "PIN:${create_pin}"
												echo "PASSWORD:>${create_password}<"
												echo "ADRESS:${create_name_hashed}"
												echo "KEY_PUB:/keys/${create_name_hashed}"
												echo "KEY_PRV:/control/keys/${create_name_hashed}"
												echo "KEY_SECRET:/control/keys/${create_name_hashed}.sct"
												echo "KEY_VERIFY_SECRET:/userdata/${create_name_hashed}/${create_name_hashed}.scv"
												exit 0
											fi
										fi
									fi
								fi
							fi
						fi
					fi
				fi
			fi
		fi
		if [ ! $rt_query = 0 ]
		then
			if [ $key_remove = 1 ]
			then
				if [ ! "${create_name_hashed}" = "" ]
				then
					###REMOVE PROOFS DIRECTORY OF USER###########################
					rm -r ${script_path}/proofs/${create_name_hashed} 2>/dev/null

					###REMOVE USERDATA DIRECTORY OF USER#########################
					rm -r ${script_path}/userdata/${create_name_hashed} 2>/dev/null

					###REMOVE KEYS FROM KEYRING##################################
					key_fp=$(gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${create_name_hashed}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p')
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
						gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-keys ${key_fp} 2>/dev/null
					fi
				fi
				if [ $gui_mode = 0 ]
				then
					exit 1
				fi
			fi
		fi
		return $rt_query
}
make_signature(){
			transaction_message=$1
			trx_now=$2
			create_index_file=$3

			###CHECK IF INDEX FILE NEEDS TO BE CREATED#######################
			if [ $create_index_file = 0 ]
			then
				###IF NOT WRITE TRX MESSAGE TO FILE##############################
				message=${script_path}/trx/${handover_account}.${trx_now}
				message_blank=${user_path}/message_blank.dat
				touch ${message_blank}
				printf "%b" "${transaction_message}" >>${message_blank}
				#################################################################
			else
				###IF YES.....###################################################
				message=${script_path}/proofs/${handover_account}/${handover_account}.txt
				message_blank=${user_path}/message_blank.dat
				touch ${message_blank}

				###WRITE ASSETS TO INDEX FILE####################################
				for asset in $(cat ${user_path}/all_assets.dat)
				do
					asset_hash=$(sha256sum ${script_path}/assets/${asset})
					asset_hash=${asset_hash%% *}
					echo "assets/${asset} ${asset_hash}" >>${message_blank}
				done

				for key_file in $(cat ${user_path}/all_accounts.dat)
				do
					###WRITE KEYFILE TO INDEX FILE###################################
					key_hash=$(sha256sum ${script_path}/keys/${key_file})
					key_hash=${key_hash%% *}
					echo "keys/${key_file} ${key_hash}" >>${message_blank}
					#################################################################

					###ADD TSA FILES#################################################
					for tsa_file in $(ls -1 ${script_path}/proofs/${key_file}/*.ts*)
					do
						file=$(basename $tsa_file)
						file_hash=$(sha256sum ${script_path}/proofs/${key_file}/${file})
						file_hash=${file_hash%% *}
						echo "proofs/${key_file}/${file} ${file_hash}" >>${message_blank}
					done
				done

				####WRITE TRX LIST TO INDEX FILE#################################
				cat ${user_path}/*_index_trx.dat >>${message_blank} 2>/dev/null
			fi
			#################################################################

			###SIGN FILE AND REMOVE GPG WRAPPER##############################
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase ${login_password} --pinentry-mode loopback --digest-algo SHA512 --local-user ${handover_account} --clearsign ${message_blank} 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				mv ${message_blank}.asc ${message}
			fi
			#################################################################

			###PURGE FILES###################################################
			rm ${message_blank} 2>/dev/null
			rm ${message_blank}.asc 2>/dev/null

			return $rt_query
}
verify_signature(){
			file_to_verify=$1
			user_signed=$2
			signed_correct=0

			###CHECK GPG FILE#############################################
			gpg --status-fd 1 --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --verify ${file_to_verify} >${user_path}/gpg_verify.tmp 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				signed_correct=$(grep "GOODSIG" ${user_path}/gpg_verify.tmp|grep -c "${user_signed}")
				if [ $signed_correct = 0 ]
				then
					rt_query=1
				fi
			else
				rm ${file_to_verify} 2>/dev/null
			fi
			###############################################################

			rm ${user_path}/gpg_verify.tmp 2>/dev/null
			return $rt_query
}
check_input(){
		input_string=$1
		check_mode=$2
		rt_query=0
		length_counter=0

		###CHECK LENGTH OF INPUT STRING########################################
		length_counter=${#input_string}

		###IF INPUT LESS OR EQUAL 1 DISPLAY NOTIFICATION#######################
		if [ $length_counter -lt 1 ]
		then
			if [ $gui_mode = 1 ]
			then
				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg2" 0 0
				rt_query=1
			else
				exit 1
			fi
		fi
		#######################################################################

		case $check_mode in
			 0 )	###CHECK IF ONLY CHARS ARE IN INPUT STRING###################
				string_check=$(echo "${input_string}"|grep -c '[^[:alnum:]]')

				###IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION##############
				if [ $string_check = 1 ]
				then
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg3" 0 0
						rt_query=1
					else
						exit 1
					fi
				fi
				;;
			1 )	###CHECK IF ONLY DIGITS ARE IN INPUT STRING############################
				string_check=$(echo "${input_string}"|grep -c '[^[:digit:]]')

				###IF NOT CHECK IF ALPHA NUM ARE IN INPUT STRING#######################
				if [ $string_check = 0 ]
				then
					###CHECK IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION########
					string_check=$(echo "${input_string}"|grep -c '[^[:alnum:]]')
				fi

				###IF DIGIT CHECK FAILS DISPLAY NOTIFICATION###########################
				if [ $string_check = 1 ]
				then
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg1" 0 0
						rt_query=1
					else
						exit 1
					fi
				fi
				#######################################################################
				;;
			*)	exit 1
				;;
		esac
		return $rt_query
}
build_ledger(){
		new=$1

		###REDIRECT OUTPUT FOR PROGRESS BAR IF REQUIRED#####
		if [ $gui_mode = 1 ]
		then
			progress_bar_redir="1"
		else
			progress_bar_redir="2"
		fi

		###SET DATES##################################
		now=$(date -u +%Y%m%d)

		###CHECK IF OLD LEDGER THERE########################
		old_ledger_there=$(ls -1 ${user_path}/|grep -c "ledger.dat")

		###CHECK IF OLD SCORETABLE IS THERE#################
		old_scoretable_there=$(ls -1 ${user_path}/|grep -c "scoretable.dat")

		if [ $old_ledger_there -gt 0 ] && [ $old_scoretable_there -gt 0 ] && [ $new = 0 ]
		then
			###GET LATEST LEDGER AND EXTRACT DATE###############
			last_ledger=$(ls -1 ${user_path}/|grep "ledger.dat"|tail -1)
			last_ledger_date=${last_ledger%%_*}
			last_ledger_date_stamp=$(date -u +%s --date="${last_ledger_date}")

			###SET DATESTAMP TO NEXTDAY OF LAST LEDGER##########
			date_stamp=$(( last_ledger_date_stamp + 86400 ))

			###CALCULATE DAY COUNTER############################
			date_stamp_last=$(date -u +%s --date="${start_date}")
			no_seconds_last=$(( date_stamp - date_stamp_last ))
			day_counter=$(( no_seconds_last / 86400 ))
		else
			###SET DATESTAMP####################################
			date_stamp=$(date -u +%s --date=$(date -u +%Y%m%d --date=@$(grep -f ${user_path}/depend_accounts.dat ${user_path}/all_accounts_dates.dat|sort -t ' ' -k2|head -1|cut -d ' ' -f2)))
			date_stamp_yesterday=$(date +%Y%m%d --date="$(date -u +%Y%m%d --date=@${date_stamp}) - 1 day")

			###EMPTY LEDGER#####################################
			rm ${user_path}/*_ledger.dat 2>/dev/null
			touch ${user_path}/${date_stamp_yesterday}_ledger.dat
			####################################################

			###EMPTY SCORE TABLE################################
			rm ${user_path}/*_scoretable.dat 2>/dev/null
			touch ${user_path}/${date_stamp_yesterday}_scoretable.dat

			###EMPTY INDEX FILE#################################
			rm ${user_path}/*_index_trx.dat 2>/dev/null
			####################################################

			###EMPTY IGNORE TRX#################################
			rm ${user_path}/ignored_trx.dat 2>/dev/null
			####################################################

			###CALCULATE DAY COUNTER############################
			date_stamp_last=$(date -u +%s --date="${start_date}")
			no_seconds_last=$(( date_stamp - date_stamp_last ))
			day_counter=$(( no_seconds_last / 86400 ))
		fi
		####################################################

		###SET FOCUS########################################
		focus=$(date -u +%Y%m%d --date=@${date_stamp})
		now_stamp=$(date +%s)
		####################################################

		###CREATE LIST OF ASSETS CREATED BEFORE THAT DAY####
		previous_day=$(date +%Y%m%d --date="${focus} - 1 day")
		awk -F. -v date_stamp="${date_stamp}" '$2 < date_stamp' ${user_path}/all_assets.dat >${user_path}/assets.tmp

		###MAKE LEDGER ENTRIES FOR ASSETS#####################
		if [ -s ${user_path}/assets.tmp ]
		then
			cd ${script_path}/assets

			###CREATE LEDGER ENTRY FOR NON FUNGIBLE ASSET###############
			for asset in $(cat ${user_path}/assets.tmp)
			do
				if [ ! "${asset}" = "${main_asset}" ]
				then
					asset_data=$(cat ${script_path}/assets/${asset})
					asset_fungible=$(echo "$asset_data"|grep "asset_fungible=")
					asset_fungible=${asset_fungible#*=}
					if [ $asset_fungible = 0 ]
					then
						asset_owner=$(echo "$asset_data"|grep "asset_owner=")
						asset_owner=${asset_owner#*=}
						asset_quantity=$(echo "$asset_data"|grep "asset_quantity=")
						asset_quantity=${asset_quantity#*=}
						already_exists=$(grep -c "${asset}:${asset_owner}=" ${user_path}/${previous_day}_ledger.dat)
						if [ $already_exists = 0 ]
						then
							echo "${asset}:${asset_owner}=${asset_quantity}" >>${user_path}/${previous_day}_ledger.dat
						fi
					else
						already_exists=$(grep -c "${main_asset}:${asset}=" ${user_path}/${previous_day}_ledger.dat)
						if [ $already_exists = 0 ]
						then
							echo "${main_asset}:${asset}=0" >>${user_path}/${previous_day}_ledger.dat
						fi
						already_exists=$(grep -c "${asset}:${main_asset}=" ${user_path}/${previous_day}_ledger.dat)
						if [ $already_exists = 0 ]
						then
							echo "${asset}:${main_asset}=0" >>${user_path}/${previous_day}_ledger.dat
						fi
					fi
				fi
			done
		fi
		rm ${user_path}/assets.tmp 2>/dev/null

		if [ $focus -le $now ]
		then
			###INIT STATUS BAR##################################
			now_date_status=$(date -u +%s --date=${now})
			now_date_status=$(( now_date_status + 86400 ))
			no_seconds_total=$(( now_date_status - date_stamp ))
			no_days_total=$(( no_seconds_total / 86400 ))
			percent_per_day=$(echo "scale=10; 100 / ${no_days_total}"|bc)
			current_percent=0
			current_percent_display=0
			current_percent=$(echo "scale=10;${current_percent} + ${percent_per_day}"|bc)
			current_percent_display=$(echo "${current_percent} / 1"|bc)
		else
			progress_bar_redir="2"
		fi
		####################################################

		###AS LONG AS FOCUS LESS OR EQUAL YET..#############
		while [ $focus -le $now ]
		do
			###STATUS BAR####################################
			if [ $gui_mode = 1 ]
			then
				echo "$current_percent_display"
			fi
			current_percent=$(echo "scale=10;${current_percent} + ${percent_per_day}"|bc)
			current_percent_display=$(echo "${current_percent} / 1"|bc)
			#################################################

			###CALCULATE CURRENT COINLOAD####################
			if [ $day_counter = 1 ]
			then
				coinload=$initial_coinload
			else
				coinload=1
			fi
			#################################################

			###MOVE FILENAMES TO NEXT DAY####################
			previous_day=$(date +%Y%m%d --date="${focus} - 1 day")
			cp ${user_path}/${previous_day}_ledger.dat ${user_path}/${focus}_ledger.dat
			cp ${user_path}/${previous_day}_scoretable.dat ${user_path}/${focus}_scoretable.dat

			###GRANT COINLOAD OF THAT DAY####################
			grep -v "${main_asset}" ${user_path}/all_assets.dat|grep -v -f - ${user_path}/${focus}_ledger.dat|LC_NUMERIC=C.utf-8 awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' >${user_path}/${focus}_ledger.tmp
			if [ -s ${user_path}/${focus}_ledger.tmp ]
			then
				rm ${user_path}/${focus}_ledger_others.tmp 2>/dev/null
				touch ${user_path}/${focus}_ledger_others.tmp
				grep -v "${main_asset}" ${user_path}/all_assets.dat|grep -f - ${user_path}/${focus}_ledger.dat >${user_path}/${focus}_ledger_others.tmp
				cat ${user_path}/${focus}_ledger.tmp ${user_path}/${focus}_ledger_others.tmp >${user_path}/${focus}_ledger.dat
				rm ${user_path}/${focus}_ledger_others.tmp
			fi
			rm ${user_path}/${focus}_ledger.tmp 2>/dev/null

			###UPDATE SCORETABLE#############################
			LC_NUMERIC=C.utf-8 awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' ${user_path}/${focus}_scoretable.dat >${user_path}/${focus}_scoretable.tmp
			if [ -s ${user_path}/${focus}_scoretable.tmp ] || [ -e ${user_path}/${focus}_scoretable.tmp ]
			then
				mv ${user_path}/${focus}_scoretable.tmp ${user_path}/${focus}_scoretable.dat 2>/dev/null
			fi

			###CREATE LIST OF ACCOUNTS CREATED THAT DAY######
			touch ${user_path}/accounts.tmp
			date_stamp_tomorrow=$(( date_stamp + 86400 ))
			grep -f ${user_path}/depend_accounts.dat ${user_path}/all_accounts_dates.dat|awk -F' ' -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 >= date_stamp && $2 < date_stamp_tomorrow {print $1}' >${user_path}/accounts.tmp

			###CREATE LEDGER AND SCORETABEL ENTRY FOR USER###
			awk -v main_asset="${main_asset}" '{print main_asset":"$1"=0"}' ${user_path}/accounts.tmp >>${user_path}/${focus}_ledger.dat
			awk -v main_asset="${main_asset}" '{print main_asset":"$1"=0"}' ${user_path}/accounts.tmp >>${user_path}/${focus}_scoretable.dat
			rm ${user_path}/accounts.tmp 2>/dev/null

			###CREATE LIST OF ASSETS CREATED THAT DAY########
			awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 >= date_stamp && $2 < date_stamp_tomorrow' ${user_path}/all_assets.dat >${user_path}/assets.tmp

			###MAKE LEDGER ENTRIES FOR ASSETS################
			if [ -s ${user_path}/assets.tmp ]
			then
				cd ${script_path}/assets
				###CREATE LEDGER ENTRY FOR NON FUNGIBLE ASSETS#############
				for non_fungible_asset in $(grep -l "asset_fungible=0" $(cat ${user_path}/assets.tmp))
				do
					asset_quantity=$(grep "asset_quantity=" $non_fungible_asset)
					asset_quantity=${asset_quantity#*=}
					asset_owner=$(grep "asset_owner=" $non_fungible_asset)
					asset_owner=${asset_owner#*=}
					echo "${non_fungible_asset}:${asset_owner}=${asset_quantity}" >>${user_path}/${focus}_ledger.dat
				done
				###CREATE LEDGER ENTRY FOR FUNGIBLE ASSETS#################
				grep -l "asset_fungible=1" $(cat ${user_path}/assets.tmp)|awk -F. -v main_asset="${main_asset}" '{if ($1 != main_asset) print main_asset":"$1"."$2"=0"}' >>${user_path}/${focus}_ledger.dat
				grep -l "asset_fungible=1" $(cat ${user_path}/assets.tmp)|awk -F. -v main_asset="${main_asset}" '{if ($1 != main_asset) print $1"."$2":"main_asset"=0"}' >>${user_path}/${focus}_ledger.dat
				rm ${user_path}/assets.tmp
			fi

			###GO TROUGH TRX OF THAT DAY LINE BY LINE#####################
			for trx_filename in $(awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 > date_stamp && $2 < date_stamp_tomorrow' ${user_path}/depend_trx.dat) 
			do
				is_fungible=0

				###EXRACT DATA FOR CHECK######################################
				trx_file="${script_path}/trx/${trx_filename}"
				trx_stamp=$(awk -F: '/:TIME:/{print $3}' $trx_file)
				trx_sender=$(awk -F: '/:SNDR:/{print $3}' $trx_file)
				trx_receiver=$(awk -F: '/:RCVR:/{print $3}' $trx_file)
				trx_hash=$(sha256sum $trx_file)
				trx_hash=${trx_hash%% *}
				trx_path="trx/${trx_filename}"
				##############################################################

				###CHECK IF INDEX-FILE EXISTS#################################
				if [ -s ${script_path}/proofs/${trx_sender}/${trx_sender}.txt ] || [ "${trx_sender}" = "${handover_account}" ]
				then
					###CHECK IF TRX IS SIGNED BY USER#############################
					is_signed=$(grep -c "trx/${trx_filename} ${trx_hash}" ${script_path}/proofs/${trx_sender}/${trx_sender}.txt)
					if [ $is_signed -gt 0 ] || [ "${trx_sender}" = "${handover_account}" ]
					then
						###EXTRACT TRX AMOUNT#########################################
						trx_amount=$(awk -F: '/:AMNT:/{print $3}' $trx_file)
						trx_asset=$(awk -F: '/:ASST:/{print $3}' $trx_file)
						sender_in_ledger=$(grep -c "${trx_asset}:${trx_sender}" ${user_path}/${focus}_ledger.dat)
						if [ $sender_in_ledger = 1 ]
						then
							###GET ACCOUNT BALANCE########################################
							account_balance=$(grep "${trx_asset}:${trx_sender}" ${user_path}/${focus}_ledger.dat)
							account_balance=${account_balance#*=}

							###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
							account_check_balance=$(echo "${account_balance} - ${trx_amount}"|bc|sed 's/^\./0./g')
							enough_balance=$(echo "${account_check_balance} >= 0"|bc)

							###CHECK SCORE################################################
							if [ "${trx_asset}" = "${main_asset}" ]
							then
								###SCORING####################################################
								sender_score_balance=$(grep "${trx_asset}:${trx_sender}" ${user_path}/${focus}_scoretable.dat)
								sender_score_balance=${sender_score_balance#*=}
								is_score_ok=$(echo "${sender_score_balance} >= ${trx_amount}"|bc)
								##############################################################
							else
								is_score_ok=1
							fi

							###CHECK IF BALANCE AND SCORE ARE OK##########################
							if [ $enough_balance = 1 ] && [ $is_score_ok = 1 ]
							then
								####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)############
								echo "${trx_path} ${trx_hash}" >>${user_path}/${focus}_index_trx.dat
								##############################################################

								###SET BALANCE FOR SENDER#####################################
								account_new_balance=$account_check_balance
								sed -i "s/${trx_asset}:${trx_sender}=${account_balance}/${trx_asset}:${trx_sender}=${account_new_balance}/g" ${user_path}/${focus}_ledger.dat
								##############################################################

								###SET SCORE FOR SENDER#######################################
								if [ "${trx_asset}" = "${main_asset}" ]
								then
									sender_new_score_balance=$(echo "${sender_score_balance} - ${trx_amount}"|bc|sed 's/^\./0./g')
									sed -i "s/${trx_asset}:${trx_sender}=${sender_score_balance}/${trx_asset}:${trx_sender}=${sender_new_score_balance}/g" ${user_path}/${focus}_scoretable.dat
								fi
								##############################################################

								###CHECK IF RECEIVER IS ASSET#################################
								is_asset=$(grep -c "${trx_receiver}" ${user_path}/all_assets.dat)
								if [ $is_asset = 1 ]
								then
									is_fungible=$(grep -c "asset_fungible=1" ${script_path}/assets/${trx_receiver})
								fi
								##############################################################

								###CHECK IF RECEIVER IS IN LEDGER#############################
								receiver_in_ledger=$(grep -c "${trx_asset}:${trx_receiver}" ${user_path}/${focus}_ledger.dat)
								if [ $receiver_in_ledger = 0 ]
								then
									###CHECK IF RECEIVER IS IN LEDGER WITH UCC BALANCE############
									receiver_in_ledger=$(grep -c "${main_asset}:${trx_receiver}" ${user_path}/${focus}_ledger.dat)
									if [ $receiver_in_ledger = 1 ]
									then
										###CHECK IF RECEIVER IS ASSET#################################
										if [ $is_asset = 1 ]
										then
											###CHECK IF ASSET IS FUNGIBLE################################
											if [ $is_fungible = 1 ]
											then
												echo "${trx_asset}:${trx_receiver}=0" >>${user_path}/${focus}_ledger.dat
											else
												receiver_in_ledger=0
											fi
										else
											###WRITE LEDGER ENTRY########################################
											echo "${trx_asset}:${trx_receiver}=0" >>${user_path}/${focus}_ledger.dat
										fi
									fi
								fi
								##############################################################
								if [ $receiver_in_ledger = 1 ]
								then
									###GET CONFIRMATIONS##########################################
									total_confirmations=$(grep -s -l "trx/${line} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${trx_sender}\|${trx_receiver}")

									###ADD 1 CONFIRMATION FOR OWN#################################
									if [ ! "${trx_sender}" = "${handover_account}" ] && [ ! "${trx_receiver}" = "${handover_account}" ]
									then
										total_confirmations=$(( total_confirmations + 1 ))
									fi

									###CHECK CONFIRMATIONS########################################
									if [ $total_confirmations -ge $confirmations_from_users ]
									then
										###SET SCORE FOR SENDER#######################################
										if [ "${trx_asset}" = "${main_asset}" ]
										then
											###CHECK IF NEW SCORE IS GREATER THAN BALANCE#################
											is_greater_balance=$(echo "${sender_new_score_balance} > ${account_new_balance}"|bc)
											if [ $is_greater_balance = 1 ]
											then
												sender_score_balance="${account_new_balance}"
											fi
											##############################################################
											sender_score_balance=$(echo "${sender_score_balance}"|sed 's/^\./0./g')
											sed -i "s/${trx_asset}:${trx_sender}=${sender_new_score_balance}/${trx_asset}:${trx_sender}=${sender_score_balance}/g" ${user_path}/${focus}_scoretable.dat
										fi
										##############################################################
										###SET BALANCE FOR RECEIVER###################################
										receiver_old_balance=$(grep "${trx_asset}:${trx_receiver}" ${user_path}/${focus}_ledger.dat)
										receiver_old_balance=${receiver_old_balance#*=}
										receiver_new_balance=$(echo "${receiver_old_balance} + ${trx_amount}"|bc|sed 's/^\./0./g')
										sed -i "s/${trx_asset}:${trx_receiver}=${receiver_old_balance}/${trx_asset}:${trx_receiver}=${receiver_new_balance}/g" ${user_path}/${focus}_ledger.dat
										##############################################################
										###CHECK IF EXCHANGE REQUIRED#################################
										if [ $is_asset = 1 ] && [ $is_fungible = 1 ]
										then
											###EXCHANGE###################################################
											asset_type_price=$(grep "asset_price=" ${script_path}/assets/${trx_asset})
											asset_type_price=${asset_type_price#*=}
											asset_price=$(grep "asset_price=" ${script_path}/assets/${trx_receiver})
											asset_price=${asset_price#*=}
											asset_value=$(echo "scale=9; ${trx_amount} * ${asset_type_price} / ${asset_price}"|bc|sed 's/^\./0./g')
											##############################################################
											###WRITE ENTRY TO LEDGER FOR EXCHANGE#########################
											receiver_in_ledger=$(grep -c "${trx_receiver}:${trx_sender}" ${user_path}/${focus}_ledger.dat)
											if [ $receiver_in_ledger = 1 ]
											then
												sender_old_balance=$(grep "${trx_receiver}:${trx_sender}" ${user_path}/${focus}_ledger.dat)
												sender_old_balance=${sender_old_balance#*=}
												sender_new_balance=$(echo "${sender_old_balance} + ${asset_value}"|bc|sed 's/^\./0./g')
												sed -i "s/${trx_receiver}:${trx_sender}=${sender_old_balance}/${trx_receiver}:${trx_sender}=${sender_new_balance}/g" ${user_path}/${focus}_ledger.dat
											else
												echo "${trx_receiver}:${trx_sender}=${asset_value}" >>${user_path}/${focus}_ledger.dat
											fi
											##############################################################
										fi
										##############################################################
									fi
									##############################################################
								else
									echo "${trx_filename}" >>${user_path}/ignored_trx.dat
								fi
								##############################################################
							else
								echo "${trx_filename}" >>${user_path}/ignored_trx.dat
							fi
							##############################################################
						else
							echo "${trx_filename}" >>${user_path}/ignored_trx.dat
						fi
						##############################################################
					else
						echo "${trx_filename}" >>${user_path}/ignored_trx.dat
					fi
					##############################################################
				else
					echo "${trx_filename}" >>${user_path}/ignored_trx.dat
				fi
				##############################################################
			done

			###RAISE VARIABLES FOR NEXT RUN###############################
			date_stamp=$(( date_stamp + 86400 ))
			focus=$(date -u +%Y%m%d --date=@${date_stamp})
			day_counter=$(( day_counter + 1 ))
			##############################################################
		done|dialog --title "$dialog_ledger_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_ledger" 0 0 0 2>/dev/null 1>&${progress_bar_redir}
		if [ $gui_mode = 0 ]
		then
			###CHECK IF BALANCE NEED TO BE DISPLAYED######################
			show_balance=0
			case $cmd_action in
				"create_trx")	show_balance=1
						;;
				"read_trx")	show_balance=1
						;;
				"create_sync")	show_balance=1
						;;
				"read_sync")	show_balance=1
						;;
				"show_balance")	show_balance=1
						;;
			esac
			if [ $show_balance = 1 ]
			then
				last_ledger=$(ls -1 ${user_path}/|grep "ledger.dat"|tail -1)
				for balance in $(grep "${handover_account}" ${user_path}/${last_ledger})
				do
					echo "BALANCE_${now_stamp}:${balance}"
					asset_type=${balance%%:*}
					if [ "${asset_type}" = "${main_asset}" ]
					then
						cmd_output=$(grep "${asset_type}:${handover_account}" ${user_path}/${last_ledger})
					else
						cmd_output=$balance
					fi
				done
				echo "UNLOCKED_BALANCE_${now_stamp}:${cmd_output}"
				if [ "${cmd_action}" = "show_balance" ]
				then
					exit 0
				fi
			fi
			##############################################################
		fi
}
check_archive(){
			path_to_tarfile=$1
			check_mode=$2

			###TOUCH FILES TO AVOID NON EXISTENT FILES####################
			touch ${user_path}/tar_check.tmp
			touch ${user_path}/files_to_fetch.tmp

			###CHECK TARFILE CONTENT######################################
			tar -tvf $path_to_tarfile|grep -v '//*$' >${user_path}/tar_check_temp.tmp
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				###REMOVE DOUBLE-ENTRIES IN TAR-FILE##########################
				sort -u ${user_path}/tar_check_temp.tmp >${user_path}/tar_check_full.tmp

				###WRITE FILE LIST############################################
				awk '{print $6}' ${user_path}/tar_check_full.tmp >${user_path}/tar_check.tmp

				###CHECK FOR EXECUTABLES######################################
				executables_there=$(awk '{print $1}' ${user_path}/tar_check_full.tmp|grep -v "d"|grep -c "x")
				if [ $executables_there -eq 0 ]
				then
					###CHECK FOR BAD CHARACTERS###################################
					bad_chars_there=$(cat ${user_path}/tar_check.tmp|sed 's#/##g'|sed 's/\.//g'|grep -c '[^[:alnum:]]')
					if [ $bad_chars_there -eq 0 ]
					then
						files_not_homedir=""

						###GET HASH LIST OF EXISTING KEYS#############################
						sha224sum $(ls -1 ${script_path}/keys/*)|cut -d ' ' -f1 >${user_path}/files_to_fetch_keys.tmp

						###GO THROUGH CONTENT LIST LINE BY LINE#######################
						while read line
						do
							###CHECK IF FILES MATCH TARGET-DIRECTORIES AND IGNORE OTHERS##
							files_not_homedir=${line%%/*}
							case $files_not_homedir in
								"assets")	if [ $import_fungible_assets = 1 ] || [ $import_non_fungible_assets = 1 ]
										then
											if [ ! -d ${script_path}/$line ]
											then
												file_full=${line#*/}
												file_ext=${file_full#*.}
												file_ext_correct=$(echo $file_ext|grep -c '[^[:digit:]]')
												if [ $file_ext_correct -gt 0 ]
												then
													rt_query=1
												else
													if [ $check_mode = 0 ]
													then
														if [ ! -s ${script_path}/$line ]
														then
															echo "$line" >>${user_path}/files_to_fetch.tmp
														fi
													else
														echo "$line" >>${user_path}/files_to_fetch.tmp
													fi
												fi
											fi
										fi
							      			;;
								"keys")		if [ ! -d ${script_path}/$line ]
										then
											file_full=${line#*/}
											file_full_correct=$(echo $file_full|grep -c '[^[:alnum:]]')
											if [ $file_full_correct -gt 0 ]
											then
												rt_query=1
											else
												if [ $check_mode = 0 ]
												then
													key_exists=$(grep -c "$(sha224sum ${script_path}/$line|cut -d ' ' -f1)" ${user_path}/files_to_fetch_keys.tmp)
													if [ ! -s ${script_path}/$line ] && [ ! ${key_exists} -gt 0 ]
													then
														echo "$line" >>${user_path}/files_to_fetch.tmp
													fi
												else
													echo "$line" >>${user_path}/files_to_fetch.tmp
												fi
											fi
										fi
							      			;;
			       					"trx")		if [ ! -d ${script_path}/$line ]
										then
											file_full=${line#*/}
											file_ext=${file_ext%%.*}
											file_ext_correct=$(echo $file_ext|grep -c '[^[:digit:]]')
											if [ $file_ext_correct -gt 0 ]
											then
												rt_query=1
											else
												if [ $check_mode = 0 ]
												then
													if [ ! -s ${script_path}/$line ]
													then
														echo "$line" >>${user_path}/files_to_fetch.tmp
													fi
												else
													echo "$line" >>${user_path}/files_to_fetch.tmp
												fi
											fi
										fi
					       					;;
								"proofs")	if [ ! -d ${script_path}/$line ]
										then
											file_usr=${line#*/}
											file_usr=${file_usr%%/*}
											file_usr_correct=$(echo $file_usr|grep -c '[^[:alnum:]]')
											if [ $file_usr_correct = 0 ]
											then
												file_full=${line#*/*/}
												file_ext=${file_full#*.}
												case $file_ext in
													"tsq")	tsa_name=${file_full%%.*}
														for tsa_service in $(ls -1 ${script_path}/certs)
														do
															if [ "${tsa_service}" = "${tsa_name}" ]
															then
																if [ $check_mode = 0 ]
																then
																	if [ ! -s ${script_path}/$line ]
																	then
																		echo "$line" >>${user_path}/files_to_fetch.tmp
																	fi
																else
																	echo "$line" >>${user_path}/files_to_fetch.tmp
																fi
															fi
														done
														;;
													"tsr")	tsa_name=${file_full%%.*}
														for tsa_service in $(ls -1 ${script_path}/certs)
														do
															if [ "${tsa_service}" = "${tsa_name}" ]
															then
																if [ $check_mode = 0 ]
																then
																	if [ ! -s ${script_path}/$line ]
																	then
																		echo "$line" >>${user_path}/files_to_fetch.tmp
																	fi
																else
																	echo "$line" >>${user_path}/files_to_fetch.tmp
																fi
															fi
														done
														;;
													*)	if [ "${file_full}" = "${file_usr}.txt" ]
														then
															echo "$line" >>${user_path}/files_to_fetch.tmp
														else
															rt_query=1
														fi
														;;
												esac
											else
												rt_query=1
											fi
										fi
					       					;;
								*)		rt_query=1
										;;
							esac
							##############################################################
						done <${user_path}/tar_check.tmp
						rm ${user_path}/files_to_fetch_keys.tmp 2>/dev/null
						##############################################################
					else
						rt_query=1
					fi
					##############################################################
				else
					rt_query=1
				fi
				##############################################################
			fi
			##############################################################

			###REMOVE THE LISTS THAT CONTAINS THE CONTENT##################
			rm ${user_path}/tar_check_temp.tmp 2>/dev/null
			rm ${user_path}/tar_check_full.tmp 2>/dev/null
			rm ${user_path}/tar_check.tmp 2>/dev/null

			return $rt_query
}
check_assets(){
			###MAKE CLEAN START############################################
			rm ${user_path}/blacklisted_assets.dat 2>/dev/null
			touch ${user_path}/blacklisted_assets.dat
			if [ -s ${user_path}/all_assets.dat ]
			then
				mv ${user_path}/all_assets.dat ${user_path}/ack_assets.dat
			else
				rm ${user_path}/ack_assets.dat 2>/dev/null
				touch ${user_path}/ack_assets.dat
			fi
			###############################################################

			###CREATE LIST OF NEW ASSETS###################################
			ls -1 ${script_path}/assets >${user_path}/all_assets.dat

			###CREATE LIST OF NEW ASSETS###################################
			sort -t . -k2 ${user_path}/all_assets.dat ${user_path}/ack_assets.dat|uniq -u >${user_path}/all_assets.tmp
			while read line
			do
				###CHECK IF ASSET IS MAIN ASSET################################
				if [ "${line}" = "${main_asset}" ] || [ "${line}" = "${main_token}" ]
				then
					###SET VARIABLE################################################
					asset_acknowledged=1
				else
					###SET VARIABLES###############################################
					asset_acknowledged=0
					asset=$line
					asset_data=$(grep "asset_" ${script_path}/assets/${asset}|grep "=")
					asset_description=$(echo "$asset_data"|grep "asset_description")
					asset_description=${asset_description#*=}
					asset_symbol=${asset%%.*}
					asset_stamp=${asset#*.}
					asset_price=$(echo "$asset_data"|grep "asset_price")
					asset_price=${asset_price#*=}
					asset_quantity=$(echo "$asset_data"|grep "asset_quantity")
					asset_quantity=${asset_quantity#*=}
					asset_fungible=$(echo "$asset_data"|grep "asset_fungible")
					asset_fungible=${asset_fungible#*=}
					stamp_only_digits=$(echo "${asset_stamp}"|grep -c '[^[:digit:]]')
					stamp_size=${#asset_stamp}

					###CHECK IF STAMP IS OKAY######################################
					if [ $stamp_only_digits = 0 ] && [ $stamp_size -eq 10 ]
					then
						###CHECK IF ALL VARIABLES ARE SET##############################
						if [ ! "${asset_description}" = "" ] && [ ! "${asset_fungible}" = "" ]
						then
							###CHECK FOR ALNUM CHARS AND SIZE##############################
							symbol_check=$(echo $asset_symbol|grep -c '[^[:alnum:]]')
							symbol_size=${#asset_symbol}
							if [ $symbol_check = 0 ] && [ $symbol_size -le 10 ]
							then
								###CHECK IF ASSET ALREADY EXISTS###############################
								asset_already_exists=$(cat ${user_path}/ack_assets.dat ${user_path}/all_assets.dat|grep -c "${asset}")
								if [ $asset_already_exists -gt 0 ]
								then
									###CHECK IF FUNGIBLE VARIABLE SET CORRECTLY####################
									if [ $asset_fungible = 0 ] || [ $asset_fungible = 1 ]
									then
										asset_owner_ok=0
										asset_owner=$(echo "$asset_data"|grep "asset_owner")
										asset_owner=${asset_owner#*=}
										if [ $asset_fungible = 0 ]
										then
											###CHECK ASSET HARDCAP#################################
											if [ ! "${asset_quantity}" = "" ] && [ ! "${asset_quantity}" = "*" ]
											then
												is_big_enough=$(echo "${asset_quantity} > 0 "|bc)
												if [ $is_big_enough = 1 ]
												then
													###CHECK IF ASSET OWNER IS SET#########################
													if [ ! "${asset_owner}" = "" ]
													then
														owner_exists=$(ls -1 ${script_path}/keys|grep -c "${asset_owner}")
														if [ $owner_exists = 1 ]
														then
															asset_owner_ok=1
														fi
													fi
												fi
											fi
										else
											asset_owner_ok=1
										fi
										if [ $asset_owner_ok = 1 ]
										then
											if [ $asset_fungible = 0 ]
											then
												check_value=$asset_quantity
											else
												check_value=$asset_price
											fi
											###CHECK ASSET PRICE###################################
											is_amount_ok=$(echo "$check_value >= 0.000000001"|bc)
											is_amount_mod=$(echo "$check_value % 0.000000001"|bc)
											is_amount_mod=$(echo "${is_amount_mod} > 0"|bc)
											if [ $is_amount_ok = 1 ] && [ $is_amount_mod = 0 ]
											then
												asset_acknowledged=1
											fi
											#######################################################
										fi
										#######################################################
									fi
									#######################################################
								fi
								#######################################################
							fi
							#######################################################
						fi
						######################################################
					fi
					######################################################
				fi
				######################################################

				###WRITE ENTY TO BLACKLIST IF NOT ACKNOWLEDGED########
				if [ $asset_acknowledged = 0 ]
				then
					echo "$line" >>${user_path}/blacklisted_assets.dat
				fi
				#######################################################
			done <${user_path}/all_assets.tmp

			###GO THROUGH BLACKLISTED TRX LINE BY LINE AND REMOVE THEM#########
			if [ -s ${user_path}/blacklisted_assets.dat ]
			then
				while read line
				do
					rm ${script_path}/assets/${line} 2>/dev/null
				done <${user_path}/blacklisted_assets.dat
			fi
			###################################################################

			###REMOVE BLACKLISTED ASSETS FROM ASSET LIST#######################
			sort -t . -k2 ${user_path}/all_assets.tmp ${user_path}/blacklisted_assets.dat|uniq -u >${user_path}/all_assets.dat

			###ADD ACKNOWLEDGED ASSETS TO FINAL LIST###########################
			sort -t . -k2 ${user_path}/all_assets.dat ${user_path}/ack_assets.dat >${user_path}/all_assets.tmp
			mv ${user_path}/all_assets.tmp ${user_path}/all_assets.dat
			rm ${user_path}/ack_assets.dat
}
check_blacklist(){
			###CHECK IF USER HAS BEEN BLACKLISTED AND IF SO WARN HIM##
			am_i_blacklisted=$(grep -c "${handover_account}" ${user_path}/blacklisted_accounts.dat)
			if [ $am_i_blacklisted -gt 0 ]
			then
				if [ $gui_mode = 1 ]
				then
					dialog_blacklisted_display=$(echo $dialog_blacklisted|sed "s/<account_name>/${handover_account}/g")
					dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_blacklisted_display" 0 0
				else
					echo "WARNING:USER_BLACKLISTED"
					exit 1
				fi
			fi
}
check_tsa(){
			cd ${script_path}/certs

			###SET NOW STAMP#################################
			now_stamp=$(date +%s)

			###PURGE OLD TMP FILES###########################
			rm ${script_path}/certs/*.crt 2>/dev/null
			rm ${script_path}/certs/*.crl 2>/dev/null
			rm ${script_path}/certs/*.pem 2>/dev/null

			###FOR EACH TSA-SERVICE IN CERTS/-FOLDER#########
			for tsa_service in $(ls -1 ${script_path}/certs)
			do
				###SET VARIABLES#################################
				tsa_update_required=0
				tsa_checked=0
				tsa_cert_available=0
				tsa_rootcert_available=0
				crl_retry_counter=0
				retry_counter=0

				###CHECK IF TIMESTAMP-FILE IS THERE##############
				if [ -s "${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat" ]
				then
					###IF YES EXTRACT STAMP##########################
					last_check=$(cat ${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat)
					period_seconds=$(( now_stamp - last_check ))
				else
					###IF NOT SET STAMP##############################
					period_seconds=$(( check_period_tsa + 1 ))
				fi
				#################################################

				###CHECK TSA.CRT, CACERT.PEM AND ROOT_CA.CRL#####
				while [ $tsa_checked = 0 ]
				do
					###IF TSA.CRT FILE AVAILABLE...##################
					if [ -s ${script_path}/certs/${tsa_service}/tsa.crt ]
					then
						###GET DATES######################################
						old_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -noout -dates|grep "notBefore"|cut -d '=' -f2)")
						old_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -noout -dates|grep "notAfter"|cut -d '=' -f2)")

						###CHECK IF CERT IS VALID#########################
						if [ $now_stamp -gt $old_cert_valid_from ] && [ $now_stamp -lt $old_cert_valid_till ]
						then
							tsa_cert_available=1
						else
							tsa_update_required=1
						fi
					else
						tsa_update_required=1
					fi
					if [ $tsa_update_required = 1 ]
					then
						###GET URL FROM TSA.CONF##########################
						tsa_cert_url=$(grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f2)

						###DOWNLOAD TSA.CRT###############################
						wget -q -O tsa.crt ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###GET DATES######################################
							new_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/tsa.crt -noout -dates|grep "notBefore"|cut -d '=' -f2)")
							new_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/tsa.crt -noout -dates|grep "notAfter"|cut -d '=' -f2)")

							###CHECK IF CERT IS VALID#########################
							if [ $now_stamp -gt $new_cert_valid_from ] && [ $now_stamp -lt $new_cert_valid_till ]
							then
								if [ -s ${script_path}/certs/${tsa_service}/tsa.crt ]
								then
									mv ${script_path}/certs/${tsa_service}/tsa.crt ${script_path}/certs/${tsa_service}/tsa.${old_cert_valid_from}-${old_cert_valid_till}.crt
								fi
								mv ${script_path}/certs/tsa.crt ${script_path}/certs/${tsa_service}/tsa.crt
								tsa_cert_available=1
							else
								rm ${script_path}/certs/tsa.crt 2>/dev/null
							fi
						fi
						rm ${script_path}/certs/tsa.crt 2>/dev/null
						tsa_update_required=0
					fi

					###IF CACERT.PEM FILE AVAILABLE...################
					if [ -s ${script_path}/certs/${tsa_service}/cacert.pem ]
					then
						###GET DATES######################################
						old_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/cacert.pem -noout -dates|grep "notBefore"|cut -d '=' -f2)")
						old_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/cacert.pem -noout -dates|grep "notAfter"|cut -d '=' -f2)")

						###CHECK IF CERT IS VALID#########################
						if [ $now_stamp -gt $old_cert_valid_from ] && [ $now_stamp -lt $old_cert_valid_till ]
						then
							tsa_rootcert_available=1
						else
							tsa_update_required=1
						fi
					else
						tsa_update_required=1
					fi
					if [ $tsa_update_required = 1 ]
					then
						###GET URL FROM TSA.CONF##########################
						tsa_cert_url=$(grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f3)

						###DOWNLOAD CACERT.PEM############################
						wget -q -O cacert.pem ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###GET DATES######################################
							new_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/cacert.pem -noout -dates|grep "notBefore"|cut -d '=' -f2)")
							new_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/cacert.pem -noout -dates|grep "notAfter"|cut -d '=' -f2)")

							###CHECK IF CERT IS VALID#########################
							if [ $now_stamp -gt $new_cert_valid_from ] && [ $now_stamp -lt $new_cert_valid_till ]
							then
								if [ -s ${script_path}/certs/${tsa_service}/cacert.pem ]
								then
									mv ${script_path}/certs/${tsa_service}/cacert.pem ${script_path}/certs/${tsa_service}/cacert.${old_cert_valid_from}-${old_cert_valid_till}.pem
								fi
								mv ${script_path}/certs/cacert.pem ${script_path}/certs/${tsa_service}/cacert.pem
								tsa_rootcert_available=1
							else
								rm ${script_path}/certs/cacert.pem
							fi
						fi
						rm ${script_path}/certs/cacert.pem 2>/dev/null
						tsa_update_required=0
					fi

					###IF TSA.CRT AND CACERT.PEM ARE THERE############
					if [ $tsa_cert_available = 1 ] && [ $tsa_rootcert_available = 1 ]
					then
						###GET TSA CRL URL FIRST BY CRT THEN BY CONFIG####
						tsa_crl_url=""
						tsa_crl_url=$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -text -noout|grep -A4 "X509v3 CRL Distribution Points:"|grep "URI"|awk -F: '{print $2":"$3}')
						if [ "${tsa_crl_url}" = "" ]
						then
							###GET CRL URL FROM TSA.CONF######################
							tsa_crl_url=$(grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f4)
							if [ "${tsa_crl_url}" = "" ]
							then
								###IF NO CRL IS THERE#############################
								tsa_checked=1
							fi
						fi
						if [ $tsa_checked = 0 ]
						then
							###CHECK WAIT PERIOD######################################
							if [ $period_seconds -gt $check_period_tsa ] || [ ! -s ${script_path}/certs/${tsa_service}/root_ca.crl ]
							then
								###DOWNLOAD CURRENT CRL FILE##############################
								wget -q -O root_ca.crl ${tsa_crl_url}
								if [ -s ${script_path}/certs/root_ca.crl ]
								then
									###CHECK IF OLD CRL IS THERE##############################
									if [ -s ${script_path}/certs/${tsa_service}/root_ca.crl ]
									then
										###GET CRL DATES##########################################
										crl_old_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)")
										crl_old_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)")
										crl_new_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)")
										crl_new_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)")

										###COMPARE VALID FROM AND VALID TILL######################
										if [ $crl_old_valid_from -eq $crl_new_valid_from ] && [ $crl_old_valid_till -eq $crl_new_valid_till ]
										then
											###GET HASHES TO COMPARE##################################
											new_crl_hash=$(sha224sum ${script_path}/certs/root_ca.crl)
											new_crl_hash=${new_crl_hash%% *}
											old_crl_hash=$(sha224sum ${script_path}/certs/${tsa_service}/root_ca.crl)
											old_crl_hash=${old_crl_hash%% *}
											if [ ! "${new_crl_hash}" = "${old_crl_hash}" ]
											then
												mv ${script_path}/certs/root_ca.crl ${script_path}/certs/${tsa_service}/root_ca.crl
											fi
										else
											###UNCOMMENT TO ENABLE SAVESTORE OF CRL###################
											mv ${script_path}/certs/${tsa_service}/root_ca.crl ${script_path}/certs/${tsa_service}/root_ca.${crl_old_valid_from}-${crl_old_valid_till}.crl
											mv ${script_path}/certs/root_ca.crl ${script_path}/certs/${tsa_service}/root_ca.crl
										fi
									else
										mv ${script_path}/certs/root_ca.crl ${script_path}/certs/${tsa_service}/root_ca.crl
									fi
								fi
								rm ${script_path}/certs/root_ca.crl 2>/dev/null
								if [ -s ${script_path}/certs/${tsa_service}/root_ca.crl ]
								then
									###GET CRL DATES########################
									crl_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)")
									crl_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)")
									if [ $crl_valid_from -lt $now_stamp ] && [ $crl_valid_till -gt $now_stamp ]
									then
										###CHECK CERTIFICATE AGAINST CRL########
										cat ${script_path}/certs/${tsa_service}/cacert.pem ${script_path}/certs/${tsa_service}/root_ca.crl >${script_path}/certs/${tsa_service}/crl_chain.pem
										openssl verify -crl_check -CAfile ${script_path}/certs/${tsa_service}/crl_chain.pem ${script_path}/certs/${tsa_service}/tsa.crt >/dev/null 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											tsa_checked=1
										else
											tsa_update_required=1
											if [ $crl_retry_counter = 1 ]
											then
												cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -text -noout|grep -A2 "Validity"|grep "Not Before"|cut -c 25-48)")
												mv ${script_path}/certs/${tsa_service}/tsa.crt ${script_path}/certs/${tsa_service}/tsa.${cert_valid_from}-${crl_valid_from}.crt
												tsa_checked=1
											fi
											crl_retry_counter=$(( crl_retry_counter + 1 ))
										fi
									else
										tsa_checked=1
									fi
								fi
								###IF SUCCESSFULLY CHECKED WRITE ENTRY############
								if [ $tsa_checked = 1 ]
								then
									date +%s >${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat
								fi
							else
								tsa_checked=1
							fi
						fi
					else
						retry_counter=$(( retry_counter + 1 ))
						if [ $retry_counter -le $retry_limit ]
						then
							sleep $retry_wait_seconds
						else
							if [ $gui_mode = 1 ]
							then
								dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --infobox "$dialog_no_network" 0 0
								sleep 10
								exit 1
							else
								exit 1
							fi
						fi
					fi
				done
			done
			cd ${script_path}/

			###PURGE BLACKLIST AND SETUP ALL LIST#########
			rm ${user_path}/blacklisted_accounts.dat 2>/dev/null
			touch ${user_path}/blacklisted_accounts.dat
			if [ -s ${user_path}/all_accounts.dat ]
			then
				mv ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat
			else
				rm ${user_path}/ack_accounts.dat 2>/dev/null
				touch ${user_path}/ack_accounts.dat
			fi

			###FLOCK######################################
			flock ${script_path}/keys ls -1 -X ${script_path}/keys >${user_path}/all_accounts.dat
			sort ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat|uniq -u >${user_path}/all_accounts.tmp
			while read line
			do
				###SET FLAG##############################################
				account_verified=0

				###CHECK IF KEY-FILENAME IS EQUAL TO NAME INSIDE KEY#####
				accountname_key_name="${line}"
				accountname_key_content=$(gpg --list-packets ${script_path}/keys/${line}|grep "user ID"|awk '{print $4}'|sed 's/"//g')
				if [ $accountname_key_name = $accountname_key_content ]
				then
					###CHECK IF TSA QUERY AND RESPONSE ARE THERE#############
					if [ -s ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsq ] && [ -s ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsr ]
					then
						###FOR EACH TSA-SERVUCE IN CERTS/-FOLDER#################
						for tsa_service in $(ls -1 ${script_path}/certs)
						do
							cacert_file_found=0
							for cacert_file in $(ls -1 ${script_path}/certs/${tsa_service}/cacert.*)
							do
								for crt_file in $(ls -1 ${script_path}/certs/${tsa_service}/tsa.*)
								do
									###CHECK TSA QUERYFILE###################################
									openssl ts -verify -queryfile ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsq -in ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsr -CAfile ${cacert_file} -untrusted ${crt_file} 1>/dev/null 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										###WRITE OUTPUT OF RESPONSE TO FILE######################
										openssl ts -reply -in ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsr -text >${user_path}/timestamp_check.tmp 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											###VERIFY TSA RESPONSE###################################
											openssl ts -verify -data ${script_path}/keys/${line} -in ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsr -CAfile ${cacert_file} -untrusted ${crt_file} 1>/dev/null 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												###WRITE TIMESTAMP TO FILE###############################
												file_stamp=$(date -u +%s --date="$(grep "Time stamp" ${user_path}/timestamp_check.tmp|cut -c 13-37)")
												echo "${accountname_key_name} ${file_stamp}" >>${user_path}/all_accounts_dates.dat

												###SET VARIABLE THAT TSA HAS BEEN FOUND##################
												account_verified=1

												###STEP OUT OF LOOP CACERT_FILE##########################
												cacert_file_found=1

												###STEP OUT OF LOOP CRT_FILE#############################
												break
											fi
										fi
									fi
								done
								if [ $cacert_file_found = 1 ]
								then
									break
								fi
							done
							if [ $account_verified = 1 ]
							then
								break
							fi
						done
					fi
				fi
				if [ $account_verified = 0 ]
				then
					echo $line >>${user_path}/blacklisted_accounts.dat
				fi
			done <${user_path}/all_accounts.tmp
			rm ${user_path}/timestamp_check.tmp 2>/dev/null

			#####################################################################################
			###GO THROUGH BLACKLISTED ACCOUNTS LINE BY LINE AND REMOVE KEYS AND PROOFS###########
			###############################WITH FLOCK############################################
			if [ -s ${user_path}/blacklisted_accounts.dat ]
			then
				cd ${user_path}/
				flock ${script_path}/keys/ -c '
				user_path=$(pwd)
				base_dir=$(dirname $user_path)
				script_path=$(dirname $base_dir)
				handover_account=$(basename $user_path)
				while read line
				do
					if [ ! $line = $handover_account ]
					then
						rm ${script_path}/keys/${line} 2>/dev/null
						rm -R ${script_path}/proofs/${line}/ 2>/dev/null
						rm ${script_path}/trx/${line}.* 2>/dev/null
					fi
				done <${user_path}/blacklisted_accounts.dat
				'
				cd ${script_path}
				#####################################################################################
			fi
			###REMOVE BLACKLISTED USER FROM LIST OF FILES########################################
			sort ${user_path}/all_accounts.tmp ${user_path}/blacklisted_accounts.dat|uniq -u >${user_path}/all_accounts.dat

			###ADD ACKNOWLEDGED ACCOUNTS TO FINAL LIST#########################
			sort ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat >${user_path}/all_accounts.tmp
			mv ${user_path}/all_accounts.tmp ${user_path}/all_accounts.dat
			rm ${user_path}/ack_accounts.dat

			###SORT DATES LIST#################################################
			sort -u -t ' ' -k2 ${user_path}/all_accounts_dates.dat >${user_path}/all_accounts_dates.tmp
			mv ${user_path}/all_accounts_dates.tmp ${user_path}/all_accounts_dates.dat
}
check_keys(){
		###SETUP ALL LIST#################################################
		if [ -s ${user_path}/all_keys.dat ]
		then
			mv ${user_path}/all_keys.dat ${user_path}/ack_keys.dat
		else
			rm ${user_path}/ack_keys.dat 2>/dev/null
			touch ${user_path}/ack_keys.dat
		fi
		cp ${user_path}/all_accounts.dat ${user_path}/all_keys.dat
		sort ${user_path}/all_keys.dat ${user_path}/ack_keys.dat|uniq -u >${user_path}/all_keys.tmp

		###CHECK KEYS IF ALREADY IN KEYRING AND IMPORT THEM IF NOT#########
		touch ${user_path}/keylist_gpg.tmp
		gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys >${user_path}/keylist_gpg.tmp 2>/dev/null
  	       	while read line
  	      	do
		       	key_uname=$line
 			key_imported=$(grep -c "${key_uname}" ${user_path}/keylist_gpg.tmp)
			if [ $key_imported = 0 ]
	      		then
			       	gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/keys/${line} 2>/dev/null
	      			rt_query=$?
			       	if [ $rt_query -gt 0 ]
			       	then
					dialog_import_fail_display=$(echo $dialog_import_fail|sed -e "s/<key_uname>/${key_uname}/g" -e "s/<file>/${line}/g")
		       			dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_import_fail_display" 0 0
				       	key_already_blacklisted=$(grep -c "${key_uname}" ${user_path}/blacklisted_accounts.dat)
				       	if [ $key_already_blacklisted = 0 ]
				       	then
					       	echo "${line}" >>${user_path}/blacklisted_accounts.dat
				       	fi
			       	fi
			else
				index_file="${script_path}/proofs/${line}/${line}.txt"
				if [ -s $index_file ]
				then
					verify_signature $index_file $line
					rt_query=$?
					if [ $rt_query -gt 0 ]
					then
						rm ${script_path}/proofs/${line}/${line}.txt 2>/dev/null
					fi
				fi
		       	fi
	       	done <${user_path}/all_keys.tmp
		rm ${user_path}/keylist_gpg.tmp

		###GO THROUGH BLACKLISTED ACCOUNTS LINE BY LINE AND REMOVE KEYS AND PROOFS###########
		###############################WITH FLOCK############################################
		if [ -s ${user_path}/blacklisted_accounts.dat ]
		then
			cd ${user_path}/
			flock ${script_path}/keys/ -c '
			user_path=$(pwd)
			base_dir=$(dirname $user_path)
			script_path=$(dirname $base_dir)
			handover_account=$(basename $user_path)
			while read line
			do
				if [ ! $line = $handover_account ]
				then
					rm ${script_path}/keys/${line} 2>/dev/null
					rm -R ${script_path}/proofs/${line}/ 2>/dev/null
					rm ${script_path}/trx/${line}.* 2>/dev/null
				fi
			done <${user_path}/blacklisted_accounts.dat
			'
			###################################################################
		fi
		###REMOVE BLACKLISTED ACCOUNTS FROM ACCOUNT LIST###################
		sort ${user_path}/all_keys.tmp ${user_path}/blacklisted_accounts.dat|uniq -u >${user_path}/all_keys.dat

		###ADD ACKNOWLEDGED ACCOUNTS TO FINAL LIST#########################
		sort ${user_path}/all_keys.dat ${user_path}/ack_keys.dat >${user_path}/all_keys.tmp
		mv ${user_path}/all_keys.tmp ${user_path}/all_keys.dat
		cp ${user_path}/all_keys.dat ${user_path}/all_accounts.dat
		rm ${user_path}/ack_keys.dat
}
check_trx(){
		###PURGE BLACKLIST AND SETUP ALL LIST##############################
		rm ${user_path}/blacklisted_trx.dat 2>/dev/null
		touch ${user_path}/blacklisted_trx.dat
		if [ -s ${user_path}/all_trx.dat ]
		then
			mv ${user_path}/all_trx.dat ${user_path}/ack_trx.dat
		else
			rm ${user_path}/ack_trx.dat 2>/dev/null
			touch ${user_path}/ack_trx.dat
		fi
		touch ${user_path}/all_trx.dat

		###REMOVE OLD FILES AND RECREATE THEM##############################
		rm ${user_path}/all_trx.tmp 2>/dev/null
		rm ${user_path}/trx_list_all.tmp 2>/dev/null
		touch ${user_path}/all_trx.tmp
		touch ${user_path}/trx_list_all.tmp

		###WRITE INITIAL LIST OF TRANSACTIONS TO FILE######################
		ls -1 ${script_path}/trx >${user_path}/trx_list_all.tmp
		while read line
		do
			grep "${line}" ${user_path}/trx_list_all.tmp >>${user_path}/all_trx.dat
		done <${user_path}/all_accounts.dat
		rm ${user_path}/trx_list_all.tmp 2>/dev/null
		###################################################################

		###SORT LIST OF TRANSACTION PER DATE###############################
		sort -t . -k2 ${user_path}/all_trx.dat ${user_path}/ack_trx.dat|uniq -u >${user_path}/all_trx.tmp

		###GO THROUGH TRANSACTIONS LINE PER LINE###########################
		while read line
		do
			###SET ACKNOWLEDGED VARIABLE###############################
			trx_acknowledged=0

			###CHECK IF HEADER MATCHES OWNER###################################
			file_to_check=${script_path}/trx/${line}
			user_to_check=$(echo $line|awk -F. '{print $1}')
			trx_sender=$(awk -F: '/:SNDR:/{print $3}' $file_to_check)
			if [ $user_to_check = $trx_sender ]
			then
				###VERIFY SIGNATURE OF TRANSACTION#################################
				verify_signature $file_to_check $user_to_check
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###CHECK IF DATE IN HEADER MATCHES DATE OF FILENAME AND TRX########
					###WAS CREATED BEFORE RECEIVER WAS CREATED#########################
					trx_date_filename=${line#*.}
					trx_date_inside=$(awk -F: '/:TIME:/{print $3}' $file_to_check)
					trx_receiver_date=$(awk -F: '/:RCVR:/{print $3}' $file_to_check)
					trx_receiver_date=$(grep "${trx_receiver_date}" ${user_path}/all_accounts_dates.dat)
					trx_receiver_date=${trx_receiver_date#* }
					if [ $trx_date_filename = $trx_date_inside ] && [ $trx_date_inside -gt $trx_receiver_date ]
					then
						###CHECK IF PURPOSE CONTAINS ALNUM##################################
						purpose_start=$(awk -F: '/:PRPS:/{print NR}' $file_to_check)
						purpose_start=$(( purpose_start + 1 ))
						purpose_end=$(awk -F: '/BEGIN PGP SIGNATURE/{print NR}' $file_to_check)
						purpose_end=$(( purpose_end - 1 ))
						trx_purpose=$(sed -n "${purpose_start},${purpose_end}p" $file_to_check)
						purpose_contains_alnum=$(printf "%s" "${trx_purpose}"|grep -c -v '[a-zA-Z0-9+/=]')
						if [ $purpose_contains_alnum = 0 ]
						then
							###CHECK IF ASSET TYPE EXISTS############################################
							trx_asset=$(awk -F: '/:ASST:/{print $3}' $file_to_check)
							asset_already_exists=$(grep -c "${trx_asset}" ${user_path}/all_assets.dat)
							if [ $asset_already_exists = 1 ]
							then
								###CHECK IF AMOUNT IS MINIMUM 0.000000001################################
								trx_amount=$(awk -F: '/:AMNT:/{print $3}' $file_to_check)
								is_amount_ok=$(echo "${trx_amount} >= 0.000000001"|bc)
								is_amount_mod=$(echo "${trx_amount} % 0.000000001"|bc)
								is_amount_mod=$(echo "${is_amount_mod} > 0"|bc)

								###CHECK IF USER HAS CREATED A INDEX FILE################################
								if [ -s ${script_path}/proofs/${user_to_check}/${user_to_check}.txt ]
								then
									####CHECK IF USER HAS INDEXED THE TRANSACTION############################
									is_trx_signed=$(grep -c "trx/${line}" ${script_path}/proofs/${user_to_check}/${user_to_check}.txt)
									if [ $is_trx_signed = 1 ] && [ $is_amount_ok = 1 ] && [ $is_amount_mod = 0 ]
									then
										trx_acknowledged=1
									else
										if [ $delete_trx_not_indexed = 0 ] && [ $is_amount_ok = 1 ] && [ $is_amount_mod = 0 ]
										then
											trx_acknowledged=1
										fi
									fi
								else
									if [ $delete_trx_not_indexed = 0 ] && [ $is_amount_ok = 1 ] && [ $is_amount_mod = 0 ]
									then
										trx_acknowledged=1
									fi
								fi
							fi
						fi
					fi
				fi
			fi
			if [ $trx_acknowledged = 0 ]
			then
				if [ ! ${user_to_check} = ${handover_account} ]
				then
					echo $line >>${user_path}/blacklisted_trx.dat
				fi
			fi
		done <${user_path}/all_trx.tmp

		###GO THROUGH BLACKLISTED TRX LINE BY LINE AND REMOVE THEM#########
		if [ -s ${user_path}/blacklisted_trx.dat ]
		then
			while read line
			do
				rm ${script_path}/trx/${line} 2>/dev/null
			done <${user_path}/blacklisted_trx.dat
		fi
		###################################################################

		###REMOVE BLACKLISTED TRX FROM ACCOUNT LIST########################
		sort -t . -k2 ${user_path}/all_trx.tmp ${user_path}/blacklisted_trx.dat|uniq -u >${user_path}/all_trx.dat

		###ADD ACKNOWLEDGED TRX TO FINAL LIST##############################
		sort -t . -k2 ${user_path}/all_trx.dat ${user_path}/ack_trx.dat >${user_path}/all_trx.tmp
		mv ${user_path}/all_trx.tmp ${user_path}/all_trx.dat
		rm ${user_path}/ack_trx.dat

		cd ${script_path}/
}
process_new_files(){
			process_mode=$1
			if [ $process_mode = 0 ]
			then
				touch ${user_path}/new_index_filelist.tmp
				touch ${user_path}/old_index_filelist.tmp
				touch ${user_path}/remove_list.tmp
				touch ${user_path}/temp_filelist.tmp
				for new_index_file in $(grep "proofs/" ${user_path}/files_to_fetch.tmp|grep ".txt")
				do
					user_to_verify=$(basename $new_index_file)
					user_to_verify=${user_to_verify%%.*}
					user_already_there=$(cat ${user_path}/all_accounts.dat|grep -c "${user_to_verify}")
					if [ $user_already_there = 1 ]
					then
						verify_signature ${user_path}/temp/${new_index_file} $user_to_verify
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							assets_ok=1
							for new_index_assets in $(grep "assets/" ${user_path}/temp/${new_index_file})
							do
								asset_file=${new_index_assets%% *}
								is_asset_there=$(grep -c "${asset_file}" ${script_path}/proofs/${handover_account}/${handover_account}.txt)
								if [ $is_asset_there = 1 ]
								then
									is_asset_there=$(grep -c "${new_index_assets}" ${script_path}/proofs/${handover_account}/${handover_account}.txt)
									if [ $is_asset_there = 0 ]
									then
										assets_ok=0
									fi
								fi
							done
							if [ $assets_ok = 1 ]
							then
								touch ${user_path}/new_index_filelist.tmp
								grep "trx/${user_to_verify}" ${user_path}/temp/${new_index_file} >${user_path}/new_index_filelist.tmp
								new_trx=$(wc -l <${user_path}/new_index_filelist.tmp)
								new_trx_score_highest=0
								touch ${user_path}/old_index_filelist.tmp
								grep "trx/${user_to_verify}" ${script_path}/${new_index_file} >${user_path}/old_index_filelist.tmp
								old_trx=$(wc -l <${user_path}/old_index_filelist.tmp)
								old_trx_score_highest=0
								no_matches=0
								if [ $old_trx -le $new_trx ] && [ $new_trx -gt 0 ]
								then
									while read line
									do
										is_file_there=$(grep -c "${line}" ${user_path}/new_index_filelist.tmp)
										if [ $is_file_there = 1 ]
										then
											no_matches=$(( no_matches + 1 ))
										else
											stripped_file=$(echo "${line}"|awk '{print $1}')
											old_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/${stripped_file})
											old_trx_confirmations=$(grep -l "$line" proofs/*/*.txt|grep -c -v "${user_to_verify}\|${old_trx_receiver}")
											if [ $old_trx_confirmations -gt $old_trx_score_highest ]
											then
												old_trx_score_highest=$old_trx_confirmations
											fi
										fi
									done <${user_path}/old_index_filelist.tmp
									if [ $no_matches -lt $old_trx ]
									then
										while read line
										do
											is_file_there=$(grep -c "${line}" ${user_path}/old_index_filelist.tmp)
											if [ $is_file_there = 0 ]
											then
												stripped_file=$(echo "${line}"|awk '{print $1}')
												new_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${user_path}/temp/${stripped_file})
												new_trx_confirmations=$(grep -l "$line" ${user_path}/temp/proofs/*/*.txt|grep -c -v "${user_to_verify}\|${new_trx_receiver}")
												if [ $new_trx_confirmations -gt $new_trx_score_highest ]
												then
													new_trx_score_highest=$new_trx_confirmations
												fi
											fi
										done <${user_path}/new_index_filelist.tmp
										if [ $old_trx_score_highest -ge $new_trx_score_highest ]
										then
											echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
										fi
									else
										echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
									fi
								else
									while read line
									do
										is_file_there=$(grep -c "${line}" ${user_path}/old_index_filelist.tmp)
										if [ $is_file_there = 1 ]
										then
											no_matches=$(( no_matches + 1 ))
										else
											stripped_file=$(echo "${line}"|awk '{print $1}')
											new_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${user_path}/temp/${stripped_file})
											new_trx_confirmations=$(grep -l "$line" ${user_path}/temp/proofs/*/*.txt|grep -c -v "${user_to_verify}\|${new_trx_receiver}")
											if [ $new_trx_confirmations -gt $new_trx_score_highest ]
											then
												new_trx_score_highest=$new_trx_confirmations
											fi
										fi
									done <${user_path}/new_index_filelist.tmp
									if [ $no_matches -lt $new_trx ]
									then
										while read line
										do
											is_file_there=$(grep -c "${line}" ${user_path}/new_index_filelist.tmp)
											if [ $is_file_there = 0 ]
											then
												stripped_file=$(echo "${line}"|awk '{print $1}')
												old_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/${stripped_file})
												old_trx_confirmations=$(grep -l "$line" proofs/*/*.txt|grep -c -v "${user_to_verify}\|${old_trx_receiver}")
												if [ $old_trx_confirmations -gt $old_trx_score_highest ]
												then
													old_trx_score_highest=$old_trx_confirmations
												fi
											fi
										done <${user_path}/old_index_filelist.tmp
										if [ $old_trx_score_highest -ge $new_trx_score_highest ]
										then
											echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
										fi
									fi
								fi
							else
								echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
							fi
						else
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						fi
					else
						user_new=$(ls -1 ${user_path}/temp/keys|grep -c "${user_to_verify}")
						if [ $user_new = 0 ]
						then
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						fi
					fi
				done
				rm ${user_path}/new_index_filelist.tmp
				rm ${user_path}/old_index_filelist.tmp
				sort -u ${user_path}/remove_list.tmp >${user_path}/temp_filelist.tmp
				cat ${user_path}/files_to_fetch.tmp >>${user_path}/temp_filelist.tmp
				sort ${user_path}/temp_filelist.tmp|uniq -u >${user_path}/files_to_fetch.tmp
				rm ${user_path}/temp_filelist.tmp

				###REMOVE FILES OF REMOVE LIST################
				while read line
				do
					rm ${user_path}/temp/${line}
				done <${user_path}/remove_list.tmp
				rm ${user_path}/remove_list.tmp 2>/dev/null
			else
				###CHECK IF EXISTING FILES ARE OVERWRITTEN####
				files_replaced=0
				while read line
				do
					if [ -s ${script_path}/$line ]
					then
						files_replaced=1
					fi
				done <${user_path}/files_to_fetch.tmp

				###IF FILES OVERWRITTEN DELETE *.DAT FILES####
				if [ $files_replaced = 1 ]
				then
					rm ${script_path}/userdata/${handover_account}/all_assets.dat
					rm ${script_path}/userdata/${handover_account}/all_keys.dat
					rm ${script_path}/userdata/${handover_account}/all_trx.dat
					rm ${script_path}/userdata/${handover_account}/all_accounts.dat
					rm ${script_path}/userdata/${handover_account}/*_ledger.dat
				fi
			fi
			while read line
			do
				is_asset=$(echo $line|grep -c "assets/")
				is_fungible=$(grep -c "asset_fungible=1" ${user_path}/temp/${line})
				if [ -h ${user_path}/temp/${line} ] || [ -x ${user_path}/temp/${line} ] || [ $is_asset = 1 ] && [ $is_fungible = 1 ] && [ $import_fungible_assets = 0 ] || [ $is_asset = 1 ] && [ $is_fungible = 0 ] && [ $import_non_fungible_assets = 0 ]
				then
					rm ${user_path}/temp/${line}
				fi
			done <${user_path}/files_to_fetch.tmp
			files_to_copy=$(find ${user_path}/temp/ -maxdepth 3 -type f|wc -l)
			if [ $files_to_copy -gt 0 ]
			then
				#############################################
				############  COPY FILES TO TARGET###########
				##################WITH FLOCK#################
				cd ${user_path}/
				flock ${script_path}/keys/ -c '
				user_path=$(pwd)
				base_dir=$(dirname $user_path)
				script_path=$(dirname $base_dir)
				cp ${user_path}/temp/assets/* ${script_path}/assets/ 2>/dev/null
				cp ${user_path}/temp/keys/* ${script_path}/keys/ 2>/dev/null
				cp -r ${user_path}/temp/proofs/* ${script_path}/proofs/ 2>/dev/null
				cp ${user_path}/temp/trx/* ${script_path}/trx/ 2>/dev/null
				'
				cd ${script_path}/
				#############################################

				###PURGE TEMP FILES##########################
				rm -r ${user_path}/temp/assets/* 2>/dev/null
				rm -r ${user_path}/temp/keys/* 2>/dev/null
				rm -r ${user_path}/temp/trx/* 2>/dev/null
				rm -r ${user_path}/temp/proofs/* 2>/dev/null
			fi
}
set_permissions(){
			###AVOID EXECUTABLES BY SETTING PERMISSIONS###############
			while read line
			do
				file_to_change="${script_path}/${line}"
				curr_permissions=$(stat -c '%a' ${file_to_change})
				if [ -d $file_to_change ]
				then
					if [ ! $curr_permissions = $permissions_directories ]
					then
						chmod $permissions_directories ${script_path}/${line}
					fi
				else
					if [ -s $file_to_change ]
					then
						if [ ! $curr_permissions = $permissions_files ]
						then
							chmod $permissions_files ${script_path}/${line}
						fi
					fi
				fi
			done <${user_path}/files_to_fetch.tmp

			###REMOVE FILE LIST#######################################
			rm ${user_path}/files_to_fetch.tmp 2>/dev/null
}
purge_files(){
		###FIRST REMOVE ALL KEYS FROM KEYRING TO AVOID GPG ERRORS##########
		for key_file in $(gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys|grep "uid"|cut -d ':' -f10 2>/dev/null)
		do
			key_fp=$(gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${key_file}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p')
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
				gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-keys ${key_fp} 2>/dev/null
			fi
		done

		###REMOVE KEYRING AND FILES########################################
		rm ${script_path}/control/keyring.file 2>/dev/null
		rm ${script_path}/control/keyring.file~ 2>/dev/null
		rm ${script_path}/assets/* 2>/dev/null
		rm ${script_path}/keys/* 2>/dev/null
		rm ${script_path}/trx/* 2>/dev/null
		rm -r ${script_path}/proofs/* 2>/dev/null
		rm -r ${script_path}/userdata/* 2>/dev/null
}
import_keys(){
		cd ${script_path}/control/keys
		for key_file in $(ls -1 ${script_path}/control/keys)
		do
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/control/keys/${key_file}
		done
		cd ${script_path}/
}
get_dependencies(){
			cd ${script_path}/trx
			ledger_mode=1
			own_index_there=0
			first_start=0

			###CHECK IF INDEX/IGNORE/LEDGER THERE IF NOT BUILD LEDGE######################
			if [ -s ${script_path}/proofs/${handover_account}/${handover_account}.txt ]
			then
				own_index_there=1
			fi
			##############################################################################

			###CHECK IF ANYTHING HAS CHANGED##############################################
			depend_accounts_old_hash="X"
			depend_trx_old_hash="X"
			depend_confirmations_old_hash="X"
			if [ -e ${user_path}/depend_accounts.dat ]
			then
				depend_accounts_old_hash=$(sha256sum ${user_path}/depend_accounts.dat)
				depend_accounts_old_hash=${depend_accounts_old_hash%% *}
				cp ${user_path}/depend_accounts.dat ${user_path}/depend_accounts_old.tmp
			else
				first_start=1
			fi
			if [ $first_start = 0 ]
			then
				if [ -e ${user_path}/depend_trx.dat ]
				then
					depend_trx_old_hash=$(sha256sum ${user_path}/depend_trx.dat)
					depend_trx_old_hash=${depend_trx_old_hash%% *}
					cp ${user_path}/depend_trx.dat ${user_path}/depend_trx_old.tmp
				fi
				if [ -e ${user_path}/depend_confirmations.dat ]
				then
					depend_confirmations_old_hash=$(sha256sum ${user_path}/depend_confirmations.dat)
					depend_confirmations_old_hash=${depend_confirmations_old_hash%% *}
					cp ${user_path}/depend_confirmations.dat ${user_path}/depend_confirmations_old.tmp
				fi
			fi

			###GET DEPENDENT TRX AND ACCOUNTS#############################################
			rm ${user_path}/depend_trx.dat 2>/dev/null
			touch ${user_path}/depend_trx.dat
			if [ $only_process_depend = 1 ]
			then
				echo "${handover_account}" >${user_path}/depend_accounts.dat
				grep "${handover_account}" ${user_path}/all_trx.dat >${user_path}/depend_trx.dat
				while read line
				do
					touch ${user_path}/depend_user_list.tmp
					user=$line
					grep -l "RCVR:${user}" $(cat ${user_path}/all_trx.dat)|sort -u|cut -d '.' -f1 >${user_path}/depend_user_list.tmp
					for user_trx in $(grep "${user}" ${user_path}/all_trx.dat)
					do
						echo "${user_trx}" >>${user_path}/depend_trx.dat
						receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/trx/${user_trx})
						is_asset=$(grep -c "$receiver" ${user_path}/all_assets.dat)
						if [ $is_asset = 0 ]
						then
							echo $receiver >>${user_path}/depend_user_list.tmp
						fi
					done
					for trx_file in $(sort -u ${user_path}/depend_user_list.tmp)
					do
						name="${trx_file%%.*}"
						already_there=$(grep -c "${name}" ${user_path}/depend_accounts.dat)
						if [ $already_there = 0 ]
						then
							echo $trx_file >>${user_path}/depend_accounts.dat
						fi
					done
				done <${user_path}/depend_accounts.dat

				###SORT DEPENDENCIE LISTS#####################################################
				sort ${user_path}/depend_accounts.dat >${user_path}/depend_accounts.tmp
				mv ${user_path}/depend_accounts.tmp ${user_path}/depend_accounts.dat
				sort -u -t . -k2 ${user_path}/depend_trx.dat >${user_path}/depend_trx.tmp
				mv ${user_path}/depend_trx.tmp ${user_path}/depend_trx.dat
			else
				###COPY FILES#################################################################
				cp ${user_path}/all_accounts.dat ${user_path}/depend_accounts.dat
				cp ${user_path}/all_trx.dat ${user_path}/depend_trx.dat
			fi

			###GET DEPEND TRX WITH 0 CONFIRMATIONS########################################
			rm ${user_path}/depend_confirmations.dat 2>/dev/null
			touch ${user_path}/depend_confirmations.dat
			while read line
			do
				trx_hash=$(sha256sum ${script_path}/trx/${line})
				trx_hash=${trx_hash%% *}
				trx_sender=$(awk -F: '/:SNDR:/{print $3}' ${script_path}/trx/${line})
				trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/trx/${line})
				total_confirmations=$(grep -s -l "trx/${line} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${trx_sender}\|${trx_receiver}")
				if [ $total_confirmations -ge $confirmations_from_users ]
				then
					echo "$line" >>${user_path}/depend_confirmations.dat
				fi
			done <${user_path}/depend_trx.dat

			###GET HASH AND COMPARE#######################################################
			depend_accounts_new_hash=$(sha256sum ${user_path}/depend_accounts.dat)
			depend_accounts_new_hash=${depend_accounts_new_hash%% *}
			depend_trx_new_hash=$(sha256sum ${user_path}/depend_trx.dat)
			depend_trx_new_hash=${depend_trx_new_hash%% *}
			depend_confirmations_new_hash=$(sha256sum ${user_path}/depend_confirmations.dat)
			depend_confirmations_new_hash=${depend_confirmations_new_hash%% *}
			if [ "${depend_accounts_new_hash}" = "${depend_accounts_old_hash}" ] && [ "${depend_trx_new_hash}" = "${depend_trx_old_hash}" ] && [ "${depend_confirmations_new_hash}" = "${depend_confirmations_old_hash}" ] && [ $own_index_there = 1 ]
			then
				make_new_index=0
				ledger_mode=0
			else
				make_new_index=1
				if [ $first_start = 0 ]
				then
					ledger_mode=0
					touch ${user_path}/dates.tmp

					###CREATE LISTS WITH DATE OF LEDGER CHANGES###################################
					if [ ! "${depend_accounts_new_hash}" = "${depend_accounts_old_hash}" ]
					then
						depend_accounts_new_date=$(grep "$(sort ${user_path}/depend_accounts_old.tmp ${user_path}/depend_accounts.dat|uniq -u)" ${user_path}/all_accounts_dates.dat|sort -t ' ' -k2|head -1)
						depend_accounts_new_date=${depend_accounts_new_date#* }
						if [ ! "${depend_accounts_new_date}" = "" ]
						then
							echo "${depend_accounts_new_date}" >>${user_path}/dates.tmp
						fi
					fi
					if [ ! "${depend_trx_new_hash}" = "${depend_trx_old_hash}" ]
					then
						if [ -e ${user_path}/depend_trx.dat ] && [ ! "${depend_trx_old_hash}" = "X" ]
						then
							depend_trx_new_date=$(sort -t . -k2 ${user_path}/depend_trx_old.tmp ${user_path}/depend_trx.dat|uniq -u|head -1|cut -d '.' -f2)
							if [ ! "${depend_trx_new_date}" = "" ]
							then
								echo "${depend_trx_new_date}" >>${user_path}/dates.tmp
							fi
						fi
					fi
					if  [ ! "${depend_confirmations_new_hash}" = "${depend_confirmations_old_hash}" ]
					then
						if [ -e ${user_path}/depend_confirmations.dat ] && [ ! "${depend_confirmations_new_hash}" = "X" ]
						then
							depend_confirmations_new_date=$(sort -t . -k2 ${user_path}/depend_confirmations_old.tmp ${user_path}/depend_confirmations.dat|head -1|cut -d '.' -f2)
							if [ ! "${depend_confirmations_new_date}" = "" ]
							then
								echo "${depend_confirmations_new_date}" >>${user_path}/dates.tmp
							fi
						fi
					fi

					###GET EARLIEST DATE AND REMOVE ALL FILES AFTER THIS DATE#####################
					cd ${user_path}/
					earliest_date=$(sort ${user_path}/dates.tmp|head -1)
					if [ ! "${earliest_date}" = "" ]
					then
						last_date=$(date +%Y%m%d --date=@${earliest_date})
						rm $(ls -1 ${user_path}/|grep "ledger.dat"|awk -F_ -v last_date="${last_date}" '$1 >= last_date')
						rm $(ls -1 ${user_path}/|grep "scoretable.dat"|awk -F_ -v last_date="${last_date}" '$1 >= last_date')
						rm $(ls -1 ${user_path}/|grep "index_trx.dat"|awk -F_ -v last_date="${last_date}" '$1 >= last_date')
					fi
				fi
			fi
			rm ${user_path}/*.tmp 2>/dev/null
			cd ${script_path}/
			return $ledger_mode
}
request_uca(){
		###GET TOTAL NUMBER OF UCAs FOR PROGRESSBAR########
		if [ $gui_mode = 1 ]
		then
			rm ${user_path}/uca_list.tmp 2>/dev/null
			total_number_uca=$(wc -l <${script_path}/control/uca.conf)
			percent_per_uca=$(echo "scale=10; 100 / $total_number_uca"|bc)
			current_percent=0
			percent_display=0
			while read line
			do
				uca_info=$(echo $line|cut -d ',' -f4)
				printf "%b" "\"${uca_info}\" \"WAITING\"\n" >>${user_path}/uca_list.tmp
			done <${script_path}/control/uca.conf
		fi
		###################################################

		###READ UCA.CONF LINE BY LINE######################
		while read line
		do
			###SET SESSION KEY################################
			session_key=$(date -u +%Y%m%d)

			###GET VALUES FROM UCA.CONF#######################
			uca_connect_string=$(echo $line|cut -d ',' -f1)
			uca_rcv_port=$(echo $line|cut -d ',' -f2)
			uca_info=$(echo $line|cut -d ',' -f4)

			###STATUS BAR FOR GUI##############################
			if [ $gui_mode = 1 ]
			then
				sed -i "s/\"${uca_info}\" \"WAITING\"/\"${uca_info}\" \"IN_PROGRESS\"/g" ${user_path}/uca_list.tmp
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_request" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi

			###GET RANDOM P AND RELATED G#####################
			numbers_total=$(wc -l <${script_path}/control/dh.db)
			number_urandom=$(head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 6)
			number_random=$(echo "${number_urandom} % ${numbers_total}"|bc)
			number_random=$(( number_random + 1 ))
			p_number=$(sed -n "${number_random}p" ${script_path}/control/dh.db|cut -d ':' -f1)
			g_number=$(sed -n "${number_random}p" ${script_path}/control/dh.db|cut -d ':' -f2)

			###CALCULATE VALUE FOR A##########################
			usera_random_integer_unformatted=$(head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 5)
			usera_random_integer_formatted=$(echo "${usera_random_integer_unformatted} / 1"|bc)
			usera_send_tmp=$(echo "${g_number} ^ ${usera_random_integer_formatted}"|bc)
			usera_send=$(echo "${usera_send_tmp} % ${p_number}"|bc)
			usera_session_id=$(head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 20)
			usera_string="${p_number}:${g_number}:${usera_send}:${usera_session_id}:${handover_account}:"
			##################################################

			###SET VALUES#####################################
			now_stamp=$(date +%s)
			sync_file="${user_path}/uca_${now_stamp}.sync"
			out_file="${user_path}/uca_${now_stamp}.out"
			save_file="${user_path}/uca_save.dat"

			###WRITE HEADER AND ENCRYPT#######################
			printf "%s" "${usera_string}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${user_path}/uca_header.tmp --passphrase ${session_key} - 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				###SEND KEY VIA DIFFIE-HELLMAN AND WRITE RESPONSE TO FILE####################
				cat ${user_path}/uca_header.tmp|netcat -q 120 -w60 ${uca_connect_string} ${uca_rcv_port} >${out_file} 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###DECRYPT HEADER RECEIVED#########################
					header=$(head -7 ${out_file}|gpg --batch --no-tty --output - --passphrase ${session_key} --decrypt - 2>/dev/null)

					###GET SIZE OF HEADER AND BODY######################
					total_bytes_received=$(wc -c <${out_file})
					total_bytes_header=$(head -7 ${out_file}|wc -c)
					total_bytes_count=$(( total_bytes_received - total_bytes_header ))

					###CALCULATE SHARED-SECRET##########################
					header=${header#*:}
					header=${header#*:}
					userb_sent=${header%%:*}
					header=${header#*:}
					usera_ssecret_tmp=$(echo "${userb_sent} ^ ${usera_random_integer_formatted}"|bc)
					usera_ssecret=$(echo "${usera_ssecret_tmp} % ${p_number}"|bc)
					usera_hssecret=$(echo "${usera_ssecret}_${session_key}"|sha256sum)
					usera_hssecret=${usera_hssecret%% *}
					userb_uname=${header%%:*}

					###CUT OUT BODY AND MOVE FILE#######################
					dd skip=${total_bytes_header} count=${total_bytes_count} if=${out_file} of=${out_file}.tmp bs=1 2>/dev/null
					mv ${out_file}.tmp ${out_file}

					###DECRYPT SENT FILE################################
					gpg --batch --no-tty --pinentry-mode loopback --output ${sync_file} --passphrase ${usera_hssecret} --decrypt ${out_file} 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						if [ ! -s ${save_file} ]
						then
							echo "${uca_connect_string}:${usera_ssecret}:${usera_session_id}:${userb_uname}:" >${save_file}
						fi
						###WRITE SHARED SECRET TO DB########################
						ssecret_there=$(grep -c "${uca_connect_string}" ${save_file})
						if [ $ssecret_there = 0 ]
						then
							echo "${uca_connect_string}:${usera_ssecret}:${usera_session_id}:" >>${save_file}
						else
							same_key=$(grep "${uca_connect_string}" ${save_file}|cut -d ':' -f2)
							if [ ! $same_key = $usera_ssecret ]
							then
								sed -i "s/${uca_connect_string}:${same_key}:/${uca_connect_string}:${usera_ssecret}/g" ${save_file}
							fi
						fi
						###CHECK SENT FILE##################################
						check_archive ${sync_file} 0
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###STEP INTO USERDATA/USER/TEMP AND EXTRACT FILE####
							cd ${user_path}/temp

							###EXTRACT FILE#####################################
							tar -xzf ${sync_file} -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								process_new_files 0
								set_permissions
							fi
						fi
					fi
				else
					if [ $gui_mode = 0 ]
					then
						echo "ERROR: UCA-LINK RCV ${uca_connect_string}:${uca_rcv_port} FAILED"
					fi
				fi
			else
				if [ $gui_mode = 0 ]
				then
					echo "ERROR: UCA-LINK RCV ${uca_connect_string}:${uca_rcv_port} FAILED"
				fi
			fi
			###REMOVE TMP HEADER FILE##########################
			rm ${user_path}/uca_header.tmp 2>/dev/null

			###STATUS BAR FOR GUI##############################
			if [ $gui_mode = 1 ]
			then
				current_percent=$(echo "scale=10; ${current_percent} + ${percent_per_uca}"|bc)
				percent_display=$(echo "scale=0; ${current_percent} / 1"|bc)
				if [ $rt_query = 0 ]
				then
					sed -i "s/\"${uca_info}\" \"IN_PROGRESS\"/\"${uca_info}\" \"SUCCESSFULL\"/g" ${user_path}/uca_list.tmp
				else
					sed -i "s/\"${uca_info}\" \"IN_PROGRESS\"/\"${uca_info}\" \"FAILED\"/g" ${user_path}/uca_list.tmp
				fi
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_request" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi

			###PURGE TEMP FILES################################
			rm ${out_file} 2>/dev/null
			rm ${sync_file} 2>/dev/null
		done <${script_path}/control/uca.conf
		rm ${user_path}/uca_list.tmp 2>/dev/null
}
send_uca(){
		now_stamp=$(date +%s)

		###SET VARIABLES#############################
		sync_file="${user_path}/${handover_account}_${now_stamp}.sync"
		out_file="${user_path}/${handover_account}_${now_stamp}.out"
		save_file="${user_path}/uca_save.dat"

		###GET TOTAL NUMBER OF UCAs FOR PROGRESSBAR########
		if [ $gui_mode = 1 ]
		then
			rm ${user_path}/uca_list.tmp 2>/dev/null
			total_number_uca=$(wc -l <${script_path}/control/uca.conf)
			percent_per_uca=$(echo "scale=10; 100 / $total_number_uca"|bc)
			current_percent=0
			percent_display=0
			while read line
			do
				uca_info=$(echo $line|cut -d ',' -f4)
				printf "%b" "\"${uca_info}\" \"WAITING\"\n" >>${user_path}/uca_list.tmp
			done <${script_path}/control/uca.conf
		fi
		###################################################

		###READ UCA.CONF LINE BY LINE######################
		while read line
		do
			###SET SESSION KEY################################
			session_key=$(date -u +%Y%m%d)

			###GET VALUES FROM UCA.CONF#######################
			uca_connect_string=$(echo $line|cut -d ',' -f1)
			uca_snd_port=$(echo $line|cut -d ',' -f3)
			uca_info=$(echo $line|cut -d ',' -f4)

			###STATUS BAR FOR GUI##############################
			if [ $gui_mode = 1 ]
			then
				sed -i "s/\"${uca_info}\" \"WAITING\"/\"${uca_info}\" \"IN_PROGRESS\"/g" ${user_path}/uca_list.tmp
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_send" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi

			###GET STAMP#######################################
			now_stamp=$(date +%s)

			###ONLY CONTINUE IF SAVEFILE IS THERE##############
			if [ -s ${save_file} ]
			then
				###GET CONNECTION DATA#############################
				ssecret_there=$(grep -c "${uca_connect_string}" ${save_file})
				if [ ! $ssecret_there = 0 ]
				then
					###GET KEY FROM SAVE-TABLE#########################
					usera_ssecret=$(grep "${uca_connect_string}" ${save_file}|cut -d ':' -f2)
					usera_ssecret=$(( usera_ssecret + usera_ssecret ))
					usera_hssecret=$(echo "${usera_ssecret}_${session_key}"|sha256sum)
					usera_hssecret=${usera_hssecret%% *}
					usera_session_id=$(grep "${uca_connect_string}" ${save_file}|cut -d ':' -f3)
					uca_user=$(grep "${uca_connect_string}" ${save_file}|cut -d ':' -f4)

					###CREATE FILE LIST FOR SYNC FILE##################
					receipient_index_file="${script_path}/proofs/${uca_user}/${uca_user}.txt"
					###GROUP COMMANDS TO OPEN FILE ONLY ONCE###################
					{
						if [ -s $receipient_index_file ]
						then
							###GET ASSETS######################################
							while read line
							do
								asset_there=$(grep -c "assets/${line}" $receipient_index_file)
								if [ $asset_there = 0 ]
								then
									echo "assets/${line}"
								fi
							done <${user_path}/all_assets.dat

							###GET KEYS AND PROOFS#############################
							while read line
							do
								key_there=$(grep -c "keys/${line}" $receipient_index_file)
								if [ $key_there = 0 ]
								then
									echo "keys/${line}"
								fi

								for tsa_service in $(ls -1 ${script_path}/certs)
								do
									tsa_req_there=0
									tsa_req_there=$(grep -c "proofs/${line}/${tsa_service}.tsq" $receipient_index_file)
									if [ $tsa_req_there = 0 ]
									then
										echo "proofs/${line}/${tsa_service}.tsq"
									fi
									tsa_res_there=0
									tsa_res_there=$(grep -c "proofs/${line}/${tsa_service}.tsr" $receipient_index_file)
									if [ $tsa_res_there = 0 ]
									then
										echo "proofs/${line}/${tsa_service}.tsr"
									fi
								done
								if [ -s ${script_path}/proofs/${line}/${line}.txt ]
								then
									echo "proofs/${line}/${line}.txt"
								fi
							done <${user_path}/depend_accounts.dat

							###GET TRX#########################################
							while read line
							do
								trx_there=$(grep -c "trx/${line}" $receipient_index_file)
								if [ $trx_there = 0 ]
								then
									echo "trx/${line}"
								fi
							done <${user_path}/depend_trx.dat
						else
							###GET ASSETS######################################
							awk '{print "assets/" $1}' ${user_path}/all_assets.dat

							###GET KEYS AND PROOFS#############################
							while read line
							do
								echo "keys/${line}"
								for tsa_file in $(ls -1 ${script_path}/proofs/${line}/*.ts*)
								do
									file=$(basename $tsa_file)
									echo "proofs/${line}/${file}"
								done
								if [ -s ${script_path}/proofs/${line}/${line}.txt ]
								then
									echo "proofs/${line}/${line}.txt"
								fi
							done <${user_path}/depend_accounts.dat

							###GET TRX#########################################
							awk '{print "trx/" $1}' ${user_path}/depend_trx.dat
						fi
					} >${user_path}/files_list.tmp

					###STEP INTO HOMEDIR AND CREATE TARBALL######
					cd ${script_path}/
					tar -czf ${out_file} -T ${user_path}/files_list.tmp --dereference --hard-dereference
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###ENCRYPT HEADER CONTAINING SESSION ID############
						printf "%s" "${usera_session_id}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${user_path}/uca_header.tmp --passphrase ${session_key} - 2>/dev/null
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###ENCRYPT SYNCFILE################################
							gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${sync_file} --passphrase ${usera_hssecret} ${out_file}
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								###SEND KEY AND SYNCFILE VIA DIFFIE-HELLMAN########
								cat ${user_path}/uca_header.tmp ${sync_file}|netcat -q0 -w5 ${uca_connect_string} ${uca_snd_port} >/dev/null 2>/dev/null
								rt_query=$?
								if [ ! $rt_query = 0 ]
								then
									if [ $gui_mode = 0 ]
									then
										echo "ERROR: UCA-LINK SND ${uca_connect_string}:${uca_snd_port} FAILED"
									fi
								fi
							fi
						fi
						rm ${user_path}/uca_header.tmp 2>/dev/null
						rm ${sync_file} 2>/dev/null
						rm ${user_path}/files_list.tmp 2>/dev/null
					fi
					rm ${out_file} 2>/dev/null
				fi
			fi
			###STATUS BAR FOR GUI##############################
			if [ $gui_mode = 1 ]
			then
				current_percent=$(echo "scale=10; ${current_percent} + ${percent_per_uca}"|bc)
				percent_display=$(echo "scale=0; ${current_percent} / 1"|bc)
				if [ $rt_query = 0 ]
				then
					sed -i "s/\"${uca_info}\" \"IN_PROGRESS\"/\"${uca_info}\" \"SUCCESSFULL\"/g" ${user_path}/uca_list.tmp
				else
					sed -i "s/\"${uca_info}\" \"IN_PROGRESS\"/\"${uca_info}\" \"FAILED\"/g" ${user_path}/uca_list.tmp
				fi
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_send" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi
		done <${script_path}/control/uca.conf
		rm ${save_file} 2>/dev/null
		rm ${user_path}/uca_list.tmp 2>/dev/null
		sleep 1
}
##################
#Main Menu Screen#
##################
###VERSION INFO#############
core_system_name="Universal Credit System"
core_system_version="v0.0.1"

###SET INITIAL VARIABLES####
check_period_tsa=21600
main_asset="UCC"
main_token="UCT"
start_date="20241229"
now=$(date -u +%Y%m%d)
no_ledger=0
user_logged_in=0
uca_trigger=0
action_done=1
make_ledger=1
make_new_index=1
end_program=0
small_trx=0
script_path=$(dirname $(readlink -f ${0}))
my_pid=$$

###SOURCE CONFIG FILE#######
. ${script_path}/control/config.conf

###SET THEME################
export DIALOGRC="${script_path}/theme/${theme_file}"
dialogrc_set="${theme_file}"

###SOURCE LANGUAGE FILE#####
. ${script_path}/lang/${lang_file}

###CHECK IF GUI MODE OR CMD MODE AND ASSIGN VARIABLES###
if [ $# -gt 0 ]
then
	###IF ANY VARIABLES ARE HANDED OVER SET INITAL VALUES##########
	gui_mode=0
	cmd_var=""
	cmd_action=""
	cmd_user=""
	cmd_pin=""
	cmd_pw=""
	cmd_sender=""
	cmd_receiver=""
	cmd_amount=""
	cmd_asset=$main_asset
	cmd_purpose=""
	cmd_type=""
	cmd_path=""
	cmd_file=""

	###GO THROUGH PARAMETERS ONE BY ONE############################
	while [ $# -gt 0 ]
	do
		###GET TARGET VARIABLES########################################
		case $1 in
			"-no_ledger")	no_ledger=1
					;;
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
			"-type")	cmd_var=$1
					;;
			"-path")	cmd_var=$1
					;;
			"-file")	cmd_var=$1
					;;
			"-help")	more ${script_path}/control/HELP.txt
					exit 0
					;;
			*)		###SET TARGET VARIABLES########################################
					case $cmd_var in
						"-action")	cmd_action=$1
								case $cmd_action in
									"create_user")		main_menu=$dialog_main_create
												;;
									"create_backup")	main_menu=$dialog_main_backup
												;;
									"restore_backup")	main_menu=$dialog_main_backup
												;;
									"create_trx")		main_menu=$dialog_main_logon
												user_menu=$dialog_send
												;;
									"read_trx")		main_menu=$dialog_main_logon
												user_menu=$dialog_receive
												;;
									"create_sync")		main_menu=$dialog_main_logon
												user_menu=$dialog_sync
												;;
									"read_sync")		main_menu=$dialog_main_logon
												user_menu=$dialog_sync
												;;
									"sync_uca")		main_menu=$dialog_main_logon
												user_menu=$dialog_uca
												;;
									"show_balance")		main_menu=$dialog_main_logon
												;;
									"show_stats")		main_menu=$dialog_main_logon
												user_menu=$dialog_stats
												;;
									*)			echo "ERROR! TRY THIS:"
												echo "./ucs_client.sh -help"
												exit 1
												;;
								esac
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
						"-type")	cmd_type=$1
								case $cmd_type in
									"partial")	small_trx=0
											extract_all=0
											;;
									"full")		small_trx=1
											extract_all=1
											;;
									*)		echo "ERROR! TRY THIS:"
											echo "./ucs_client.sh -help"
											exit 1
											;;
								esac
								;;
						"-path")	cmd_path=$1
								;;
						"-file")	cmd_file=$1
								;;
						*)		echo "ERROR! TRY THIS:"
								echo "./ucs_client.sh -help"
								exit 1
								;;
					esac
					cmd_var=""
					;;
		esac
		shift
	done
	if [ $no_ledger = 1 ]
	then
		if [ $cmd_action = "create_trx" ]
		then
			no_ledger=0
		fi
	fi
else
	gui_mode=1
fi
while [ $end_program = 0 ]
do
	if [ $user_logged_in = 0 ]
	then
		if [ $gui_mode = 1 ]
		then
			main_menu=$(dialog --ok-label "$dialog_main_choose" --no-cancel --backtitle "$core_system_name $core_system_version" --output-fd 1 --colors --no-items --menu "\Z7XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXX                   XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX                   XXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXX \ZUUNIVERSAL CREDIT SYSTEM\ZU XXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 22 43 5 "$dialog_main_logon" "$dialog_main_create" "$dialog_main_settings" "$dialog_main_backup" "$dialog_main_end")
			rt_query=$?
		else
			rt_query=0
		fi
		if [ ! $rt_query = 0 ]
		then
			clear
			exit 0
		else
			case $main_menu in
				"$dialog_main_logon")   set -f
							account_name_entered="blank"
							account_pin_entered="12345"
							account_name_entered_correct=0
							while [ $account_name_entered_correct = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									account_name_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --output-fd 1 --max-input 30 --inputbox "$dialog_login_display_account" 0 0 "")
									rt_query=$?
								else
									if [ ! "${cmd_user}" = "" ]
									then
										rt_query=0
										account_name_entered=$cmd_user
									else
										if [ "${cmd_sender}" = "" ]
										then
											exit 1
										fi
									fi
								fi
								if [ $rt_query = 0 ]
								then
									check_input "${account_name_entered}" 0
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										account_pin_entered_correct=0
										while [ $account_pin_entered_correct = 0 ]
										do
											if [ $gui_mode = 1 ]
											then
												account_pin_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --output-fd 1 --max-input 5 --insecure --passwordbox "$dialog_login_display_loginkey" 0 0 "")
												rt_query=$?
											else
												if [ ! "${cmd_pin}" = "" ]
												then
													rt_query=0
													account_pin_entered=$cmd_pin
												else
													if [ "${cmd_sender}" = "" ]
													then
														exit 1
													fi
												fi
											fi
											if [ $rt_query = 0 ]
											then
												check_input "${account_pin_entered}" 1
												rt_query=$?
												if [ $rt_query = 0 ]
										       		then
													account_password_entered_correct=0
	     												while [ $account_password_entered_correct = 0 ]
	       												do
														if [ $gui_mode = 1 ]
														then
															account_password_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_login_display_pw" 0 0 "")
															rt_query=$?
														else
															if [ ! "${cmd_pw}" = "" ]
															then
																rt_query=0
																account_password_entered=$cmd_pw
															else
																exit 1
															fi
														fi
							     	   						if [ $rt_query = 0 ]
							       							then
															check_input "${account_password_entered}" 0
															rt_query=$?
															if [ $rt_query = 0 ]
															then
																login_account "${account_name_entered}" "${account_pin_entered}" "${account_password_entered}"
																account_password_entered_correct=1
																account_pin_entered_correct=1
																account_name_entered_correct=1
															fi
														else
															account_password_entered_correct=1
															account_pin_entered_correct=1
															account_name_entered_correct=1
														fi
													done
												fi
											else
												account_pin_entered_correct=1
												account_name_entered_correct=1
											fi
										done
									fi
								else
									account_name_entered_correct=1
								fi
							done
							set +f
							;;
				"$dialog_main_create")  set -f
							account_name_inputbox=""
							account_name_entered_correct=0
							while [ $account_name_entered_correct = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									account_name=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --title "$dialog_main_create" --backtitle "$core_system_name $core_system_version" --max-input 30 --output-fd 1 --inputbox "$dialog_keys_account" 0 0 "${account_name_inputbox}")
									rt_query=$?
								else
									if [ "${cmd_user}" = "" ]
									then
										account_name=$(tr -dc A-Za-z0-9 </dev/urandom|head -c 20)
									else
										account_name=$cmd_user
									fi
									rt_query=0
								fi
								if [ $rt_query = 0 ]
								then
									check_input "${account_name}" 0
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										account_pin_inputbox=""
										account_pin_entered_correct=0
										while [ $account_pin_entered_correct = 0 ]
										do
											if [ $gui_mode = 1 ]
											then
												account_pin_first=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin1" 0 0 "$account_pin_inputbox")
												rt_query=$?
											else
												if [ "${cmd_pin}" = "" ]
												then
													account_pin_first=$(tr -dc 0-9 </dev/urandom|head -c 5)
													account_pin_second=$account_pin_first
												else
													account_pin_first=$cmd_pin
													account_pin_second=$cmd_pin
												fi
												rt_query=0
											fi
											if [ $rt_query = 0 ]
											then
												check_input "${account_pin_first}" 1
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													if [ $gui_mode = 1 ]
													then
														clear
														account_pin_second=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin2" 0 0 "$account_pin_inputbox")
														rt_query=$?
													else
														rt_query=0
													fi
													if [ $rt_query = 0 ]
													then
				       										if [ ! "${account_pin_first}" = "${account_pin_second}" ]
														then
															clear
															dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_pinmatch" 0 0
															clear
														else
															account_password_entered_correct=0
	     														while [ $account_password_entered_correct = 0 ]
	       														do
																if [ $gui_mode = 1 ]
																then
																	account_password_first=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw1" 0 0)
																	rt_query=$?
																else
																	if [ "${cmd_pw}" = "" ]
																	then
																		account_password_first=$(tr -dc A-Za-z0-9 </dev/urandom|head -c 10)
																		account_password_second=$account_password_first
																	else
																		account_password_first=$cmd_pw
																		account_password_second=$cmd_pw
																	fi
																	rt_query=0
																fi
																if [ $rt_query = 0 ]
																then
	       																check_input "${account_password_first}" 0
																	rt_query=$?
																	if [ $rt_query = 0 ]
																	then
																		if [ $gui_mode = 1 ]
																		then
																			clear
																			account_password_second=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw2" 0 0)
																			rt_query=$?
																		else
																			rt_query=0
																		fi
																		if [ $rt_query = 0 ]
																		then
				       															if [ ! "${account_password_first}" = "${account_password_second}" ]
																			then
																				clear
																				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_pwmatch" 0 0
																				clear
																			else
																				account_name_entered_correct=1
																				account_pin_entered_correct=1
																				account_password_entered_correct=1
																				create_keys "${account_name}" "${account_pin_second}" "${account_password_second}"
																				rt_query=$?
																				if [ $rt_query = 0 ]
																				then
																					dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_success" 0 0
																				else
																					dialog --title "$dialog_type_titel_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_fail" 0 0
																				fi
																			fi
																		else
																			account_password_entered_correct=1
																		fi
																	fi
																else
																	account_password_entered_correct=1
																fi
															done
														fi
													else
														account_pin_entered_correct=1
													fi
												fi
											else
												if [ $rt_query = 3 ]
												then
													account_pin_inputbox=$(tr -dc 0-9 </dev/urandom|head -c 5)
												else
													account_pin_entered_correct=1
												fi
											fi
										done
									fi
								else
									if [ $rt_query = 3 ]
									then
										account_name_inputbox=$(tr -dc A-Za-z0-9 </dev/urandom|head -c 20)
									else
										account_name_entered_correct=1
									fi
								fi
							done
							set +f
							;;
				"$dialog_main_settings")	quit_settings=0
								while [ $quit_settings -eq 0 ]
								do
									settings_menu=$(dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_main_back" --backtitle "$core_system_name $core_system_version" --output-fd 1 --colors --menu "$dialog_main_settings" 0 5 0 "$dialog_main_lang" "" "$dialog_main_theme" "" "config.conf" "")
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										case $settings_menu in
											"$dialog_main_lang")	for language_file in $(ls -1 ${script_path}/lang/)
														do
															lang_ex_short=$(echo $language_file|cut -d '_' -f2)
															lang_ex_full=$(echo $language_file|cut -d '_' -f3|cut -d '.' -f1)
															printf "%s" "$lang_ex_short $lang_ex_full " >>${script_path}/lang_list.tmp
														done
														lang_selection=$(dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_cancel" --title "$dialog_main_lang" --backtitle "$core_system_name $core_system_version" --output-fd 1 --menu "$dialog_lang" 0 0 0 --file ${script_path}/lang_list.tmp)
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															new_lang_file=$(ls -1 ${script_path}/lang/|grep "lang_${lang_selection}_")
															if [ ! $lang_file = $new_lang_file ]
															then
																sed -i "s/lang_file=${lang_file}/lang_file=${new_lang_file}/g" ${script_path}/control/config.conf
																. ${script_path}/control/config.conf
																. ${script_path}/lang/${lang_file}
															fi
														fi
														rm ${script_path}/lang_list.tmp
														;;
											"$dialog_main_theme")	for theme_file in $(ls -1 ${script_path}/theme/)
														do
															theme_name=${theme_file%%.*}
															printf "%s" "$theme_name theme " >>${script_path}/theme_list.tmp
														done
														theme_selection=$(dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_cancel" --title "$dialog_main_theme" --backtitle "$core_system_name $core_system_version" --output-fd 1 --menu "$dialog_theme" 0 0 0 --file ${script_path}/theme_list.tmp)
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															new_theme_file=$(ls -1 ${script_path}/theme/|grep "${theme_selection}")
															if [ ! $dialogrc_set = $new_theme_file ]
															then
																sed -i "s/theme_file=${dialogrc_set}/theme_file=${new_theme_file}/g" ${script_path}/control/config.conf
																. ${script_path}/control/config.conf
																export DIALOGRC="${script_path}/theme/${theme_file}"
																dialogrc_set="${theme_file}"
																clear
																sleep 1
															fi
														fi
														rm ${script_path}/theme_list.tmp
														;;
											"config.conf")		rm ${script_path}/config_*.tmp 2>/dev/null
														config_changed=0
														while [ $config_changed -eq 0 ]
														do
															### CREATE COPY OF CONFIG.CONF ##################
															cat ${script_path}/control/config.conf|grep -v "###"|sed 's/=/= /g' >${script_path}/config_${my_pid}.tmp

															### DISPLAY INPUTMENU DIALOG ####################
															changed=$(dialog --cancel-label "$dialog_main_back" --extra-label "$dialog_main_choose" --output-fd 1 --inputmenu "CONFIG.CONF" 30 70 10 --file ${script_path}/config_${my_pid}.tmp)
															rt_query=$?
															if [ $rt_query = 3 ]
															then
																entry=$(echo "${changed}"|awk '{print $2}'|awk -F= '{print $1}')
																old_value=$(grep "${entry}" ${script_path}/config_${my_pid}.tmp|awk -F= '{print $2}'|sed 's/ //g')
																new_value=$(echo "${changed}"|awk '{print $3}')
																sed -i "s#${entry}=${old_value}#${entry}=${new_value}#" ${script_path}/control/config.conf
															else
																config_changed=1
															fi
														done
														rm ${script_path}/config_${my_pid}.tmp
														;;
										esac
									else
										quit_settings=1
									fi
								done
								;;
				"$dialog_main_backup")	if [ $gui_mode = 1 ]
							then
								dialog --yes-label "$dialog_backup_create" --no-label "$dialog_backup_restore" --title "$dialog_main_backup" --backtitle "$core_system_name $core_system_version" --yesno "$dialog_backup_text" 0 0
								rt_query=$?
							else
								case $cmd_action in
								 	"create_backup")	rt_query=0
												;;
									"restore_backup")	rt_query=1
												;;
								esac
							fi
							if [ $rt_query = 0 ]
							then
								cd ${script_path}
								now_stamp=$(date +%s)
								tar -czf ${script_path}/backup/${now_stamp}.bcp assets/ control/ keys/ trx/ proofs/ userdata/ --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									cd ${script_path}/backup
									backup_file=$(find . -maxdepth 1 -type f|sed "s#./##g"|sort -t . -k1|tail -1)
									if [ $gui_mode = 1 ]
									then
										dialog_backup_success_display=$(echo $dialog_backup_create_success|sed "s/<backup_file>/${backup_file}/g")
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_backup_success_display" 0 0
									else
										echo "BACKUP_FILE:${backup_file}"
										exit 0
									fi
								else
									rm ${script_path}/backup/${now_stamp}.bcp 2>/dev/null
									if [ $gui_mode = 1 ]
									then
										dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_backup_create_fail" 0 0
									else
										exit 1
									fi
								fi
							else
								if [ ! $rt_query = 255 ]
								then
									if [ $gui_mode = 1 ]
									then
										cd ${script_path}/backup
										touch ${script_path}/backups_list.tmp
										find . -maxdepth 1 -type f|sed "s#./##g"|sort -r -t . -k1 >${script_path}/backups_list.tmp
										no_backups=$(wc -l <${script_path}/backups_list.tmp)
										if [ $no_backups -gt 0 ]
										then
											while read line
											do
												backup_stamp=${line%%.*}
												backup_date=$(date +'%F|%H:%M:%S' --date=@${backup_stamp})
												printf "%s" "${backup_date} BACKUP " >>${script_path}/backup_list.tmp
											done <${script_path}/backups_list.tmp
										else
											printf "%s" "${dialog_history_noresult}" >${script_path}/backup_list.tmp
										fi
										backup_decision=$(dialog --ok-label "$dialog_backup_restore" --cancel-label "$dialog_main_back" --title "$dialog_main_backup" --backtitle "$core_system_name $core_system_version" --output-fd 1 --menu "$dialog_backup_menu" 0 0 0 --file ${script_path}/backup_list.tmp)
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											no_results=${dialog_history_noresult%% *}
											if [ ! "${backup_decision}" = "${no_results}" ]
											then
												bcp_date_extracted=${backup_decision%%|*}
												bcp_time_extracted=${backup_decision#*|}
												bcp_stamp=$(date +%s --date="${bcp_date_extracted} ${bcp_time_extracted}")
												bcp_file=$(cat ${script_path}/backups_list.tmp|grep "${bcp_stamp}")
												file_path="${script_path}/backup/${bcp_file}"
												cd ${script_path}
												purge_files
												tar -xzf $file_path --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
												rt_query=$?
												if [ $rt_query -gt 0 ]
												then
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_backup_restore_fail" 0 0
												else
													import_keys
													dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_backup_restore_success" 0 0
												fi
											else
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_backup_fail" 0 0
											fi
										else
											rm ${script_path}/backups_list.tmp 2>/dev/null
										fi
									else
										if [ "${cmd_path}" = "" ]
										then
											exit 1
										else
											cd ${script_path}
											file_path=$cmd_path
											tar -tf $file_path >/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												purge_files
												tar -xzf $file_path --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
												rt_query=$?
												if [ $rt_query -gt 0 ]
												then
													exit 1
												else
													import_keys
													echo "SUCCESS"
													exit 0
												fi
											else
												exit 1
											fi
										fi
									fi
								fi
							fi
							rm ${script_path}/backup_list.tmp 2>/dev/null
							;;
				"$dialog_main_end")     clear
							end_program=1
							;;
			esac
		fi

	else
		###IF AUTO-UCA-SYNC########################
		if [ $auto_uca_start = 1 ] && [ $no_ledger = 0 ]
		then
			request_uca
		fi

		###ON EACH START AND AFTER EACH ACTION...
		if [ $action_done = 1 ]
		then
			check_tsa
			check_keys
			check_assets
			check_trx
			get_dependencies
			ledger_mode=$?
			action_done=0
		fi

		if [ $no_ledger = 0 ]
		then
			if [ $make_ledger = 1 ]
			then
				build_ledger $ledger_mode
				if [ $make_new_index = 1 ]
				then
					now_stamp=$(date +%s)
					make_signature "none" $now_stamp 1
				fi
				make_ledger=0
			fi
			check_blacklist
			account_my_balance=""
			account_my_score=""
			for ledger_entry in $(grep ":${handover_account}" ${user_path}/${now}_ledger.dat)
			do
				balance_asset=${ledger_entry%%:*}
				balance_value=${ledger_entry#*=}
				account_my_balance="${account_my_balance}${balance_value} ${balance_asset}\n"
				score_there=$(grep -c "${balance_asset}:${handover_account}" ${user_path}/${now}_scoretable.dat)
				if [ $score_there -eq 1 ]
				then
					score_value=$(grep "${balance_asset}:${handover_account}" ${user_path}/${now}_scoretable.dat)
					score_value=${score_value#*=}
					is_score_greater_balance=$(echo "${score_value} > ${balance_value}"|bc)
					if [ $is_score_greater_balance = 1 ]
					then
						account_my_score_tmp=$balance_value
					else
						account_my_score_tmp=$score_value
					fi
				else
					account_my_score_tmp=$balance_value
				fi
				account_my_score="${account_my_score}${account_my_score_tmp} ${balance_asset}\n"
			done
		fi

		###IF AUTO-UCA-SYNC########################
		if [ $auto_uca_start = 1 ] && [ $no_ledger = 0 ]
		then
			send_uca
		fi

		###SET UCA TRIGGER BACK TO 0###############
		if [ $uca_trigger = 1 ]
		then
			auto_uca_start=0
			uca_trigger=0
		fi

		if [ $gui_mode = 1 ]
		then
			dialog_main_menu_text_display=$(echo $dialog_main_menu_text|sed -e "s/<login_name>/${login_name}/g" -e "s/<handover_account>/${handover_account}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<account_my_score>/${account_my_score}/g")
			user_menu=$(dialog --ok-label "$dialog_main_choose" --no-cancel --title "$dialog_main_menu" --backtitle "$core_system_name $core_system_version" --output-fd 1 --no-items --menu "$dialog_main_menu_text_display" 0 0 0 "$dialog_send" "$dialog_receive" "$dialog_sync" "$dialog_uca" "$dialog_browser" "$dialog_history" "$dialog_stats" "$dialog_logout")
			rt_query=$?
		else
			rt_query=0
		fi

		if [ ! $rt_query = 0 ]
		then
			user_logged_in=0
			action_done=1
			make_ledger=1
			clear
		else
			if [ $gui_mode = 1 ]
			then
				clear
			fi
			case "$user_menu" in
				"$dialog_send")	asset_found=0
						receipient_is_asset=0
						grep "${handover_account}" ${user_path}/${now}_ledger.dat|cut -d ':' -f1|sort -t. -k2 >${user_path}/menu_assets.tmp
						while [ $asset_found = 0 ]
						do
							if [ $gui_mode = 1 ]
							then
								quit_asset_loop=0
								while [ $quit_asset_loop = 0 ]
								do
									###ASSET OVERVIEW################################
									order_asset=$(dialog --cancel-label "$dialog_cancel" --extra-button --extra-label "$dialog_show" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_assets:" 0 0 0 --file ${user_path}/menu_assets.tmp)
									rt_query=$?
									if [ $rt_query = 3 ]
									then
										###DISPLAY DETAILED ASSET INFORMATION############
										dialog --exit-label "$dialog_main_back" --title "$dialog_assets : $order_asset" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/assets/${order_asset}" 0 0						
									else
										quit_asset_loop=1
									fi
								done
							else
								order_asset=$cmd_asset
								asset_there=$(grep -c "${order_asset}" ${user_path}/menu_assets.tmp)
								if [ $asset_there = 1 ]
								then
									rt_query=0
								else
									exit 1
								fi
							fi
							if [ $rt_query = 0 ]
							then
								currency_symbol=$order_asset
								asset_found=1
								receipient_found=0
								amount_selected=1
								order_aborted=0
								order_receipient=""
								while [ $receipient_found = 0 ]
								do
									if [ $gui_mode = 1 ]
									then
										###USER OVERVIEW####################################################
										order_receipient=$(dialog --ok-label "$dialog_next" --cancel-label "..." --help-button --help-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --max-input 56 --output-fd 1 --inputbox "$dialog_send_address" 0 0 "$order_receipient")
										rt_query=$?
									else
										rt_query=0
										order_receipient=$cmd_receiver
									fi
									if [ $rt_query = 0 ]
									then
										if [ ! "${order_receipient}" = "" ]
										then
											###CHECK IF INPUT CONTAINS ALNUM####################################
											check_input $order_receipient 0
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												###CHECK IF RECEIPIENT IS USER OR ASSET#############################
												if [ $(grep -c -w "${order_receipient}" ${user_path}/all_accounts.dat) = 1 ]
												then
													receipient_found=1
													amount_selected=0
												else
													asset_there=$(grep -c -w "${order_receipient}" ${user_path}/all_assets.dat)
													asset=$(grep -w "${order_receipient}" ${user_path}/all_assets.dat)
													is_fungible=$(cat ${script_path}/assets/${asset}|grep -c "asset_fungible=1" 2>/dev/null)
													if [ $asset_there = 1 ] && [ $is_fungible = 1 ]
													then
														receipient_is_asset=1
														receipient_found=1
														amount_selected=0
													else
														if [ $gui_mode = 1 ]
														then
															dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_history_noresult" 0 0
														else
															exit 1
														fi
													fi
												fi
												while [ $amount_selected = 0 ]
												do
													account_my_balance=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_ledger.dat)
													account_my_balance=${account_my_balance#*=}
													if [ "${order_asset}" = "${main_asset}" ]
													then
														###SCORE############################################################
														account_my_score=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_scoretable.dat)
														account_my_score=${account_my_score#*=}
														sender_score_balance_value=$account_my_score
														is_score_greater_balance=$(echo "${account_my_score}>${account_my_balance}"|bc)
														if [ $is_score_greater_balance = 1 ]
														then
															account_my_score=$account_my_balance
														fi
														sender_score_balance_value=$account_my_score
														####################################################################
													else
														account_my_score=$account_my_balance
													fi
													if [ $gui_mode = 1 ]
													then
														dialog_send_amount_display=$(echo $dialog_send_amount|sed -e "s/<score>/${account_my_score}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g")
														order_amount=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --output-fd 1 --inputbox "$dialog_send_amount_display" 0 0 "1.000000000")
														rt_query=$?
													else
														rt_query=0
														order_amount=$cmd_amount
													fi
													if [ $rt_query = 0 ]
													then
														order_amount_alnum=$(echo $order_amount|grep -c '[^0-9.,]')
														if [ $order_amount_alnum = 0 ]
														then
															order_amount_formatted=$(echo $order_amount|sed -e 's/,/./g' -e 's/ //g')
															amount_mod=$(echo "${order_amount_formatted} % 0.000000001"|bc)
															amount_mod=$(echo "${amount_mod} > 0"|bc)
															if [ $amount_mod = 0 ]
															then
																order_amount_formatted=$(echo "scale=9; ${order_amount_formatted} / 1"|bc|sed 's/^\./0./g')
																is_amount_big_enough=$(echo "${order_amount_formatted} >= 0.000000001"|bc)
																if [ $is_amount_big_enough = 1 ]
																then
																	enough_balance=$(echo "${account_my_balance} - ${order_amount_formatted} >= 0"|bc)
																	if [ "${order_asset}" = "${main_asset}" ]
																	then
																		###SCORE#############################################################
																		is_score_ok=$(echo "${sender_score_balance_value} >= ${order_amount_formatted}"|bc)
																		#####################################################################
																	else
																		is_score_ok=1
																	fi
																	if [ $enough_balance = 1 ] && [ $is_score_ok = 1 ]
																	then
																		amount_selected=1
																	else
																		if [ $gui_mode = 1 ]
																		then
																			dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail_nobalance" 0 0
																		else
																			exit 1
																		fi
																	fi
																else
																	if [ $gui_mode = 1 ]
																	then
																		dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_amount_not_big_enough" 0 0
																	else
																		exit 1
																	fi
																fi
															else
																if [ $gui_mode = 1 ]
																then
																	dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_amount_not_big_enough" 0 0
																else
																	exit 1
																fi
															fi
														else
															if [ $gui_mode = 1 ]
															then
																dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail_amount" 0 0
															else
																exit 1
															fi
														fi
													else
														amount_selected=1
														receipient_found=1
														order_aborted=1
													fi
												done
											fi
										fi
									else
										if [ $rt_query = 1 ]
										then
											rm ${user_path}/menu_addresses_fungible.tmp 2>/dev/null
											touch ${user_path}/menu_addresses_fungible.tmp
											is_order_asset_fungible=$(grep -c "asset_fungible=1" ${script_path}/assets/${order_asset})
											if [ $is_order_asset_fungible = 1 ]
											then
												while  read line
												do
													is_fungible=$(grep -c "asset_fungible=1" ${script_path}/assets/$line)
													if [ $is_fungible = 1 ]
													then
														echo $line >>${user_path}/menu_addresses_fungible.tmp
													fi
												done <${user_path}/all_assets.dat
											fi
											cat ${user_path}/menu_addresses_fungible.tmp ${user_path}/all_assets.dat|grep -v "${order_asset}"|sort|uniq -d|sort -t. -k2|cat - ${user_path}/all_accounts.dat >${user_path}/menu_addresses.tmp
											order_receipient=$(dialog --cancel-label "$dialog_main_back" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "..." 0 0 0 --file ${user_path}/menu_addresses.tmp)
											rm ${user_path}/menu_addresses.tmp
											rm ${user_path}/menu_addresses_fungible.tmp
										else
											receipient_found=1
											order_aborted=1
										fi
									fi
								done
								if [ $order_aborted = 0 ]
								then
									is_text=0
									is_file=0
									touch ${user_path}/trx_purpose_blank.tmp
									if [ $receipient_is_asset = 0 ]
									then
										if [ $gui_mode = 1 ]
										then
											###LOOP UNTIL A PURPOSE HAS BEEN DEFINED##############
											quit_purpose_loop=0
											while [ $quit_purpose_loop = 0 ]
											do
												###DISPLAY INPUTFIELD FOR ORDER PURPOSE###############
												order_purpose=$(dialog --ok-label "$dialog_next" --cancel-label "..." --help-button --help-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --max-input 75 --output-fd 1 --inputbox "$dialog_send_purpose" 0 0 "")
												rt_query=$?
												if [ $rt_query = 1 ]
												then
													###IF USER WANTS EDITBOX##############################
													dialog --ok-label "$dialog_next" --cancel-label "..." --help-button --help-label "$dialog_cancel" --title "$dialog_send_purpose" --backtitle "$core_system_name $core_system_version" --editbox ${user_path}/trx_purpose_blank.tmp 20 80 2>${user_path}/trx_purpose_edited.tmp
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														order_purpose=$(cat ${user_path}/trx_purpose_edited.tmp)
														quit_purpose_loop=1
													else
														if [ $rt_query = 1 ]
														then
															quit_file_path=0
															path_to_search=$script_path
															while [ $quit_file_path = 0 ]
															do
																###IF USER WANTS FILE##############################
																file_path=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name $core_system_version" --output-fd 1 --fselect "$path_to_search" 20 48)
																rt_query=$?
																if [ $rt_query = 0 ]
																then
																	if [ ! -d "${file_path}" ] && [ -s "${file_path}" ]
																	then
																		quit_file_path=1
																		quit_purpose_loop=1
																		order_purpose_path=$file_path
																		is_file=1
																		is_text=$(file ${order_purpose_path}|grep -c -v "text")
																	else
																		path_to_search=$file_path
																	fi
																else
																	quit_file_path=1
																fi
															done
														fi
													fi
												else
													quit_purpose_loop=1
												fi
											done
										else
											###CHECK IF FILE IS USED FOR PUPOSE###################
											if [ ! "${cmd_file}" = "" ] && [ -s ${cmd_file} ]
											then
												order_purpose_path=$cmd_file
												is_file=1
												is_text=$(file ${order_purpose_path}|grep -c -v "text")
											else
												order_purpose=$cmd_purpose
											fi
										fi
									else
										###SET PURPOSE TO EXCHANGE##############################
										order_purpose="EXCHANGE"
									fi
									if [ $rt_query = 0 ]
									then
										if [ $is_text = 0 ] && [ $is_file = 0 ]
										then
											###ENCRYPT ORDER PURPOSE################################
											printf "%b" "${order_purpose}" >${user_path}/trx_purpose_edited.tmp
										else
											###CHANGE ORDER PURPOSE TO BINARY DATA##################
											order_purpose="[data:${order_purpose_path}]"
											
											###COPY FILE TO SEND AS PURPOSE#########################
											cp ${order_purpose_path} ${user_path}/trx_purpose_edited.tmp
										fi
										if [ $receipient_is_asset = 0 ]
										then
											###IF RECIPIENT IS NORMAL USER USE HIS KEY##############
											order_purpose_hash=$(echo "\n$(gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always -r ${order_receipient} --pinentry-mode loopback --armor --output - --encrypt ${user_path}/trx_purpose_edited.tmp|awk '/-----BEGIN PGP MESSAGE-----/{next} /-----END PGP MESSAGE-----/{next} NF>0 {print}' -)")
										else
											###IF RECIPIENT IS ASSET USE USERS KEY##################
											order_purpose_hash=$(echo "\n$(gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always -r ${handover_account} --pinentry-mode loopback --armor --output - --encrypt ${user_path}/trx_purpose_edited.tmp|awk '/-----BEGIN PGP MESSAGE-----/{next} /-----END PGP MESSAGE-----/{next} NF>0 {print}' -)")
										fi
										rm ${user_path}/trx_purpose_blank.tmp
										rm ${user_path}/trx_purpose_edited.tmp 2>/dev/null
										########################################################
										if [ $gui_mode = 1 ]
										then
											###ASK FOR FINAL CONFIRMATION############################
											currency_symbol=$order_asset
											dialog_send_overview_display=$(echo $dialog_send_overview|sed -e "s#<order_receipient>#${order_receipient}#g" -e "s#<account_my_balance>#${account_my_balance}#g" -e "s#<currency_symbol>#${currency_symbol}#g" -e "s#<order_amount_formatted>#${order_amount_formatted}#g" -e "s#<order_purpose>##g")
											printf "%b" "${dialog_send_overview_display}\n${order_purpose}" >${user_path}/order_confirm.tmp
											dialog --exit-label "$dialog_yes" --help-button --help-label "$dialog_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --textbox "${user_path}/order_confirm.tmp" 0 0
											rt_query=$?
											rm ${user_path}/order_confirm.tmp
										else
											rt_query=0
										fi
										if [ $rt_query = 0 ]
										then
											trx_now=$(date +%s)
											make_signature ":TIME:${trx_now}\n:AMNT:${order_amount_formatted}\n:ASST:${order_asset}\n:SNDR:${handover_account}\n:RCVR:${order_receipient}\n:PRPS:${order_purpose_hash}" ${trx_now} 0
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												last_trx="${script_path}/trx/${handover_account}.${trx_now}"
												verify_signature ${last_trx} ${handover_account}
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													if [ $receipient_is_asset = 0 ]
													then
														if [ $gui_mode = 1 ] && [ ! $small_trx = 255 ]
														then
															dialog --yes-label "$dialog_yes" --no-label "$dialog_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --yesno "$dialog_send_trx" 0 0
															small_trx=$?
														fi
													fi
													if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
													then
														receipient_index_file="${script_path}/proofs/${order_receipient}/${order_receipient}.txt"
														###GROUP COMMANDS TO OPEN FILE ONLY ONCE###################
														{
															if [ $small_trx = 0 ] && [ -s $receipient_index_file ]
															then
																###GET ASSETS###################################################
																while read line
																do
																	asset_there=$(grep -c "assets/${line}" $receipient_index_file)
																	if [ $asset_there = 0 ]
																	then
																		echo "assets/${line}"
																	fi
																done <${user_path}/all_assets.dat

																###GET KEYS AND PROOFS##########################################
																while read line
																do
																	key_there=$(grep -c "keys/${line}" $receipient_index_file)
																	if [ $key_there = 0 ]
																	then
																		echo "keys/${line}"
																	fi

																	for tsa_service in $(ls -1 ${script_path}/certs)
																	do
																		tsa_req_there=0
																		tsa_req_there=$(grep -c "proofs/${line}/${tsa_service}.tsq" $receipient_index_file)
																		if [ $tsa_req_there = 0 ]
																		then
																			echo "proofs/${line}/${tsa_service}.tsq"
																		fi
																		tsa_res_there=0
																		tsa_res_there=$(grep -c "proofs/${line}/${tsa_service}.tsr" $receipient_index_file)
																		if [ $tsa_res_there = 0 ]
																		then
																			echo "proofs/${line}/${tsa_service}.tsr"
																		fi
																	done
																	if [ -s ${script_path}/proofs/${line}/${line}.txt ]
																	then
																		echo "proofs/${line}/${line}.txt"
																	fi
																done <${user_path}/depend_accounts.dat

																###GET TRX###################################################################
																while read line
																do
																	trx_there=$(grep -c "trx/${line}" $receipient_index_file)
																	if [ $trx_there = 0 ]
																	then
																		echo "trx/${line}"
																	fi
																done <${user_path}/depend_trx.dat
															else
																###GET ASSETS################################################################
																awk '{print "assets/" $1}' ${user_path}/all_assets.dat

																###GET KEYS AND PROOFS#######################################################
																while read line
																do
																	echo "keys/${line}"
																	for tsa_file in $(ls -1 ${script_path}/proofs/${line}/*.ts*)
																	do
																		file=$(basename $tsa_file)
																		echo "proofs/${line}/${file}"
																	done
																	if [ -s ${script_path}/proofs/${line}/${line}.txt ]
																	then
																		echo "proofs/${line}/${line}.txt"
																	fi
																done <${user_path}/depend_accounts.dat

																###GET TRX###################################################################
																awk '{print "trx/" $1}' ${user_path}/depend_trx.dat
															fi
															###GET LATEST TRX############################################################
															echo "trx/${handover_account}.${trx_now}"
														} >${user_path}/files_list.tmp
													fi

													###COMMANDS TO REPLACE BUILD_LEDGER CALL#####################################
													trx_hash=$(sha256sum ${script_path}/trx/${handover_account}.${trx_now})
													trx_hash=${trx_hash%% *}
													echo "trx/${handover_account}.${trx_now} ${trx_hash}" >>${user_path}/${now}_index_trx.dat
													make_signature "none" ${trx_now} 1
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
														then
															cd ${script_path}/
															tar -czf ${handover_account}_${trx_now}.trx.tmp -T ${user_path}/files_list.tmp --dereference --hard-dereference
															rt_query=$?
															rm ${user_path}/files_list.tmp 2>/dev/null
														fi
														if [ $rt_query = 0 ]
														then
															###COMMANDS TO REPLACE BUILD LEDGER CALL######################################
															##############################################################################
															if [ "${order_asset}" = "${main_asset}" ]
															then
																###SET SCORE##################################################################
																sender_new_score_balance=$(echo "${sender_score_balance_value} - ${order_amount_formatted}"|bc|sed 's/^\./0./g')
																sed -i "s/${order_asset}:${handover_account}=${sender_score_balance_value}/${order_asset}:${handover_account}=${sender_new_score_balance}/g" ${user_path}/${now}_scoretable.dat
																##############################################################################
															fi
															###SET BALANCE################################################################
															account_new_balance=$(echo "${account_my_balance} - ${order_amount_formatted}"|bc|sed 's/^\./0./g')
															sed -i "s/${order_asset}:${handover_account}=${account_my_balance}/${order_asset}:${handover_account}=${account_new_balance}/g" ${user_path}/${now}_ledger.dat
															##############################################################################

															###WRITE ENTRIES TO FILES#####################################################
															echo "${handover_account}.${trx_now}" >>${user_path}/all_trx.dat
															echo "${handover_account}.${trx_now}" >>${user_path}/depend_trx.dat
															echo "${handover_account}.${trx_now}" >>${user_path}/depend_confirmations.dat
															##############################################################################
															##############################################################################
															
															###WRITE OUTPUT IN CMD MODE BEFORE LEDGER AND SCORETABLE ARE DELETED##########
															if [ $gui_mode = 0 ]
															then
																cmd_output=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_ledger.dat)
																echo "BALANCE_${trx_now}:${cmd_output}"
																if [ "${order_asset}" = "${main_asset}" ]
																then
																	cmd_output=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_scoretable.dat)
																fi
																echo "UNLOCKED_BALANCE_${trx_now}:${cmd_output}"
															fi
															
															###SET VARIABLES FOR NEXT LOOP RUN###########################################
															make_ledger=1
															get_dependencies
															ledger_mode=$?

															###ENCRYPT TRX FILE SO THAT ONLY THE RECEIVER CAN READ IT####################
															if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
															then
																gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output ${handover_account}_${trx_now}.trx --passphrase ${order_receipient} ${handover_account}_${trx_now}.trx.tmp
																rt_query=$?
															fi
															if [ $rt_query = 0 ]
															then
																if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
																then
																	###REMOVE GPG TMP FILE#######################################################
																	rm ${script_path}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null

																	###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER##########################
																	#cp ${script_path}/${handover_account}_${trx_now}.trx ${user_path}/${handover_account}_${trx_now}.trx
																	#############################################################################

																	if [ ! $trx_path_output = $script_path ] && [ -d $trx_path_output ]
																	then
																		mv ${script_path}/${handover_account}_${trx_now}.trx ${trx_path_output}/${handover_account}_${trx_now}.trx
																	else
																		if [ "${trx_path_output}" = "" ]
																		then
																			rm ${script_path}/${handover_account}_${trx_now}.trx
																		fi
																	fi
																fi
																if [ $gui_mode = 1 ]
																then
																	if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
																	then
																		dialog_send_success_display=$(echo $dialog_send_success|sed "s#<file>#${trx_path_output}/${handover_account}_${trx_now}.trx#g")
																	else
																		dialog_send_success_display=$(echo $dialog_send_success|sed "s#<file>#/trx/${handover_account}.${trx_now}#g")
																	fi
																	dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_success_display" 0 0
																else
																	if [ $receipient_is_asset = 0 ]
																	then
																		if [ ! $small_trx = 255 ]
																		then
																			if [ ! "${cmd_path}" = "" ] && [ ! "${trx_path_output}" = "${cmd_path}" ]
																			then
																				mv ${trx_path_output}/${handover_account}_${trx_now}.trx ${cmd_path}/${handover_account}_${trx_now}.trx
																				echo "FILE:${cmd_path}/${handover_account}_${trx_now}.trx"
																			else
																				echo "FILE:${trx_path_output}/${handover_account}_${trx_now}.trx"
																			fi
																		fi
																	else
																		echo "FILE:trx/${handover_account}.${trx_now}"
																	fi
																	exit 0
																fi
															else
																rm ${trx_path_output}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null
																rm ${trx_path_output}/${handover_account}_${trx_now}.trx 2>/dev/null
																rm ${last_trx} 2>/dev/null
																if [ $gui_mode = 1 ]
																then
																	dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
																else
																	exit 1
																fi
															fi
														else
															rm ${script_path}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null
															rm ${last_trx} 2>/dev/null
															if [ $gui_mode = 1 ]
															then
																dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
															else
																exit 1
															fi
														fi
													else
														if [ $gui_mode = 1 ]
														then
															dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
														else
															exit 1
														fi
													fi
												else
													if [ $gui_mode = 1 ]
													then
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
													else
														exit 1
													fi
												fi
											else
												if [ $gui_mode = 1 ]
												then
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
												else
													exit 1
												fi
											fi
										fi
									fi
								fi
							else
								asset_found=1
							fi
						done
						rm ${user_path}/menu_assets.tmp 2>/dev/null
						;;
				"$dialog_receive")	file_found=0
							path_to_search=$trx_path_input
							while [ $file_found = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									file_path=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name $core_system_version" --output-fd 1 --fselect "$path_to_search" 20 48)
									rt_query=$?
								else
									rt_query=0
									file_path=$cmd_path
								fi
								if [ $rt_query = 0 ]
								then
									if [ ! -d $file_path ]
									then
										if [ -s $file_path ]
										then
											cd ${script_path}
											if [ $gui_mode = 1 ]
											then
												all_extract=0
											else
												all_extract=$extract_all
											fi

											###DECRYPT TRANSACTION FILE################################
											gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase ${handover_account} --pinentry-mode loopback --output ${file_path}.tmp --decrypt ${file_path} 1>/dev/null 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												###CHANGE TO ORIGINAL FILENAME#############################
												mv ${file_path}.tmp ${file_path}

												###CHECK ARCHIVE###########################################
												if [ $all_extract = 0 ]
												then
													check_archive $file_path 0
													rt_query=$?
												else
													check_archive $file_path 1
													rt_query=$?
												fi

												###UNPACK ARCHIVE##########################################
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
													tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --no-overwrite-dir --keep-directory-symlink --dereference --hard-dereference
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														if [ $all_extract = 0 ]
														then
															process_new_files 0
														else
															process_new_files 1
														fi
														set_permissions
														if [ $gui_mode = 1 ]
														then
															file_found=1
															action_done=1
															make_ledger=1
														else
															check_tsa
															check_keys
															check_assets
															check_trx
															get_dependencies
															ledger_mode=$?
															build_ledger $ledger_mode
															if [ $make_new_index = 1 ]
															then
																now_stamp=$(date +%s)
																make_signature "none" $now_stamp 1
																rt_query=$?
																if [ $rt_query -gt 0 ]
																then
																	exit 1
																else
																	exit 0
																fi
															else
																exit 1
															fi
														fi
													fi
												else
													if [ $gui_mode = 1 ]
													then
														dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
													else
														exit 1
													fi
												fi
											else
												if [ $gui_mode = 1 ]
												then
													dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
												else
													exit 1
												fi
												rm ${file_path}.tmp 2>/dev/null
											fi
										else
											if [ $gui_mode = 1 ]
											then
												dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
											else
												exit 1
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
											dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
										else
											exit 1
										fi
									fi
								else
									file_found=1
								fi
							done
							;;
				"$dialog_sync")	if [ $gui_mode = 1 ]
						then
							dialog --yes-label "$dialog_sync_read" --no-label "$dialog_sync_create" --title "$dialog_sync" --backtitle "$core_system_name $core_system_version" --yesno "$dialog_sync_io" 0 0
							rt_query=$?
						else
							case $cmd_action in
								"create_sync")	rt_query=1
										;;
								"read_sync")	rt_query=0
										;;
								*)		exit 1
										;;
							esac
						fi
						if [ $rt_query = 0 ]
						then
							file_found=0
							path_to_search=$sync_path_input
	      				  		while [ $file_found = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									file_path=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name $core_system_version" --output-fd 1 --fselect "$path_to_search" 20 48)
 						       			rt_query=$?
								else
									rt_query=0
									file_path=$cmd_path
								fi
								if [ $rt_query = 0 ]
								then
									if [ ! -d $file_path ]
		  							then
										if [ -s $file_path ]
										then
											cd ${script_path}
											if [ $gui_mode = 1 ]
											then
					 			       				dialog --yes-label "$dialog_sync_add_yes" --no-label "$dialog_sync_add_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --yesno "$dialog_sync_add" 0 0
												all_extract=$?
											else
												case $cmd_type in
													"partial")	all_extract=0
															;;
													"full")		all_extract=1
															;;
													*)		exit 1
															;;
												esac
											fi
											if [ ! $all_extract = 255 ]
											then
												if [ $all_extract = 0 ]
												then
													check_archive $file_path 0
													rt_query=$?
												else
													check_archive $file_path 1
													rt_query=$?
												fi
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
								       			 		tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --no-overwrite-dir --keep-directory-symlink --dereference --hard-dereference
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														if [ $all_extract = 0 ]
														then
															process_new_files 0
														else
															process_new_files 1
														fi
														set_permissions
														if [ $gui_mode = 1 ]
														then
															file_found=1
															action_done=1
															make_ledger=1
														else
															check_tsa
															check_keys
															check_assets
															check_trx
															get_dependencies
															ledger_mode=$?
															build_ledger $ledger_mode
															if [ $make_new_index = 1 ]
															then
																now_stamp=$(date +%s)
																make_signature "none" $now_stamp 1
																rt_query=$?
																if [ $rt_query -gt 0 ]
																then
																	exit 1
																else
																	exit 0
																fi
															else
																exit 0
															fi
														fi
													fi
												else
													if [ $gui_mode = 1 ]
													then
														dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
													else
														exit 1
													fi
												fi
											else
												file_found=1
											fi
										else
											if [ $gui_mode = 1 ]
											then
												dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
    												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
											else
												exit 1
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
			       								dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
										else
											exit 1
										fi
									fi
			       					else
			      			 			file_found=1
			       					fi
							done
						else
							if [ ! $rt_query = 255 ]
							then
								###GROUP COMMANDS TO OPEN FILE ONLY ONCE###################
								{
									if [ $gui_mode = 0 ] && [ $cmd_type = "partial" ]
									then
										###WRITE ASSETS TO FILE LIST#################
										awk '{print "assets/" $1}' ${user_path}/all_assets.dat

										###WRITE ACCOUNTS TO FILE LIST###############
										while read line
										do
											echo "keys/${line}"
											for tsa_file in $(ls -1 ${script_path}/proofs/${line}/*.ts*)
											do
												file=$(basename $tsa_file)
												echo "proofs/${line}/${file}"
											done
											if [ -s ${script_path}/proofs/${line}/${line}.txt ]
											then
												echo "proofs/${line}/${line}.txt"

											fi
										done <${user_path}/depend_accounts.dat

										###WRITE TRX TO FILE LIST####################
										awk '{print "trx/" $1}' ${user_path}/depend_trx.dat
									else
										###GET ASSETS################################################################
										awk '{print "assets/" $1}' ${user_path}/all_assets.dat

										###GET KEYS AND PROOFS#######################################################
										while read line
										do
											echo "keys/${line}"
											for tsa_file in $(ls -1 ${script_path}/proofs/${line}/*.ts*)
											do
												file=$(basename $tsa_file)
												echo "proofs/${line}/${file}"
											done
											if [ -s ${script_path}/proofs/${line}/${line}.txt ]
											then
												echo "proofs/${line}/${line}.txt"
											fi
										done <${user_path}/all_accounts.dat

										###GET TRX###################################################################
										awk '{print "trx/" $1}' ${user_path}/all_trx.dat
									fi
								} >${user_path}/files_list.tmp

								###GET CURRENT TIMESTAMP#################################
								now_stamp=$(date +%s)

								###SWITCH TO SCRIPT PATH AND CREATE TAR-BALL#############
								cd ${script_path}/
								tar -czf ${handover_account}_${now_stamp}.sync -T ${user_path}/files_list.tmp --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									rm ${user_path}/files_list.tmp 2>/dev/null
									###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER################################
									#cp ${script_path}/${handover_account}_${now_stamp}.sync ${user_path}/${handover_account}_${now_stamp}.sync
									###################################################################################
									if [ ! $sync_path_output = $script_path ]
									then
										mv ${script_path}/${handover_account}_${now_stamp}.sync ${sync_path_output}/${handover_account}_${now_stamp}.sync
									fi
									if [ $gui_mode = 1 ]
									then
										dialog_sync_create_success_display=$(echo $dialog_sync_create_success|sed "s#<file>#${sync_path_output}/${handover_account}_${now_stamp}.sync#g")
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_create_success_display" 0 0
									else
										if [ ! "${cmd_path}" = "" ] && [ ! "${sync_path_output}" = "${cmd_path}" ]
										then
											mv ${sync_path_output}/${handover_account}_${now_stamp}.sync ${cmd_path}/${handover_account}_${now_stamp}.sync
											echo "FILE:${cmd_path}/${handover_account}_${now_stamp}.sync"
										else
											echo "FILE:${sync_path_output}/${handover_account}_${now_stamp}.sync"
										fi
										exit 0
									fi
		       						else
									rm ${handover_account}_${now_stamp}.sync 2>/dev/null
									dialog_sync_create_fail_display=$(echo $dialog_sync_create_fail|sed "s#<file>#${script_path}/${handover_account}_${now_stamp}.sync#g")
									dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_create_fail_display" 0 0
								fi
							fi
						fi
						;;
				"$dialog_uca")	session_key=$(date -u +%Y%m%d)
						if [ $gui_mode = 1 ]
						then
							if [ $auto_uca_start = 0 ]
							then
								uca_trigger=1
								auto_uca_start=1
							fi
							action_done=1
							make_ledger=1
						else
							if [ $cmd_action = "sync_uca" ]
							then
								request_uca
								check_tsa
								check_keys
								check_assets
								check_trx
								get_dependencies
								ledger_mode=$?
								build_ledger $ledger_mode
								if [ $make_new_index = 1 ]
								then
									now_stamp=$(date +%s)
									make_signature "none" $now_stamp 1
								fi
								send_uca
								exit 0
							fi
						fi
						;;
				"$dialog_browser")	quit_menu=0
							while [ $quit_menu = 0 ]
							do
								###BROWSER OVERVIEW######################################
								browse_type=$(dialog --cancel-label "$dialog_cancel" --title "$dialog_browser" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_select" 0 0 0 "$dialog_assets" "$dialog_users" "$dialog_trx")
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									case $browse_type in
										"$dialog_assets")	quit_asset_menu=0
													while [ $quit_asset_menu = 0 ]
													do
														###ASSET OVERVIEW########################################
														asset=$(dialog --ok-label "$dialog_show" --extra-button --extra-label "$dialog_add" --cancel-label "$dialog_cancel" --title "$dialog_browser : $dialog_assets" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/all_assets.dat)
														rt_query=$?
														if [ $rt_query = 0 ] || [ $rt_query = 3 ]
														then
															if [ $rt_query = 0 ]
															then
																###DISPLAY DETAILED ASSET INFORMATION############)
																dialog --exit-label "$dialog_main_back" --title "$dialog_assets : $asset" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/assets/${asset}" 0 0
															else
																asset_name=""
																quit_asset_name=0
																while [ $quit_asset_name = 0 ]
																do
																	###ASK FOR A NAME################################
																	asset_name=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_browser : $dialog_assets : $dialog_add" --backtitle "$core_system_name $core_system_version" --max-input 10 --output-fd 1 --inputbox "$dialog_name" 0 0 "${asset_name}")
																	rt_query=$?
																	if [ $rt_query = 0 ]
																	then
																		is_alnum=$(echo "${asset_name}"|grep -c '[^[:alnum:]]')
																		if [ $is_alnum = 0 ]
																		then
																			###ASK FOR A DESCRIPTION#########################
																			touch ${user_path}/asset_description_blank.tmp
																			dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_asset_description" --backtitle "$core_system_name $core_system_version" --editbox ${user_path}/asset_description_blank.tmp 20 80 2>${user_path}/asset_description.tmp
																			rt_query=$?
																			if [ $rt_query = 0 ]
																			then
																				asset_description=$(cat ${user_path}/asset_description.tmp|sed 's/\"/\\"/g')
																				rm ${user_path}/asset_description.tmp
																				
																				###ASK IF FUNGIBLE OR NOT########################
																				dialog --yes-label "NON-FUNGIBLE" --no-label "FUNGIBLE" --help-button --help-label "$dialog_cancel" --title "$dialog_add" --backtitle "$core_system_name $core_system_version" --yesno "$dialog_asset_type" 0 0
																				fungible=$?
																				if [ $fungible = 0 ] || [ $fungible = 1 ]
																				then
																					if [ $fungible = 0 ]
																					then
																						dialog_asset_add_value=$dialog_asset_quantity
																					else
																						dialog_asset_add_value=$dialog_asset_price
																					fi
																					
																					quit_asset_value=0
																					while [ $quit_asset_value = 0 ]
																					do
																						###GET QUANTITY OR PRICE#########################
																						asset_value=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_add" --backtitle "$core_system_name $core_system_version" --max-input 20 --output-fd 1 --inputbox "$dialog_asset_add_value" 0 0 "")
																						rt_query=$?
																						if [ $rt_query = 0 ]
																						then
																							asset_value_alnum=$(echo $asset_value|grep -c '[^0-9.,]')
																							if [ $asset_value_alnum = 0 ] 
																							then
																								asset_value_formatted=$(echo $asset_value|sed -e 's/,/./g' -e 's/ //g')
																								value_mod=$(echo "${asset_value_formatted} % 0.000000001"|bc)
																								value_mod=$(echo "${value_mod} > 0"|bc)
																								if [ $value_mod = 0 ]
																								then
																									asset_value_formatted=$(echo "scale=9; ${asset_value_formatted} / 1"|bc|sed 's/^\./0./g')
																									is_amount_big_enough=$(echo "${asset_value_formatted} >= 0.000000001"|bc)
																									if [ $is_amount_big_enough = 1 ]
																									then
																										if [ $rt_query = 0 ]
																										then
																											###WRITE ASSET###########################
																											asset_stamp=$(date +%s)
																											{
																											echo "asset_name='${asset_name}'"
																											echo "asset_fungible=${fungible}"
																											if [ $fungible = 0 ]
																											then
																												echo "asset_quantity='${asset_value_formatted}'"
																												echo "asset_owner='${handover_account}'"
																											else
																												echo "asset_price='${asset_value_formatted}'"
																											fi
																											echo "asset_description='${asset_description}'"
																											} >${user_path}/${asset_name}.${asset_stamp}
																											#########################################
																											
																											###CONFIRM###############################
																											dialog --ok-label "$dialog_add" --extra-button --extra-label "$dialog_cancel" --title "${dialog_add}?" --backtitle "$core_system_name $core_system_version" --textbox "${user_path}/${asset_name}.${asset_stamp}" 0 0
																											rt_query=$?
																											if [ $rt_query = 0 ]
																											then
																												###COPY INTO ASSETS FOLDER###############
																												mv ${user_path}/${asset_name}.${asset_stamp} ${script_path}/assets/${asset_name}.${asset_stamp}
																												
																												###DISPLAY SUCCESS MESSAGE###############
																												dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_asset_add_successfull" 0 0
																												
																												###CHECK ASSETS##########################
																												check_assets
																												if [ $fungible = 0 ]
																												then
																													###CREATE LEDGER ENTRY###################
																													last_ledger=$(ls -1 ${user_path}/|grep "ledger.dat"|tail -1)
																													echo "${asset_name}:${handover_account}=${asset_quantity}" >>${user_path}/${last_ledger}
																												fi
																											fi
																											quit_asset_value=1
																											quit_asset_name=1
																										fi
																									else
																										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_amount_not_big_enough" 0 0
																									fi
																								else
																									dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_amount_not_big_enough" 0 0
																								fi
																							else
																								dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail_amount" 0 0
																							fi
																						else
																							quit_asset_value=1
																						fi
																					done
																				fi
																			fi
																			rm ${user_path}/asset_description_blank.tmp
																		else
																			dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg3" 0 0
																		fi
																	else
																		quit_asset_name=1
																	fi
																done
															fi
														else
															quit_asset_menu=1
														fi
													done
													;;
										"$dialog_users")	quit_user_menu=0
													while [ $quit_user_menu = 0 ]
													do
														###USERS OVERVIEW########################################
														user=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --title "$dialog_browser : $dialog_users" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/depend_accounts.dat)
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															quit_trx_menu=0
															while [ $quit_trx_menu = 0 ]
															do
																###USERS TRX OVERVIEW####################################
																grep "${user}" ${user_path}/depend_trx.dat >${user_path}/dialog_browser_trx.tmp
																if [ ! -s ${user_path}/dialog_browser_trx.tmp ]
																then
																	echo "0" >${user_path}/dialog_browser_trx.tmp
																fi
																selected_trx=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --title "$dialog_browser : $dialog_trx" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$user:" 0 0 0 --file ${user_path}/dialog_browser_trx.tmp)
																rt_query=$?
																if [ $rt_query = 0 ] && [ ! "${selected_trx}" = "0" ]
																then
																	dialog --exit-label "$dialog_main_back" --title "$dialog_browser : $dialog_trx : $selected_trx" --backtitle "$core_system_name $core_system_version" --textbox "${script_path}/trx/$selected_trx" 0 0
																else
																	quit_trx_menu=1	
																fi
																rm ${user_path}/dialog_browser_trx.tmp
															done
														else
															quit_user_menu=1
														fi
													done
													;;
										"$dialog_trx")		###TRX OVERVIEW##########################################
													if [ ! -s ${user_path}/depend_trx.dat ]
													then
														echo "0" >${user_path}/dialog_browser_trx.tmp
													else
														sort -r -t . -k2 ${user_path}/depend_trx.dat >${user_path}/dialog_browser_trx.tmp
													fi
													selected_trx=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --title "$dialog_browser : $dialog_trx" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/dialog_browser_trx.tmp)
													rt_query=$?
													if [ $rt_query = 0 ] && [ ! "${selected_trx}" = "0" ]
													then
														dialog --exit-label "$dialog_main_back" --title "$dialog_browser : $dialog_trx : $selected_trx" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/trx/${selected_trx}" 0 0
													fi
													rm ${user_path}/dialog_browser_trx.tmp
													;;
										*)	quit_menu=1
											;;
									esac
								else
									quit_menu=1
								fi
							done
							;;
				"$dialog_history")	rm ${user_path}/*.tmp 2>/dev/null
							touch ${user_path}/my_trx.tmp
							touch ${user_path}/my_trx_sorted.tmp
							cd ${script_path}/trx
							grep -l ":${handover_account}" * >${user_path}/my_trx.tmp 2>/dev/null
							cd ${script_path}
							sort -r -t . -k2 ${user_path}/my_trx.tmp >${user_path}/my_trx_sorted.tmp
							mv ${user_path}/my_trx_sorted.tmp ${user_path}/my_trx.tmp
							no_trx=$(wc -l <${user_path}/my_trx.tmp)
							if [ $no_trx -gt 0 ]
							then
								while read line
								do
									trx_file=${script_path}/trx/${line}
									sender=$(awk -F: '/:SNDR:/{print $3}' $trx_file)
									receiver=$(awk -F: '/:RCVR:/{print $3}' $trx_file)
									trx_date_tmp=${line#*.}
									trx_date=$(date +'%F|%H:%M:%S' --date=@${trx_date_tmp})
			      						trx_amount=$(awk -F: '/:AMNT:/{print $3}' $trx_file)
									trx_asset=$(awk -F: '/:ASST:/{print $3}' $trx_file)
									trx_hash=$(sha256sum $trx_file)
									trx_hash=${trx_hash%% *}
									trx_confirmations=$(grep -s -l "trx/${line} ${trx_hash}" proofs/*/*.txt|grep -c -v "${sender}\|${receiver}")
									if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
									then
										trx_signed=$(grep -c "${line}" ${script_path}/proofs/${sender}/${sender}.txt)
									else
										trx_signed=0
									fi
									if [ $trx_signed -gt 0 ]
									then
										if [ $trx_confirmations -ge $confirmations_from_users ]
										then
											trx_blacklisted=$(grep -c "${line}" ${user_path}/blacklisted_trx.dat)
											sender_blacklisted=$(grep -c "${sender}" ${user_path}/blacklisted_accounts.dat)
											receiver_blacklisted=$(grep -c "${receiver}" ${user_path}/blacklisted_accounts.dat)
											if [ $trx_blacklisted = 0 ] && [ $sender_blacklisted = 0 ] && [ $receiver_blacklisted = 0 ]
											then
												trx_color="\Z2"
											else
												trx_color="\Z1"
											fi
										else
											trx_color="\Z0"
										fi
									else
										trx_color="\Z1"
									fi
									if [ $sender = $handover_account ]
									then
										echo "${trx_date}|-${trx_amount}|${trx_asset} \Zb${trx_color}$dialog_history_ack_snd\ZB" >>${user_path}/history_list.tmp
									fi
									if [ $receiver = $handover_account ]
									then
										echo "${trx_date}|+${trx_amount}|${trx_asset} \Zb${trx_color}$dialog_history_ack_rcv\ZB" >>${user_path}/history_list.tmp
									fi
								done <${user_path}/my_trx.tmp
							else
								printf "%s" "${dialog_history_noresult}" >${user_path}/history_list.tmp
							fi
							menu_item_selected=$(head -1 ${user_path}/history_list.tmp)
							menu_item_selected=${menu_item_selected%% *}
							overview_quit=0
							while [ $overview_quit = 0 ]
							do
								decision=$(dialog --colors --ok-label "$dialog_open" --cancel-label "$dialog_main_back" --title "$dialog_history" --backtitle "$core_system_name $core_system_version" --output-fd 1 --default-item "${menu_item_selected}" --menu "$dialog_history_menu" 0 0 0 --file ${user_path}/history_list.tmp)
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									menu_item_selected=$decision
									dialog_history_noresults=${dialog_history_noresult%% *}
									if [ ! $decision = $dialog_history_noresults ]
									then
										trx_date_extracted=${decision%%|*}
										trx_time_extracted=${decision#*|*}
										trx_time_extracted=${trx_time_extracted%%|*}
										trx_date=$(date +%s --date="${trx_date_extracted} ${trx_time_extracted}")
										trx_file=$(grep "${trx_date}" ${user_path}/my_trx.tmp)
										trx_amount=$(echo $decision|cut -d '|' -f3|sed -e 's/+//g' -e 's/-//g')
										trx_hash=$(sha256sum ${script_path}/trx/${trx_file})
										trx_hash=${trx_hash%% *}
										trx_file_path="${script_path}/trx/${trx_file}"
										sender=$(awk -F: '/:SNDR:/{print $3}' $trx_file_path)
										receiver=$(awk -F: '/:RCVR:/{print $3}' $trx_file_path)
										purpose_there=0
										purpose_dialog_string="-"
										if [ "${receiver}" = "${handover_account}" ]
										then
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
											} >${user_path}/history_purpose_encrypted.tmp
											gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase "${login_password}" --pinentry-mode loopback --output ${user_path}/history_purpose_decrypted.tmp --decrypt ${user_path}/history_purpose_encrypted.tmp 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												if [ -s ${user_path}/history_purpose_decrypted.tmp ]
												then
													###CHECK IF FILE CONTAINS TEXT OR ELSE######################################
													is_text=$(file ${user_path}/history_purpose_decrypted.tmp|grep -c -v "text")
													if [ $is_text = 0 ]
													then
														purpose_there=1
														purpose_dialog_string="[...]"
													else
														purpose_there=2
														purpose_dialog_string="[data]"
													fi
												fi
											fi
										fi
										rm ${user_path}/history_purpose_encrypted.tmp 2>/dev/null
										trx_status=""
										if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
										then
											trx_signed=$(grep -c "trx/${trx_file} ${trx_hash}" ${script_path}/proofs/${sender}/${sender}.txt)
										else
											trx_signed=0
										fi
										if [ $trx_signed = 0 ]
										then
											trx_status="TRX_IGNORED "
										fi
										trx_blacklisted=$(grep -c "${trx_file}" ${user_path}/blacklisted_trx.dat)
										if [ $trx_blacklisted = 1 ]
										then
											trx_status="${trx_status}TRX_BLACKLISTED "
										fi
										sender_blacklisted=$(grep -c "${sender}" ${user_path}/blacklisted_accounts.dat)
										if [ $sender_blacklisted = 1 ]
										then
										trx_status="${trx_status}SDR_BLACKLISTED "
										fi
										receiver_blacklisted=$(grep -c "${receiver}" ${user_path}/blacklisted_accounts.dat)
										if [ $receiver_blacklisted = 1 ]
										then
											trx_status="${trx_status}RCV_BLACKLISTED "
										fi
										if [ $trx_signed = 1 ] && [ $trx_blacklisted = 0 ] && [ $sender_blacklisted = 0 ] && [ $receiver_blacklisted ]
										then
											trx_status="OK"
										fi
										user_total_depend=$(cat ${user_path}/depend_accounts.dat|grep -c -v "${sender}\|${receiver}")
										user_total_all=$(cat ${user_path}/all_accounts.dat|grep -c -v "${sender}\|${receiver}")
										trx_confirmations_depend=$(grep -s -l "trx/${trx_file} ${trx_hash}" proofs/*/*.txt|grep -f ${user_path}/depend_accounts.dat|grep -c -v "${sender}\|${receiver}")
										trx_confirmations_all=$(grep -s -l "trx/${trx_file} ${trx_hash}" proofs/*/*.txt|grep -c -v "${sender}\|${receiver}")
										trx_confirmations="${trx_confirmations_all}  (${trx_confirmations_depend}\/${user_total_depend}\/${trx_confirmations_all}\/${user_total_all})"
										currency_symbol=${decision#*|*|*|*}
										if [ $sender = $handover_account ]
										then
											dialog_history_show_trx_out_display=$(printf "%s" "$dialog_history_show_trx_out"|sed -e "s/<receiver>/${receiver}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<order_purpose>/${purpose_dialog_string}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g")
											dialog_history_show_trx=$dialog_history_show_trx_out_display
										else
											dialog_history_show_trx_in_display=$(printf "%s" "$dialog_history_show_trx_in"|sed -e "s/<sender>/${sender}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<order_purpose>/${purpose_dialog_string}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g")
											dialog_history_show_trx=$dialog_history_show_trx_in_display
										fi
										if [ $purpose_there = 1 ] || [ $purpose_there = 2 ]
										then
											dialog --help-button --help-label "$purpose_dialog_string" --title "$dialog_history_show" --backtitle "$core_system_name $core_system_version" --msgbox "${dialog_history_show_trx}" 0 0
											rt_query=$?
											if [ $rt_query = 2 ]
											then
												open_write_dialog=0
												if [ $purpose_there = 1 ]
												then
													dialog --cancel-label "[...]" --title "$trx_file" --backtitle "$core_system_name $core_system_version" --editbox ${user_path}/history_purpose_decrypted.tmp 0 0 2>/dev/null
													if [ $rt_query = 2 ]
													then
														open_write_dialog=1
													fi
												fi
												if [ $purpose_there = 2 ] || [ $open_write_dialog = 1 ]
												then
													path_to_search=$script_path
													quit_file_path=0
													while [ $quit_file_path = 0 ]
													do
														###LET USER SELECT A PATH################################################
														file_path=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_choose" --backtitle "$core_system_name $core_system_version" --output-fd 1 --fselect "$path_to_search" 20 48)
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															###CHECK IF ITS A DIRECTORY##############################################
															if [ -d "${file_path}" ]
															then
																cp ${user_path}/history_purpose_decrypted.tmp ${file_path}/decrypted_$(date +%s)_${trx_file}
															else
																###CHECK IF ITS A FILE AND IF ITS EXIST##################################
																if [ ! -e "${file_path}" ]
																then
																	###COPY THE FILE TO USER SELECTED PATH###################################
																	cp ${user_path}/history_purpose_decrypted.tmp ${file_path}
																	quit_file_path=1
																fi
															fi
														else
															quit_file_path=1
														fi
													done
												fi
											fi
										else
											dialog --title "$dialog_history_show" --backtitle "$core_system_name $core_system_version" --msgbox "${dialog_history_show_trx}" 0 0
										fi
										rm ${user_path}/history_purpose_decrypted.tmp 2>/dev/null
									else
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "${dialog_history_fail}" 0 0
									fi
								else
									overview_quit=1
									rm ${user_path}/history_list.tmp 2>/dev/null
								fi
							done
							rm ${user_path}/*.tmp 2>/dev/null
							;;
				"$dialog_stats")	###EXTRACT STATISTICS FOR TOTAL################
							total_assets=$(wc -l <${user_path}/all_assets.dat)
							total_keys=$(wc -l <${user_path}/all_accounts.dat)
							total_trx=$(wc -l <${user_path}/all_trx.dat)
							total_user_blacklisted=$(wc -l <${user_path}/blacklisted_accounts.dat)
							total_trx_blacklisted=$(wc -l <${user_path}/blacklisted_trx.dat)
							###############################################

							if [ $gui_mode = 1 ]
							then
								###IF GUI MODE DISPLAY STATISTICS##############
								dialog_statistic_display=$(echo $dialog_statistic|sed -e "s/<total_keys>/${total_keys}/g" -e "s/<total_assets>/${total_assets}/g" -e "s/<total_trx>/${total_trx}/g" -e "s/<total_user_blacklisted>/${total_user_blacklisted}/g" -e "s/<total_trx_blacklisted>/${total_trx_blacklisted}/g")
								dialog --title "$dialog_stats" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_statistic_display" 0 0
							else
								###IF CMD MODE DISPLAY STATISTICS##############
								echo "ASSETS_TOTAL:${total_assets}"
								echo "KEYS_TOTAL:${total_keys}"
								echo "TRX_TOTAL:${total_trx}"
								echo "BLACKLISTED_USERS_TOTAL:${total_user_blacklisted}"
								echo "BLACKLISTED_TRX_TOTAL:${total_trx_blacklisted}"
								exit 0
							fi
							;;
				"$dialog_logout")	###LOG OUT USER###########
							user_logged_in=0
							;;
			esac
		fi
	fi
done

