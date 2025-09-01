#!/bin/sh
login_account(){
		login_name=$1
		login_pin=$2
		login_password=$3
		account_found=0
		handover_account=""

		###IF CMD SENDER IS SET HAND OVER############################
		if [ -n "${cmd_sender}" ]
		then
			key_login=${cmd_sender}
		fi

		###FOR EACH SECRET###########################################
		for secret_file in $(ls -1 ${script_path}/control/keys/|grep "${cmd_sender}.sct")
		do
			###GET ADDRESS OF SECRET#####################################
			key_file=${secret_file%%.*}

			###IF CMD_SENDER NOT SET#####################################
			if [ -z "${cmd_sender}" ]
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
				echo "${login_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --local-user ${user} -r ${user} --passphrase-fd 0 --pinentry-mode loopback --encrypt --sign ${script_path}/account_${my_pid}.tmp 1>/dev/null 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###WRITE ACCOUNTS.DB ENTRY IF NECESSARY######################
					if [ -z "${cmd_sender}" ]
					then
						name_hash=$(echo "${login_name}"|sha224sum)
						name_hash=${name_hash%% *}
						if [ $(grep -c "${name_hash}" ${script_path}/control/accounts.db) = 0 ]
						then
							echo "${name_hash}" >>${script_path}/control/accounts.db
						fi
					fi

					###REMOVE ENCRYPTION SOURCE FILE#############################
					rm ${script_path}/account_${my_pid}.tmp

					####TEST KEY BY DECRYPTING THE MESSAGE#######################
					echo "${login_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --output ${script_path}/account_${my_pid}.tmp --decrypt ${script_path}/account_${my_pid}.tmp.gpg 1>/dev/null 2>/dev/null
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

				####DISPLAY WELCOME MESSAGE##################################
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
				exit 2
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
		echo "${create_password}"|gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --no-default-keyring --keyring=${script_path}/control/keyring.file --passphrase-fd 0 --pinentry-mode loopback --quick-gen-key ${create_name_hashed} rsa4096 sign,auth,encr none 1>/dev/null 2>/dev/null
		rt_query=$?
		if [ $rt_query = 0 ]
		then
			if [ $gui_mode = 1 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR############################
				echo "33"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create2" 0 0 0
			fi

			###CREATE USER DIRECTORY AND SET USER_PATH###########
			mkdir ${script_path}/proofs/${create_name_hashed}
			mkdir ${script_path}/userdata/${create_name_hashed}
			mkdir ${script_path}/userdata/${create_name_hashed}/temp
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/assets
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/keys
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/proofs
			mkdir ${script_path}/userdata/${create_name_hashed}/temp/trx
			user_path="${script_path}/userdata/${create_name_hashed}"

			###EXPORT PUBLIC KEY#########################################
			key_remove=1
			echo "${create_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc --passphrase-fd 0 --pinentry-mode loopback --export ${create_name_hashed}
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				if [ $gui_mode = 1 ]
				then
					###DISPLAY PROGRESS ON STATUS BAR############################
					echo "66"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create3" 0 0 0
				fi

				###EXPORT PRIVATE KEY########################################
				echo "${create_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_priv.asc --pinentry-mode loopback --passphrase-fd 0 --export-secret-keys ${create_name_hashed}
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###STEP INTO USER DIRECTORY##################################
					cd ${user_path} || exit 3

					###WRITE KEY DATA TO FILE####################################
					key_stamp=$(gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys 2>/dev/null|grep "${create_name_hashed}"|cut -d ':' -f6) || rt_query=1
					if [ $rt_query = 0 ]
					then
						###CREATE TSA QUERY FILE#####################################
						openssl ts -query -data ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc -no_nonce -sha512 -out ${user_path}/${create_name_hashed}.tsq 1>/dev/null 2>/dev/null
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###CREATE LIST OF ALL TSAS AND SET GREP PATTERN##############
							ls -1 ${script_path}/certs >${user_path}/tsa_list.tmp
							tsa_pattern=$(grep "${default_tsa}" ${user_path}/tsa_list.tmp)

							###AS LONG AS NOT MINIMUM SIGNED ONCE########################
							is_stamped=0
							while [ $is_stamped = 0 ]
							do
								###FOR EACH TSA WITH DEFAULT TSA FIRST#######################
								for tsa_service in $(echo "${tsa_pattern}"|sort - ${user_path}/tsa_list.tmp|uniq -d)
								do
									###COPY QUERYFILE############################################
									cp ${user_path}/${create_name_hashed}.tsq ${user_path}/${tsa_service}.tsq

									###GET TSA CONNECTION STRING#################################
									tsa_config=$(grep "${tsa_service}" ${script_path}/control/tsa.conf)
									tsa_cert_url=$(echo "${tsa_config}"|cut -d ',' -f2)
									tsa_cert_file=$(basename $tsa_cert_url)
									tsa_cacert_url=$(echo "${tsa_config}"|cut -d ',' -f3)
									tsa_cacert_file=$(basename $tsa_cacert_url)
									tsa_connect_string=$(echo "${tsa_config}"|cut -d ',' -f5)

									retry_counter=0
									while [ $retry_counter -le $retry_limit ]
									do
										###SENT QUERY TO TSA#########################################
										curl --silent -H "Content-Type: application/timestamp-query" --data-binary @${tsa_service}.tsq ${tsa_connect_string} >${user_path}/${tsa_service}.tsr
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											###VERIFY TSA RESPONSE###################################
											openssl ts -verify -queryfile ${user_path}/${tsa_service}.tsq -in ${user_path}/${tsa_service}.tsr -CAfile ${script_path}/certs/${tsa_service}/${tsa_cacert_file} -untrusted ${script_path}/certs/${tsa_service}/${tsa_cert_file} 1>/dev/null 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												###WRITE OUTPUT OF RESPONSE TO FILE######################
												openssl ts -reply -in ${user_path}/${tsa_service}.tsr -text >${user_path}/tsa_check.tmp 2>/dev/null
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													###GET FILE STAMP########################################
													file_stamp=$(date -u +%s --date="$(grep "Time stamp" ${user_path}/tsa_check.tmp|cut -c 13-37)")

													###CHECK DIFFERENCE######################################
													stamp_diff=$(( file_stamp - key_stamp ))
													if [ $stamp_diff -lt 120 ]
													then
														###COPY TSA FILES###################################################
														cp ${user_path}/${tsa_service}.tsq ${script_path}/proofs/${create_name_hashed}/${tsa_service}.tsq
														cp ${user_path}/${tsa_service}.tsr ${script_path}/proofs/${create_name_hashed}/${tsa_service}.tsr
														is_stamped=1
														break
													else
														rt_query=1
													fi
												fi
											fi
										fi
										if [ $rt_query = 1 ]
										then
											###IF FAILED RETRY#########################
											retry_counter=$(( retry_counter + 1 ))
											if [ $retry_counter -le $retry_limit ]
											then
												sleep $retry_wait_seconds
											fi
										else
											break
										fi
									done
								done
								###IF DEFAULT TSA WAS A DEFINED PATTERN BUT NOT AVAILABLE#####
								if [ $is_stamped = 0 ] && [ "${tsa_pattern}" = "${default_tsa}" ]
								then
									###ENHANCE PATTERN TO ALL TSAS EXCEPT DEFAULT#################
									tsa_pattern=$(grep -v "${default_tsa}" ${user_path}/tsa_list.tmp)
								else
									break
								fi
							done
							rm ${user_path}/tsa_check.tmp
							rm ${user_path}/tsa_list.tmp
							rm ${user_path}/${create_name_hashed}.tsq
						fi
					fi
				fi
			fi
		fi
		if [ $rt_query = 0 ]
		then
			###COPY EXPORTED PUB-KEY INTO KEYS-FOLDER###########################
			cp ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_pub.asc ${script_path}/keys/${create_name_hashed}

			###COPY EXPORTED PRIV-KEY INTO CONTROL-FOLDER#######################
			cp ${user_path}/${create_name_hashed}_${create_name}_${create_pin}_priv.asc ${script_path}/control/keys/${create_name_hashed}

			###WRITE SECRETS####################################################
			echo "${random_secret}" >${user_path}/${create_name_hashed}.sct
			echo "${verify_secret}" >${user_path}/${create_name_hashed}.scv

			###WRITE ENTRY INTO ACCOUNTS.DB#####################################
			name_hash=$(echo "${create_name}"|sha224sum)
			name_hash=${name_hash%% *}
			echo "${name_hash}" >>${script_path}/control/accounts.db

			###ONLY COPY RANDOM SECRET (VERIFY CAN BE RECALCULATED)#############
			cp ${user_path}/${create_name_hashed}.sct ${script_path}/control/keys/${create_name_hashed}.sct

			if [ $gui_mode = 1 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR###########################
				echo "100"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name $core_system_version" --gauge "$dialog_keys_create4" 0 0 0
				sleep 1
				clear

				###DISPLAY NOTIFICATION THAT EVERYTHING WAS FINE############
				dialog_keys_final_display=$(echo $dialog_keys_final|sed -e "s/<create_name>/${create_name}/g" -e "s/<create_name_hashed>/${create_name_hashed}/g" -e "s/<create_pin>/${create_pin}/g" -e "s/<file_stamp>/${file_stamp}/g")
				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_final_display" 0 0
				key_remove=0
			else
				echo "USER:${create_name}"
				echo "PIN:${create_pin}"
				echo "PASSWORD:>${create_password}<"
				echo "ADDRESS:${create_name_hashed}"
				echo "KEY_PUB:/keys/${create_name_hashed}"
				echo "KEY_PRV:/control/keys/${create_name_hashed}"
				echo "KEY_SECRET:/control/keys/${create_name_hashed}.sct"
				echo "KEY_VERIFY_SECRET:/userdata/${create_name_hashed}/${create_name_hashed}.scv"
				exit 0
			fi
		else
			if [ $key_remove = 1 ]
			then
				if [ -n "${create_name_hashed}" ]
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
					exit 4
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
			else
				###IF YES WRITE INDEX############################################
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

					###ADD TSA FILES#################################################
					for tsa_file in $(ls -1 ${script_path}/proofs/${key_file}/*.ts*)
					do
						file=$(basename ${tsa_file})
						file_hash=$(sha256sum ${script_path}/proofs/${key_file}/${file})
						file_hash=${file_hash%% *}
						echo "proofs/${key_file}/${file} ${file_hash}" >>${message_blank}
					done

					###ADD INDEX FILE IF EXISTING####################################
					if [ -f ${script_path}/proofs/${key_file}/${key_file}.txt ] && [ -s ${script_path}/proofs/${key_file}/${key_file}.txt ]
					then
						file_hash=$(sha256sum ${script_path}/proofs/${key_file}/${key_file}.txt)
						file_hash=${file_hash%% *}
						echo "proofs/${key_file}/${key_file}.txt ${file_hash}" >>${message_blank}
					fi
				done

				####WRITE TRX LIST TO INDEX FILE#################################
				cat ${user_path}/*_index_trx.dat >>${message_blank} 2>/dev/null
			fi

			###SIGN FILE#####################################################
			echo "${login_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --digest-algo SHA512 --local-user ${handover_account} --clearsign ${message_blank} 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				mv ${message_blank}.asc ${message}
			fi

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

		###IF INPUT LESS THAN 1 DISPLAY NOTIFICATION###########################
		if [ $length_counter -lt 1 ]
		then
			if [ $gui_mode = 1 ]
			then
				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg2" 0 0
				rt_query=1
			else
				exit 5
			fi
		fi

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
						exit 6
					fi
				fi
				;;
			1 )	###CHECK IF ONLY DIGITS ARE IN INPUT STRING############################
				string_check=$(echo "${input_string}"|grep -c '[^[:digit:]]')

				###IF DIGIT CHECK FAILS DISPLAY NOTIFICATION###########################
				if [ $string_check = 1 ]
				then
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_check_msg1" 0 0
						rt_query=1
					else
						exit 7
					fi
				fi
				;;
			*)	exit 8
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
		old_ledger_there=$(ls -1 ${user_path}/*_ledger.dat 2>/dev/null|wc -l)

		if [ $old_ledger_there -gt 0 ] && [ $new = 0 ]
		then
			###GET LATEST LEDGER AND EXTRACT DATE###############
			last_ledger=$(basename -a ${user_path}/*_ledger.dat|tail -1)
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

			###EMPTY INDEX FILE#################################
			rm ${user_path}/*_index_trx.dat 2>/dev/null

			###EMPTY IGNORE TRX#################################
			rm ${user_path}/ignored_trx.dat 2>/dev/null

			###CALCULATE DAY COUNTER############################
			date_stamp_last=$(date -u +%s --date="${start_date}")
			no_seconds_last=$(( date_stamp - date_stamp_last ))
			day_counter=$(( no_seconds_last / 86400 ))
		fi
		####################################################

		###SET FOCUS########################################
		focus=$(date -u +%Y%m%d --date=@${date_stamp})
		now_stamp=$(date +%s)

		###GET PREVIOUS DAY#################################
		previous_day=$(date +%Y%m%d --date="${focus} - 1 day")

		###CREATE LEDGER ENTRY FOR NON FUNGIBLE ASSET###############
		for asset in $(awk -F. -v date_stamp="${date_stamp}" '$2 < date_stamp' ${user_path}/all_assets.dat)
		do
			if [ ! "${asset}" = "${main_asset}" ] && [ -f ${script_path}/assets/${asset} ] && [ -s ${script_path}/assets/${asset} ]
			then
				asset_data=$(cat ${script_path}/assets/${asset})
				asset_fungible=$(echo "$asset_data"|grep "asset_fungible=")
				asset_fungible=${asset_fungible#*=}
				if [ $asset_fungible = 0 ]
				then
					asset_owner=$(echo "$asset_data"|grep "asset_owner="|sed "s/\"//g")
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

		if [ $focus -le $now ] && [ $gui_mode = 1 ]
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
				current_percent=$(echo "scale=10;${current_percent} + ${percent_per_day}"|bc)
				current_percent_display=$(echo "${current_percent} / 1"|bc)
			fi
			#################################################

			###CALCULATE CURRENT COINLOAD####################
			if [ $day_counter = 1 ]
			then
				coinload=$initial_coinload
			else
				coinload=1
			fi

			###MOVE FILENAMES TO NEXT DAY####################
			previous_day=$(date +%Y%m%d --date="${focus} - 1 day")
			cp ${user_path}/${previous_day}_ledger.dat ${user_path}/${focus}_ledger.dat

			###GRANT COINLOAD OF THAT DAY####################
			grep -v "${main_asset}" ${user_path}/all_assets.dat|grep -v -f - ${user_path}/${focus}_ledger.dat|LC_NUMERIC=C.utf-8 awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' >${user_path}/${focus}_ledger.tmp
			if [ -f ${user_path}/${focus}_ledger.tmp ] && [ -s ${user_path}/${focus}_ledger.tmp ]
			then
				grep -v "${main_asset}" ${user_path}/all_assets.dat|grep -f - ${user_path}/${focus}_ledger.dat >${user_path}/${focus}_ledger_others.tmp
				cat ${user_path}/${focus}_ledger.tmp ${user_path}/${focus}_ledger_others.tmp >${user_path}/${focus}_ledger.dat
				rm ${user_path}/${focus}_ledger_others.tmp
			fi
			rm ${user_path}/${focus}_ledger.tmp 2>/dev/null

			###GET DATESTAMP OF TOMORROW#####################
			date_stamp_tomorrow=$(( date_stamp + 86400 ))

			###GET LIST OF ACCOUNTS CREATED TODAY############
			grep -f ${user_path}/depend_accounts.dat ${user_path}/all_accounts_dates.dat|awk -F' ' -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 >= date_stamp && $2 < date_stamp_tomorrow {print $1}' >${user_path}/accounts.tmp

			###CREATE LEDGER ENTRY FOR THESE USERS###########
			awk -v main_asset="${main_asset}" '{print main_asset":"$1"=0"}' ${user_path}/accounts.tmp >>${user_path}/${focus}_ledger.dat
			rm ${user_path}/accounts.tmp 2>/dev/null

			###FOR EACH ASSET CREATED THAT DAY###############
			for asset in $(awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 >= date_stamp && $2 < date_stamp_tomorrow' ${user_path}/all_assets.dat)
			do
				###SET FULL PATH###########################################
				asset_full_path="${script_path}/assets/${asset}"

				###CREATE LEDGER ENTRY FOR NON FUNGIBLE ASSETS#############
				rt_query=0
				match=$(grep -s -c "asset_fungible=0" "${asset_full_path}") || rt_query=1
				if [ $rt_query = 0 ] && [ $match = 1 ]
				then
					asset_quantity=$(grep "asset_quantity=" "${asset_full_path}")
					asset_quantity=${asset_quantity#*=}
					asset_owner=$(grep "asset_owner=" "${asset_full_path}"|sed "s/\"//g")
					asset_owner=${asset_owner#*=}
					echo "${asset}:${asset_owner}=${asset_quantity}" >>${user_path}/${focus}_ledger.dat
				fi
				###CREATE LEDGER ENTRY FOR FUNGIBLE ASSETS#################
				match=$(grep -s -c "asset_fungible=1" "${asset_full_path}") || rt_query=1
				if [ $rt_query = 0 ] && [ $asset_fungible = 1 ]
				then
					###CREATE LEDGER ENTRY FOR FUNGIBLE ASSETS#################
					echo "${asset}"|awk -F. -v main_asset="${main_asset}" '{if ($1 != main_asset) print main_asset":"$1"."$2"=0"}' >>${user_path}/${focus}_ledger.dat
					echo "${asset}"|awk -F. -v main_asset="${main_asset}" '{if ($1 != main_asset) print $1"."$2":"main_asset"=0"}' >>${user_path}/${focus}_ledger.dat
				fi
			done

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
				if [ -f ${script_path}/proofs/${trx_sender}/${trx_sender}.txt ] && [ -s ${script_path}/proofs/${trx_sender}/${trx_sender}.txt ] || [ "${trx_sender}" = "${handover_account}" ]
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

							###CHECK IF BALANCE IS OK#####################################
							if [ $enough_balance = 1 ]
							then
								####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)#############
								echo "${trx_path} ${trx_hash}" >>${user_path}/${focus}_index_trx.dat
								##############################################################

								###SET BALANCE FOR SENDER#####################################
								account_new_balance=$account_check_balance
								sed -i "s/${trx_asset}:${trx_sender}=${account_balance}/${trx_asset}:${trx_sender}=${account_new_balance}/g" ${user_path}/${focus}_ledger.dat
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
								if [ $receiver_in_ledger = 1 ]
								then
									###GET CONFIRMATIONS##########################################
									total_confirmations=$(grep -s -l "trx/${trx_filename} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${trx_sender}\|${trx_receiver}")

									###ADD 1 CONFIRMATION FOR OWN#################################
									if [ ! "${trx_sender}" = "${handover_account}" ] && [ ! "${trx_receiver}" = "${handover_account}" ]
									then
										total_confirmations=$(( total_confirmations + 1 ))
									fi

									###CHECK CONFIRMATIONS########################################
									if [ $total_confirmations -ge $confirmations_from_users ]
									then
										###SET BALANCE FOR RECEIVER###################################
										receiver_old_balance=$(grep "${trx_asset}:${trx_receiver}" ${user_path}/${focus}_ledger.dat)
										receiver_old_balance=${receiver_old_balance#*=}
										receiver_new_balance=$(echo "${receiver_old_balance} + ${trx_amount}"|bc|sed 's/^\./0./g')
										sed -i "s/${trx_asset}:${trx_receiver}=${receiver_old_balance}/${trx_asset}:${trx_receiver}=${receiver_new_balance}/g" ${user_path}/${focus}_ledger.dat

										###CHECK IF EXCHANGE REQUIRED#################################
										if [ $is_asset = 1 ] && [ $is_fungible = 1 ]
										then
											###EXCHANGE###################################################
											asset_type_price=$(grep "asset_price=" ${script_path}/assets/${trx_asset})
											asset_type_price=${asset_type_price#*=}
											asset_price=$(grep "asset_price=" ${script_path}/assets/${trx_receiver})
											asset_price=${asset_price#*=}
											asset_value=$(echo "scale=9; ${trx_amount} * ${asset_type_price} / ${asset_price}"|bc|sed 's/^\./0./g')

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
										fi
									fi
								else
									echo "${trx_filename}" >>${user_path}/ignored_trx.dat
								fi
							else
								echo "${trx_filename}" >>${user_path}/ignored_trx.dat
							fi
						else
							echo "${trx_filename}" >>${user_path}/ignored_trx.dat
						fi
					else
						echo "${trx_filename}" >>${user_path}/ignored_trx.dat
					fi
				else
					echo "${trx_filename}" >>${user_path}/ignored_trx.dat
				fi
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
				out_stamp=$(date +%s.%3N)
				last_ledger=$(basename -a ${user_path}/*_ledger.dat|tail -1)
				for balance in $(grep "${handover_account}" ${user_path}/${last_ledger}|grep "${cmd_asset}")
				do
					echo "BALANCE_${out_stamp}:${balance}"
				done
			fi
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
												file_ext_correct=$(echo "$file_ext"|grep -c '[^[:digit:]]')
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
											file_full_correct=$(echo "$file_full"|grep -c '[^[:alnum:]]')
											if [ $file_full_correct -gt 0 ]
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
			       					"trx")		if [ ! -d ${script_path}/$line ]
										then
											file_full=${line#*/}
											file_ext=${file_full#*.}
											file_ext_correct=$(echo "$file_ext"|sed 's/\.//g'|grep -c '[^[:digit:]]')
											if [ $file_ext_correct -gt 0 ]
											then
												rt_query=1
											else
												if [ $(grep "${line}" ${user_path}/tar_check_full.tmp|awk '{print $3}' -) -le $trx_max_size_bytes ]
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
											fi
										fi
					       					;;
								"proofs")	if [ ! -d ${script_path}/$line ]
										then
											file_usr=${line#*/}
											file_usr=${file_usr%%/*}
											file_usr_correct=$(echo "$file_usr"|grep -c '[^[:alnum:]]')
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
							if [ $rt_query = 1 ]
							then
								break
							fi
						done <${user_path}/tar_check.tmp
					else
						rt_query=1
					fi
				else
					rt_query=1
				fi
			fi

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
			if [ -f ${user_path}/all_assets.dat ] && [ -s ${user_path}/all_assets.dat ]
			then
				###REMOVE DELETED ASSETS FROM ALL_ASSETS.DAT AND SAVE##########
				ls -1 ${script_path}/assets|sort - ${user_path}/all_assets.dat|uniq -d >${user_path}/ack_assets.dat
			else
				rm ${user_path}/ack_assets.dat 2>/dev/null
				touch ${user_path}/ack_assets.dat
			fi

			###CREATE LIST OF NEW ASSETS###################################
			ls -1 ${script_path}/assets >${user_path}/all_assets.dat

			###CREATE LIST OF NEW ASSETS###################################
			sort -t . -k2 ${user_path}/all_assets.dat ${user_path}/ack_assets.dat|uniq -u >${user_path}/all_assets.tmp
			while read line
			do
				###CHECK IF ASSET IS MAIN ASSET################################
				if [ "${line}" = "${main_asset}" ]
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
						if [ -n "${asset_description}" ] && [ -n "${asset_fungible}" ]
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
									asset_owner_ok=0
									###IF NON FUNGIBLE ASSET#####################################
									if [ $asset_fungible = 0 ]
									then
										###CHECK ASSET HARDCAP#######################################
										if [ -n "${asset_quantity}" ] && [ ! "${asset_quantity}" = "*" ]
										then
											check_value=$asset_quantity
											asset_owner=$(echo "$asset_data"|grep "asset_owner")
											asset_owner=${asset_owner#*=}
											###CHECK IF ASSET OWNER IS SET###############################
											if [ -n "${asset_owner}" ]
											then
												test -f ${script_path}/keys/"${asset_owner}"
												rt_query=$?
												if [ $? = 0 ]
												then
													asset_owner_ok=1
												fi
											fi
										fi
									else
										###IF FUNGIBLE ASSET#########################################
										if [ $asset_fungible = 1 ]
										then
											check_value=$asset_price
											asset_owner_ok=1
										fi
									fi
									if [ $asset_owner_ok = 1 ]
									then
										###CHECK ASSET PRICE###################################
										rt_query=0
										is_amount_ok=$(echo "$check_value >= 0.000000001"|bc) || rt_query=1
										is_amount_mod=$(echo "$check_value % 0.000000001"|bc) || rt_query=1
										is_amount_mod=$(echo "${is_amount_mod} > 0"|bc) || rt_query=1
										if [ $is_amount_ok = 1 ] && [ $is_amount_mod = 0 ] && [ $rt_query = 0 ]
										then
											asset_acknowledged=1
										fi
									fi
								fi
							fi
						fi
					fi
				fi

				###WRITE ENTY TO BLACKLIST IF NOT ACKNOWLEDGED########
				if [ $asset_acknowledged = 0 ]
				then
					echo "$line" >>${user_path}/blacklisted_assets.dat
				fi
			done <${user_path}/all_assets.tmp

			###GO THROUGH BLACKLISTED TRX LINE BY LINE AND REMOVE THEM#########
			if [ -f ${user_path}/blacklisted_assets.dat ] && [ -s ${user_path}/blacklisted_assets.dat ]
			then
				while read line
				do
					rm ${script_path}/assets/${line} 2>/dev/null
				done <${user_path}/blacklisted_assets.dat
			fi

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
					exit 10
				fi
			fi
}
update_tsa(){
			cd ${script_path}/certs || exit 11

			###SET NOW STAMP#################################
			now_stamp=$(date +%s)

			###PURGE OLD TMP FILES###########################
			rm ${script_path}/certs/*.* 2>/dev/null

			###FOR EACH TSA-SERVICE IN CERTS/-FOLDER#########
			for tsa_service in $(ls -1 ${script_path}/certs/)
			do
				###SET VARIABLES#################################
				tsa_update_required=0
				tsa_checked=0
				tsa_cert_available=0
				tsa_rootcert_available=0
				crl_retry_counter=0
				retry_counter=0

				###CHECK IF TIMESTAMP-FILE IS THERE##############
				if [ -f "${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat" ] && [ -s "${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat" ]
				then
					###IF YES EXTRACT STAMP##########################
					last_check=$(cat ${script_path}/certs/${tsa_service}/tsa_check_crl_timestamp.dat)
					period_seconds=$(( now_stamp - last_check ))
				else
					###IF NOT SET STAMP##############################
					period_seconds=$(( check_period_tsa + 1 ))
				fi

				###CHECK TSA.CRT, CACERT.PEM AND ROOT_CA.CRL#####
				while [ $tsa_checked = 0 ]
				do
					###GET TSA CONFIG################################
					tsa_config=$(grep "${tsa_service}" ${script_path}/control/tsa.conf)
					tsa_cert_url=$(echo "${tsa_config}"|cut -d ',' -f2)
					tsa_cert_file=$(basename $tsa_cert_url)
					tsa_cacert_url=$(echo "${tsa_config}"|cut -d ',' -f3)
					tsa_cacert_file=$(basename $tsa_cacert_url)
					tsa_connect_string=$(echo "${tsa_config}"|cut -d ',' -f5)

					###IF TSA.CRT FILE AVAILABLE...##################
					if [ -f ${script_path}/certs/${tsa_service}/${tsa_cert_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_cert_file} ]
					then
						###GET DATES######################################
						old_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cert_file} -noout -dates|grep "notBefore"|cut -d '=' -f2)")
						old_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cert_file} -noout -dates|grep "notAfter"|cut -d '=' -f2)")

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
						###DOWNLOAD TSA.CRT###############################
						wget -o /dev/null -q -O ${tsa_cert_file} ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###GET DATES######################################
							new_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_cert_file} -noout -dates|grep "notBefore"|cut -d '=' -f2)")
							new_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_cert_file} -noout -dates|grep "notAfter"|cut -d '=' -f2)")

							###CHECK IF CERT IS VALID#########################
							if [ $now_stamp -gt $new_cert_valid_from ] && [ $now_stamp -lt $new_cert_valid_till ]
							then
								if [ -f ${script_path}/certs/${tsa_service}/${tsa_cert_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_cert_file} ]
								then
									file_name=${tsa_cert_file%%.*}
									file_ext=${tsa_cert_file#*.}
									mv ${script_path}/certs/${tsa_service}/${tsa_cert_file} ${script_path}/certs/${tsa_service}/${file_name}.${old_cert_valid_from}-${old_cert_valid_till}.${file_ext}
								fi
								mv ${script_path}/certs/${tsa_cert_file} ${script_path}/certs/${tsa_service}/${tsa_cert_file}
								tsa_cert_available=1
							else
								rm ${script_path}/certs/${tsa_cert_file} 2>/dev/null
							fi
						fi
						rm ${script_path}/certs/${tsa_cert_file} 2>/dev/null
						tsa_update_required=0
					fi

					###IF CACERT.PEM FILE AVAILABLE...################
					if [ -f ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ]
					then
						###GET DATES######################################
						old_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cacert_file} -noout -dates|grep "notBefore"|cut -d '=' -f2)")
						old_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cacert_file} -noout -dates|grep "notAfter"|cut -d '=' -f2)")

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
						###DOWNLOAD CACERT.PEM############################
						wget -o /dev/null -q -O ${tsa_cacert_file} ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###GET DATES######################################
							new_cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_cacert_file} -noout -dates|grep "notBefore"|cut -d '=' -f2)")
							new_cert_valid_till=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_cacert_file} -noout -dates|grep "notAfter"|cut -d '=' -f2)")

							###CHECK IF CERT IS VALID#########################
							if [ $now_stamp -gt $new_cert_valid_from ] && [ $now_stamp -lt $new_cert_valid_till ]
							then
								if [ -f ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ]
								then
									file_name=${tsa_cacert_file%%.*}
									file_ext=${tsa_cacert_file#*.}
									mv ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ${script_path}/certs/${tsa_service}/${file_name}.${old_cert_valid_from}-${old_cert_valid_till}.${file_ext}
								fi
								mv ${script_path}/certs/${tsa_cacert_file} ${script_path}/certs/${tsa_service}/${tsa_cacert_file}
								tsa_rootcert_available=1
							else
								rm ${script_path}/certs/${tsa_cacert_file}
							fi
						fi
						rm ${script_path}/certs/${tsa_cacert_file} 2>/dev/null
						tsa_update_required=0
					fi

					###IF TSA.CRT AND CACERT.PEM ARE THERE############
					if [ $tsa_cert_available = 1 ] && [ $tsa_rootcert_available = 1 ]
					then
						###GET TSA CRL URL FIRST BY CRT THEN BY CONFIG####
						tsa_crl_url=""
						tsa_crl_url=$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cert_file} -text -noout|grep -A4 "X509v3 CRL Distribution Points:"|grep "URI"|awk -F: '{print $2":"$3}')
						if [ -z "${tsa_crl_url}" ]
						then
							###GET CRL URL FROM TSA.CONF######################
							tsa_crl_url=$(echo "${tsa_config}"|cut -d ',' -f4)
							if [ -z "${tsa_crl_url}" ]
							then
								###IF NO CRL IS THERE#############################
								tsa_checked=1
							fi
						fi
						if [ $tsa_checked = 0 ]
						then
							###GET CRL FILE###########################################
							tsa_crl_file=$(basename $tsa_crl_url)

							###CHECK WAIT PERIOD######################################
							if [ $period_seconds -gt $check_period_tsa ] || [ ! -s ${script_path}/certs/${tsa_service}/${tsa_crl_file} ]
							then
								###DOWNLOAD CURRENT CRL FILE##############################
								wget -o /dev/null -q -O ${tsa_crl_file} ${tsa_crl_url}
								if [ -f ${script_path}/certs/${tsa_crl_file} ] && [ -s ${script_path}/certs/${tsa_crl_file} ]
								then
									###CHECK IF OLD CRL IS THERE##############################
									if [ -f ${script_path}/certs/${tsa_service}/${tsa_crl_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_crl_file} ]
									then
										###GET CRL DATES##########################################
										crl_old_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/${tsa_crl_file} -text|grep "Last Update:"|cut -c 22-45)")
										crl_old_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/${tsa_crl_file} -text|grep "Next Update:"|cut -c 22-45)")
										crl_new_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_crl_file} -text|grep "Last Update:"|cut -c 22-45)")
										crl_new_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_crl_file} -text|grep "Next Update:"|cut -c 22-45)")

										###COMPARE VALID FROM AND VALID TILL######################
										if [ $crl_old_valid_from -eq $crl_new_valid_from ] && [ $crl_old_valid_till -eq $crl_new_valid_till ]
										then
											###GET HASHES TO COMPARE##################################
											new_crl_hash=$(sha224sum ${script_path}/certs/${tsa_crl_file})
											new_crl_hash=${new_crl_hash%% *}
											old_crl_hash=$(sha224sum ${script_path}/certs/${tsa_service}/${tsa_crl_file})
											old_crl_hash=${old_crl_hash%% *}
											if [ ! "${new_crl_hash}" = "${old_crl_hash}" ]
											then
												mv ${script_path}/certs/${tsa_crl_file} ${script_path}/certs/${tsa_service}/${tsa_crl_file}
											fi
										else
											###UNCOMMENT TO ENABLE SAVESTORE OF CRL###################
											file_name=${tsa_cacert_file%%.*}
											file_ext=${tsa_cacert_file#*.}
											mv ${script_path}/certs/${tsa_service}/${tsa_crl_file} ${script_path}/certs/${tsa_service}/${file_name}.${crl_old_valid_from}-${crl_old_valid_till}.${file_ext}
											mv ${script_path}/certs/${tsa_crl_file} ${script_path}/certs/${tsa_service}/${tsa_crl_file}
										fi
									else
										mv ${script_path}/certs/${tsa_crl_file} ${script_path}/certs/${tsa_service}/${tsa_crl_file}
									fi
								fi
								rm ${script_path}/certs/${tsa_crl_file} 2>/dev/null
								if [ -f ${script_path}/certs/${tsa_service}/${tsa_crl_file} ] && [ -s ${script_path}/certs/${tsa_service}/${tsa_crl_file} ]
								then
									###GET CRL DATES########################
									crl_valid_from=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/${tsa_crl_file} -text|grep "Last Update:"|cut -c 22-45)")
									crl_valid_till=$(date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/${tsa_crl_file} -text|grep "Next Update:"|cut -c 22-45)")
									if [ $crl_valid_from -lt $now_stamp ] && [ $crl_valid_till -gt $now_stamp ]
									then
										###CHECK CERTIFICATE AGAINST CRL########
										cat ${script_path}/certs/${tsa_service}/${tsa_cacert_file} ${script_path}/certs/${tsa_service}/${tsa_crl_file} >${script_path}/certs/${tsa_service}/crl_chain.pem
										openssl verify -crl_check -CAfile ${script_path}/certs/${tsa_service}/crl_chain.pem ${script_path}/certs/${tsa_service}/${tsa_cert_file} >/dev/null 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											tsa_checked=1
										else
											tsa_update_required=1
											if [ $crl_retry_counter = 1 ]
											then
												file_name=${tsa_cert_file%%.*}
												file_ext=${tsa_cert_file#*.}
												cert_valid_from=$(date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/${tsa_cert_file} -text -noout|grep -A2 "Validity"|grep "Not Before"|cut -c 25-48)")
												mv ${script_path}/certs/${tsa_service}/${tsa_cert_file} ${script_path}/certs/${tsa_service}/${file_name}.${cert_valid_from}-${crl_valid_from}.${file_ext}
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
								exit 12
							else
								exit 12
							fi
						fi
					fi
				done
			done
			cd ${script_path} || exit 13
}
check_tsa(){
			###PURGE BLACKLIST AND SETUP ALL LIST#########
			rm ${user_path}/blacklisted_accounts.dat 2>/dev/null
			touch ${user_path}/blacklisted_accounts.dat
			if [ -f ${user_path}/all_accounts.dat ] && [ -s ${user_path}/all_accounts.dat ]
			then
				###REMOVE DELETED KEYS FROM ALL_ACCOUNTS.DAT AND SAVE#######
				ls -1 ${script_path}/keys|sort - ${user_path}/all_accounts.dat|uniq -d >${user_path}/ack_accounts.dat
			else
				rm ${user_path}/ack_accounts.dat 2>/dev/null
				touch ${user_path}/ack_accounts.dat
			fi

			###FLOCK######################################
			flock ${script_path}/keys ls -1 ${script_path}/keys >${user_path}/all_accounts.dat
			sort ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat|uniq -u >${user_path}/all_accounts.tmp
			if [ -s ${user_path}/all_accounts.tmp ]
			then
				gpg --with-colons --import-options show-only --import $(cat ${user_path}/all_accounts.tmp|awk -v script_path="${script_path}" '{print script_path "/keys/" $1}')|grep "uid" >${user_path}/gpg_check.tmp
				counter=1
				while read line
				do
					###SET FLAG##############################################
					account_verified=0

					###CHECK IF KEY-FILENAME IS EQUAL TO NAME INSIDE KEY#####
					account="${line}"
					account_key=$(head -$counter ${user_path}/gpg_check.tmp|tail -1|cut -d ':' -f10)
					if [ "${account}" = "${account_key}" ]
					then
						###FOR EACH TSA-SERVICE USED BY USER#####################
						for tsa_service in $(ls -1 ${script_path}/proofs/${account}/|grep ".tsr"|cut -d '.' -f1)
						do
							###CHECK IF TSA QUERY AND RESPONSE ARE THERE#############
							if [ -f ${script_path}/proofs/${account}/${tsa_service}.tsq ] && [ -s ${script_path}/proofs/${account}/${tsa_service}.tsq ] && [ -f ${script_path}/proofs/${account}/${tsa_service}.tsr ] && [ -s ${script_path}/proofs/${account}/${tsa_service}.tsr ]
							then
								###GET TSA CONFIG################################
								tsa_config=$(grep "${tsa_service}" ${script_path}/control/tsa.conf)
								tsa_cert_url=$(echo "${tsa_config}"|cut -d ',' -f2)
								tsa_cert_file=$(basename $tsa_cert_url)
								tsa_cacert_url=$(echo "${tsa_config}"|cut -d ',' -f3)
								tsa_cacert_file=$(basename $tsa_cacert_url)

								###CHECK TSA QUERYFILE###################################
								openssl ts -verify -queryfile ${script_path}/proofs/${account}/${tsa_service}.tsq -in ${script_path}/proofs/${account}/${tsa_service}.tsr -CAfile ${script_path}/certs/${tsa_service}/${tsa_cacert_file} -untrusted ${script_path}/certs/${tsa_service}/${tsa_cert_file} 1>/dev/null 2>/dev/null
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									###WRITE OUTPUT OF RESPONSE TO FILE######################
									openssl ts -reply -in ${script_path}/proofs/${account}/${tsa_service}.tsr -text >${user_path}/tsa_check.tmp 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										###VERIFY TSA RESPONSE###################################
										openssl ts -verify -data ${script_path}/keys/${line} -in ${script_path}/proofs/${account}/${tsa_service}.tsr -CAfile ${script_path}/certs/${tsa_service}/${tsa_cacert_file} -untrusted ${script_path}/certs/${tsa_service}/${tsa_cert_file} 1>/dev/null 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											###GET STAMPS###############################
											file_stamp=$(date -u +%s --date="$(grep "Time stamp" ${user_path}/tsa_check.tmp|cut -c 13-37)")
											key_stamp=$(head -$counter ${user_path}/gpg_check.tmp|tail -1|cut -d ':' -f6)

											###CALCULATE DIFFERENCE#####################
											stamp_diff=$(( file_stamp - key_stamp ))

											###CHECK IF CREATED WITHIN 120 SECONDS######
											if [ $stamp_diff -gt 0 ] && [ $stamp_diff -lt 120 ]
											then
												###WRITE STAMP TO FILE###################################
												echo "${account} ${file_stamp}" >>${user_path}/all_accounts_dates.dat

												###SET VARIABLE THAT TSA HAS BEEN FOUND##################
												account_verified=1

												###STEP OUT OF LOOP######################################
												break
											fi
										fi
									fi
								fi
							fi
						done
					fi
					if [ $account_verified = 0 ]
					then
						echo $line >>${user_path}/blacklisted_accounts.dat
					fi
					counter=$(( counter + 1 ))
				done <${user_path}/all_accounts.tmp
				rm ${user_path}/*_check.tmp 2>/dev/null
			fi

			#####################################################################################
			###GO THROUGH BLACKLISTED ACCOUNTS LINE BY LINE AND REMOVE KEYS AND PROOFS###########
			###############################WITH FLOCK############################################
			if [ -f ${user_path}/blacklisted_accounts.dat ] && [ -s ${user_path}/blacklisted_accounts.dat ]
			then
				cd ${user_path} || exit 3
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
				cd ${script_path} || exit 13
				#####################################################################################
			fi
			###REMOVE BLACKLISTED USER FROM LIST OF FILES######################
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
		###SETUP ALL LIST######################################
		if [ -f ${user_path}/all_keys.dat ] && [ -s ${user_path}/all_keys.dat ]
		then
			mv ${user_path}/all_keys.dat ${user_path}/ack_keys.dat
		else
			rm ${user_path}/ack_keys.dat 2>/dev/null
			touch ${user_path}/ack_keys.dat
		fi
		cp ${user_path}/all_accounts.dat ${user_path}/all_keys.dat
		sort ${user_path}/all_keys.dat ${user_path}/ack_keys.dat|uniq -u >${user_path}/all_keys.tmp

		###CHECK IF KEYS IN KEYRING IMPORT THEM IF NOT#########
		gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys 2>/dev/null|grep "uid"|cut -d ':' -f10 >${user_path}/keylist_gpg.tmp
  	        rt_query=$?
  	        if [ $rt_query = 0 ]
  	        then
  	        	###GO THROUGH ACCOUNTS NOT IN GPG KEYRING##############
	  	        for account in $(grep -v -f ${user_path}/keylist_gpg.tmp ${user_path}/all_keys.tmp)
	  	      	do
	  	      		###IMPORT KEY INTO KEYRING ############################
	  	      		gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/keys/${account} 2>/dev/null
		      		rt_query=$?
		      		if [ ! rt_query = 0 ]
			       	then
					echo "${account}" >>${user_path}/blacklisted_accounts.dat
			       	fi
		       	done
		fi
		rm ${user_path}/keylist_gpg.tmp

		###GO THROUGH BLACKLISTED ACCOUNTS LINE BY LINE AND REMOVE KEYS AND PROOFS###########
		###############################WITH FLOCK############################################
		if [ -f ${user_path}/blacklisted_accounts.dat ] && [ -s ${user_path}/blacklisted_accounts.dat ]
		then
			cd ${user_path} || exit 3
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
			cd ${script_path} || exit 13
			###################################################################
		fi
		###REMOVE BLACKLISTED ACCOUNTS FROM ACCOUNT LIST########
		sort ${user_path}/all_keys.tmp ${user_path}/blacklisted_accounts.dat|uniq -u >${user_path}/all_keys.dat

		###CHECK INDEX FILES####################################
		for account in $(cat ${user_path}/all_keys.dat)
		do
			index_file="${script_path}/proofs/${account}/${account}.txt"
			if [ -f $index_file ] && [ -s $index_file ]
			then
				verify_signature $index_file $account
				rt_query=$?
				if [ $rt_query -gt 0 ]
				then
					rm ${script_path}/proofs/${account}/${account}.txt 2>/dev/null
				fi
			fi
		done

		###ADD ACKNOWLEDGED ACCOUNTS TO FINAL LIST##############
		sort ${user_path}/all_keys.dat ${user_path}/ack_keys.dat >${user_path}/all_keys.tmp
		mv ${user_path}/all_keys.tmp ${user_path}/all_keys.dat
		cp ${user_path}/all_keys.dat ${user_path}/all_accounts.dat
		rm ${user_path}/ack_keys.dat
}
check_trx(){
		###PURGE BLACKLIST AND SETUP ALL LIST###################
		rm ${user_path}/blacklisted_trx.dat 2>/dev/null
		touch ${user_path}/blacklisted_trx.dat
		if [ -f ${user_path}/all_trx.dat ] && [ -s ${user_path}/all_trx.dat ]
		then
			###REMOVE DELETED TRX FROM ALL_TRX.DAT AND SAVE#########
			ls -1 ${script_path}/trx|sort - ${user_path}/all_trx.dat|uniq -d|grep -f ${user_path}/all_accounts.dat >${user_path}/ack_trx.dat
		else
			rm ${user_path}/ack_trx.dat 2>/dev/null
			touch ${user_path}/ack_trx.dat
		fi
		touch ${user_path}/all_trx.dat

		###WRITE INITIAL LIST OF TRANSACTIONS TO FILE###########
		ls -1 ${script_path}/trx >${user_path}/trx_list_all.tmp
		grep -f ${user_path}/all_accounts.dat ${user_path}/trx_list_all.tmp >${user_path}/all_trx.dat
		rm ${user_path}/trx_list_all.tmp 2>/dev/null

		###SORT LIST OF TRANSACTION PER DATE####################
		sort -t . -k2 ${user_path}/all_trx.dat ${user_path}/ack_trx.dat|uniq -u >${user_path}/all_trx.tmp

		###GO THROUGH TRANSACTIONS LINE PER LINE################
		while read line
		do
			###SET ACKNOWLEDGED VARIABLE############################
			trx_acknowledged=0

			###CHECK SIZE###########################################
			trx_size=$(wc -c <${script_path}/trx/${line})
			if [ $trx_size -le $trx_max_size_bytes ]
			then
				###CHECK IF HEADER MATCHES OWNER########################
				file_to_check=${script_path}/trx/${line}
				user_to_check=${line%%.*}
				trx_sender=$(awk -F: '/:SNDR:/{print $3}' $file_to_check)
				if [ "${user_to_check}" = "${trx_sender}" ]
				then
					###VERIFY SIGNATURE OF TRANSACTION######################
					verify_signature $file_to_check $user_to_check
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###GET DATES############################################
						trx_date_filename=${line#*.}
						trx_date_inside=$(awk -F: '/:TIME:/{print $3}' $file_to_check)
						trx_date_formatted=${trx_date_inside%%.*}
						trx_receiver_date=$(awk -F: '/:RCVR:/{print $3}' $file_to_check)
						###IF RECEIVER NOT A USER###############################
						if [ $(grep -c "${trx_receiver_date}" ${user_path}/all_accounts_dates.dat) = 0 ]
						then
							###IF RECEIVER NOT A ASSET##############################
							if [ $(grep -c "${trx_receiver_date}" ${user_path}/all_assets.dat) = 0 ]
							then
								###GET DATE#############################################
								trx_receiver_date=${trx_receiver_date#*.}
								if [ -z "${trx_receiver_date}" ]
								then
									###IF RECEIVER IS UNDETECTABLE##########################
									trx_receiver_date=$(date -u +%s --date="${start_date}")
								fi
							else
								if [ ! "${trx_receiver_date}" = "${main_asset}" ]
								then
									###IF RECEIVER IS ASSET GET DATE########################
									trx_receiver_date=$(grep "${trx_receiver_date}" ${user_path}/all_assets.dat)
									trx_receiver_date=${trx_receiver_date#*.}
								else
									###IF MAIN ASSET SET TO START DATE######################
									trx_receiver_date=$(date -u +%s --date="${start_date}")
								fi
							fi
						else
							###IF RECEIVER IS USER##################################
							trx_receiver_date=$(grep "${trx_receiver_date}" ${user_path}/all_accounts_dates.dat)
							trx_receiver_date=${trx_receiver_date#* }
						fi
						if [ $trx_date_filename = $trx_date_inside ] && [ $trx_date_formatted -gt $trx_receiver_date ]
						then
							###CHECK IF PURPOSE CONTAINS ALNUM######################
							purpose_key_start=$(awk -F: '/:PRPK:/{print NR}' $file_to_check)
							purpose_key_start=$(( purpose_key_start + 1 ))
							purpose_key_end=$(awk -F: '/:PRPS:/{print NR}' $file_to_check)
							purpose_key_end=$(( purpose_key_end - 1 ))
							purpose_key=$(sed -n "${purpose_key_start},${purpose_key_end}p" $file_to_check)
							purpose_key_contains_alnum=$(printf "%s" "${purpose_key}"|grep -c -v '[a-zA-Z0-9+/=]')
							purpose_start=$(awk -F: '/:PRPS:/{print NR}' $file_to_check)
							purpose_start=$(( purpose_start + 1 ))
							purpose_end=$(awk -F: '/BEGIN PGP SIGNATURE/{print NR}' $file_to_check)
							purpose_end=$(( purpose_end - 1 ))
							purpose=$(sed -n "${purpose_start},${purpose_end}p" $file_to_check)
							purpose_contains_alnum=$(printf "%s" "${purpose}"|grep -c -v '[a-zA-Z0-9+/=]')
							if [ $purpose_key_contains_alnum = 0 ] && [ $purpose_contains_alnum = 0 ]
							then
								###CHECK IF ASSET TYPE EXISTS###########################
								trx_asset=$(awk -F: '/:ASST:/{print $3}' $file_to_check)
								asset_already_exists=$(grep -c "${trx_asset}" ${user_path}/all_assets.dat)
								if [ $asset_already_exists = 1 ]
								then
									###CHECK IF AMOUNT IS MINIMUM 0.000000001###############
									trx_amount=$(awk -F: '/:AMNT:/{print $3}' $file_to_check)
									is_amount_ok=$(echo "${trx_amount} >= 0.000000001"|bc)
									is_amount_mod=$(echo "${trx_amount} % 0.000000001"|bc)
									is_amount_mod=$(echo "${is_amount_mod} > 0"|bc)

									###CHECK IF USER HAS CREATED A INDEX FILE###############
									if [ -f ${script_path}/proofs/${user_to_check}/${user_to_check}.txt ] && [ -s ${script_path}/proofs/${user_to_check}/${user_to_check}.txt ]
									then
										####CHECK IF USER HAS INDEXED THE TRANSACTION###########
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
			fi
			if [ $trx_acknowledged = 0 ]
			then
				if [ ! ${user_to_check} = ${handover_account} ]
				then
					echo $line >>${user_path}/blacklisted_trx.dat
				fi
			fi
		done <${user_path}/all_trx.tmp

		###GO THROUGH BLACKLISTED TRX AND REMOVE THEM#########
		if [ -f ${user_path}/blacklisted_trx.dat ] && [ -s ${user_path}/blacklisted_trx.dat ]
		then
			while read line
			do
				rm ${script_path}/trx/${line} 2>/dev/null
			done <${user_path}/blacklisted_trx.dat
		fi

		###REMOVE BLACKLISTED TRX FROM ACCOUNT LIST###########
		sort -t . -k2 ${user_path}/all_trx.tmp ${user_path}/blacklisted_trx.dat|uniq -u >${user_path}/all_trx.dat

		###ADD ACKNOWLEDGED TRX TO FINAL LIST#################
		sort -t . -k2 ${user_path}/all_trx.dat ${user_path}/ack_trx.dat >${user_path}/all_trx.tmp
		mv ${user_path}/all_trx.tmp ${user_path}/all_trx.dat
		rm ${user_path}/ack_trx.dat

		cd ${script_path} || exit 13
}
process_new_files(){
			process_mode=$1
			if [ $process_mode = 0 ]
			then
				###CREATE TMP FILE##################################
				touch ${user_path}/remove_list.tmp
				touch ${user_path}/new_list.tmp
				for new_index_file in $(grep ".txt" ${user_path}/files_to_fetch.tmp)
				do
					###CHECK IF USER ALREADY EXISTS#####################
					user_to_verify=$(basename -s ".txt" $new_index_file)
					user_already_there=$(cat ${user_path}/all_accounts.dat|grep -c "${user_to_verify}")
					if [ $user_already_there = 1 ]
					then
						###VERIFY SIGNATURE OF USER#########################
						verify_signature ${user_path}/temp/${new_index_file} $user_to_verify
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###GO THROUGH ALL ASSETS OF NEW INDEX FILE##########
							for new_index_asset in $(grep "assets/" ${user_path}/temp/${new_index_file})
							do
								###COMPARE HASHES###################################
								is_asset_there=$(grep -c "${new_index_asset}" ${script_path}/proofs/${handover_account}/${handover_account}.txt)
								if [ $is_asset_there = 0 ]
								then
									echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
								fi
							done
						else
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						fi
					else
						###CHECK IF USER KEY IS CONTAINED#############
						user_new=$(ls -1 ${user_path}/temp/keys|grep -c "${user_to_verify}")
						if [ $user_new = 0 ]
						then
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						else
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/new_list.tmp
						fi
					fi
				done
				###UPDATE LIST OF FILES TO FETCH##############
				sort ${user_path}/remove_list.tmp ${user_path}/files_to_fetch.tmp|uniq -u >${user_path}/temp_filelist.tmp
				mv ${user_path}/temp_filelist.tmp ${user_path}/files_to_fetch.tmp

				###REMOVE FILES OF REMOVE LIST################
				while read line
				do
					rm ${user_path}/temp/${line}
				done <${user_path}/remove_list.tmp
				rm ${user_path}/remove_list.tmp 2>/dev/null
				touch ${user_path}/remove_list.tmp

				###AFTER INDEX FILES HAVE BEEN VERIFIED#######
				for new_index_file in $(sort ${user_path}/new_list.tmp ${user_path}/files_to_fetch.tmp|uniq -u|grep ".txt")
				do
					###SET VARIABLES############################################
					user_to_verify=$(basename -s ".txt" $new_index_file)
					new_trx_score_highest=0
					old_trx_score_highest=0

					###GET USER TRANSACTION OF OLD AND NEW INDEX FILE###########
					grep "trx/${user_to_verify}" ${user_path}/temp/${new_index_file} >${user_path}/new_index_filelist.tmp
					grep "trx/${user_to_verify}" ${script_path}/${new_index_file} >${user_path}/old_index_filelist.tmp

					###GET UNIQUE USER TRANSACIONS OF OLD INDEX FILE############
					sort ${user_path}/new_index_filelist.tmp ${user_path}/old_index_filelist.tmp ${user_path}/old_index_filelist.tmp|uniq -u >${user_path}/new_unique_filelist.tmp

					###GET UNIQUE USER TRANSACIONS OF NEW INDEX FILE############
					sort ${user_path}/old_index_filelist.tmp ${user_path}/new_index_filelist.tmp ${user_path}/new_index_filelist.tmp|uniq -u >${user_path}/old_unique_filelist.tmp

					###GET HIGHEST NUMBER OF TRX CONFIRMATIONS IN OLD INDEX#####
					while read line
					do
						stripped_file=$(echo "${line}"|awk '{print $1}')
						if [ -f ${script_path}/${stripped_file} ] && [ -s ${script_path}/${stripped_file} ]
						then
							old_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/${stripped_file})
							old_trx_confirmations=$(grep -l "$line" ${script_path}/proofs/*/*.txt|grep -c -v "${user_to_verify}\|${old_trx_receiver}")
							if [ $old_trx_confirmations -gt $old_trx_score_highest ]
							then
								old_trx_score_highest=$old_trx_confirmations
							fi
						fi
					done <${user_path}/old_unique_filelist.tmp

					###GET HIGHEST NUMBER OF TRX CONFIRMATIONS IN NEW INDEX#####
					while read line
					do
						stripped_file=$(echo "${line}"|awk '{print $1}')
						if [ -f ${user_path}/temp/${stripped_file} ] && [ -s ${user_path}/temp/${stripped_file} ]
						then
							new_trx_receiver=$(awk -F: '/:RCVR:/{print $3}' ${user_path}/temp/${stripped_file})
							new_trx_confirmations=$(grep -l "$line" ${user_path}/temp/proofs/*/*.txt|grep -c -v "${user_to_verify}\|${new_trx_receiver}")
							if [ $new_trx_confirmations -gt $new_trx_score_highest ]
							then
								new_trx_score_highest=$new_trx_confirmations
							fi
						fi
					done <${user_path}/new_unique_filelist.tmp

					###COMPARE BOTH############################################
					if [ $old_trx_score_highest -ge $new_trx_score_highest ]
					then
						if [ $old_trx_score_highest -gt $new_trx_score_highest ] || [ $(grep -c -v "trx/${user_to_verify}" ${user_path}/temp/${new_index_file}) -le $(grep -c -v "trx/${user_to_verify}" ${script_path}/${new_index_file}) ]
						then
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						fi
					fi
				done
				###UPDATE LIST OF FILES TO FETCH##############
				sort ${user_path}/remove_list.tmp ${user_path}/files_to_fetch.tmp|uniq -u >${user_path}/temp_filelist.tmp
				mv ${user_path}/temp_filelist.tmp ${user_path}/files_to_fetch.tmp

				###REMOVE FILES OF REMOVE LIST################
				while read line
				do
					rm ${user_path}/temp/${line}
				done <${user_path}/remove_list.tmp
				rm ${user_path}/remove_list.tmp 2>/dev/null
				rm ${user_path}/new_list.tmp
			else
				###CHECK IF EXISTING FILES ARE OVERWRITTEN####
				files_replaced=0
				while read file_to_fetch
				do
					if [ -f ${script_path}/$file_to_fetch ] && [ -s ${script_path}/$file_to_fetch ]
					then
						files_replaced=1
					fi
				done <${user_path}/files_to_fetch.tmp

				###IF FILES OVERWRITTEN DELETE *.DAT FILES####
				if [ $files_replaced = 1 ]
				then
					rm ${script_path}/userdata/${handover_account}/*.dat
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
				cd ${user_path} || exit 3
				flock ${script_path}/keys/ -c '
				user_path=$(pwd)
				base_dir=$(dirname $user_path)
				script_path=$(dirname $base_dir)
				cp ${user_path}/temp/assets/* ${script_path}/assets/ 2>/dev/null
				cp ${user_path}/temp/keys/* ${script_path}/keys/ 2>/dev/null
				cp -r ${user_path}/temp/proofs/* ${script_path}/proofs/ 2>/dev/null
				cp ${user_path}/temp/trx/* ${script_path}/trx/ 2>/dev/null
				'
				cd ${script_path} || exit 13
				#############################################

				###PURGE TEMP FILES##########################
				rm -r ${user_path}/temp/assets/* 2>/dev/null
				rm -r ${user_path}/temp/keys/* 2>/dev/null
				rm -r ${user_path}/temp/trx/* 2>/dev/null
			fi
			###CLEANUP TEMP PROOFS#######################
			rm -r ${user_path}/temp/proofs/* 2>/dev/null
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
					if [ -f $file_to_change ]
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
		for key_fp in $(gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys 2>/dev/null|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p')
		do
			gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
			gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-keys ${key_fp} 2>/dev/null
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
		for private_key in $(ls -1 ${script_path}/control/keys|grep -v ".sct")
		do
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/control/keys/${private_key} 2>/dev/null
		done
		for public_key in $(ls -1 ${script_path}/keys)
		do
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/keys/${public_key} 2>/dev/null
		done
}
get_dependencies(){
			cd ${script_path}/trx || exit 14
			ledger_mode=1
			own_index_there=0
			first_start=0

			###CHECK IF INDEX/IGNORE/LEDGER THERE IF NOT BUILD LEDGE######################
			if [ -f ${script_path}/proofs/${handover_account}/${handover_account}.txt ] && [ -s ${script_path}/proofs/${handover_account}/${handover_account}.txt ]
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
			if [ $only_process_depend = 1 ]
			then
				counter=1
				echo "${handover_account}" >${user_path}/depend_accounts.dat
				grep "${handover_account}" ${user_path}/all_trx.dat >${user_path}/depend_trx.dat
				while [ $counter -le $(wc -l <${user_path}/depend_accounts.dat) ]
				do
					user=$(head -$counter ${user_path}/depend_accounts.dat|tail -1)
					grep -l "RCVR:${user}" /dev/null $(cat ${user_path}/all_trx.dat)|cut -d '.' -f1 >${user_path}/depend_user_list.tmp
					for trx in $(grep "${user}" ${user_path}/all_trx.dat)
					do
						echo "${trx}" >>${user_path}/depend_trx.dat
						receiver=$(awk -F: '/:RCVR:/{print $3}' ${script_path}/trx/${trx})
						if [ $(grep -c "$receiver" ${user_path}/all_assets.dat) = 0 ] && [ $(grep -c "$receiver" ${user_path}/all_accounts.dat) = 1 ]
						then
							echo $receiver >>${user_path}/depend_user_list.tmp
						fi
					done
					for user in $(sort -u ${user_path}/depend_user_list.tmp)
					do
						if [ $(grep -c "${user}" ${user_path}/depend_accounts.dat) = 0 ]
						then
							echo $user >>${user_path}/depend_accounts.dat
						fi
					done
					counter=$(( counter + 1 ))
				done
				rm ${user_path}/depend_user_list.tmp

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

			###GET DEPEND TRX THAT HAVE ENOUGH CONFIRMATIONS##############################
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
						if [ -n "${depend_accounts_new_date}" ]
						then
							echo "${depend_accounts_new_date}" >>${user_path}/dates.tmp
						fi
					fi
					if [ ! "${depend_trx_new_hash}" = "${depend_trx_old_hash}" ]
					then
						if [ -e ${user_path}/depend_trx.dat ] && [ ! "${depend_trx_old_hash}" = "X" ]
						then
							depend_trx_new_date=$(sort -t . -k2 ${user_path}/depend_trx_old.tmp ${user_path}/depend_trx.dat|uniq -u|head -1|cut -d '.' -f2)
							if [ -n "${depend_trx_new_date}" ]
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
							if [ -n "${depend_confirmations_new_date}" ]
							then
								echo "${depend_confirmations_new_date}" >>${user_path}/dates.tmp
							fi
						fi
					fi

					###GET EARLIEST DATE AND REMOVE ALL FILES AFTER THIS DATE#####################
					cd ${user_path} || exit 3
					earliest_date=$(sort ${user_path}/dates.tmp|head -1)
					if [ -n "${earliest_date}" ]
					then
						last_date=$(date +%Y%m%d --date=@${earliest_date})
						for ledger in $(basename -a ${user_path}/*_ledger.dat|awk -F_ -v last_date="${last_date}" '$1 >= last_date')
						do
							rm $ledger
						done
						for index in $(basename -a ${user_path}/*_index_trx.dat|awk -F_ -v last_date="${last_date}" '$1 >= last_date')
						do
							rm $index
						done
					fi
				fi
			fi
			rm ${user_path}/*.tmp 2>/dev/null
			cd ${script_path} || exit 13
			return $ledger_mode
}
request_uca(){
		### MAKE CLEAN START ##############################
		rm ${user_path}/dhuser_*.* 2>/dev/null
		rm ${user_path}/dhsecret_*.* 2>/dev/null

		### GET TOTAL NUMBER OF UCAs FOR PROGRESSBAR ######
		if [ $gui_mode = 1 ]
		then
			rm ${user_path}/uca_list.tmp 2>/dev/null
			total_number_uca=$(wc -l <${script_path}/control/uca.conf)
			percent_per_uca=$(echo "scale=10; 100 / $total_number_uca"|bc)
			current_percent=0
			percent_display=0
			while read line
			do
				uca_info=${line#*,*,*,*}
				printf "%b" "\"${uca_info%%,*}\" \"WAITING\"\n" >>${user_path}/uca_list.tmp
			done <${script_path}/control/uca.conf
		fi
		###################################################

		### GET A UNIQUE ID AND WRITE TO FILE #############
		unique_id=$(mktemp -u XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)
		echo "${unique_id}" >${user_path}/dhuser_id.dat

		### WRITE PLAIN INDEX TO FILE WITHOUT TRX/ ########
		gpg --output - --verify ${script_path}/proofs/${handover_account}/${handover_account}.txt 2>/dev/null|grep -v "trx/" >${user_path}/dhuser_data.tmp

		### ADD TRANSACTIONS ##############################
		sha224sum ${script_path}/trx/* 2>/dev/null|awk '{print $2 " " $1}'|sed "s#${script_path}/##g" >>${user_path}/dhuser_data.tmp

		### MERGE ID AND PLAIN INDEX ######################
		cat ${user_path}/dhuser_id.dat ${user_path}/dhuser_data.tmp >${user_path}/dhuser.dat
		rm ${user_path}/dhuser_data.tmp 2>/dev/null

		### READ UCA.CONF LINE BY LINE ####################
		while read line
		do
			### GET VALUES FROM UCA.CONF #######################
			uca_connect_string=${line%%,*}
			uca_rcv_port=${line#*,}
			uca_rcv_port=${uca_rcv_port%%,*}
			uca_info=${line#*,*,*,*}
			uca_info=${uca_info%%,*}
			uca_info_hashed=$(echo "${uca_info}"|sha224sum)
			uca_info_hashed=${uca_info_hashed%% *}

			### SET FILES #######################################
			sync_file="${user_path}/uca_${uca_info_hashed}.sync"
			out_file="${user_path}/uca_${uca_info_hashed}.out"

			### STATUS BAR FOR GUI ##############################
			if [ $gui_mode = 1 ]
			then
				sed -i "s/\"${uca_info}\" \"WAITING\"/\"${uca_info}\" \"IN_PROGRESS\"/g" ${user_path}/uca_list.tmp
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_request" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi

			### GENERATE DIFFIE-HELLMAN GLOBAL PUBLIC #########
			#openssl genpkey -genparam -algorithm DH -out - >${user_path}/dhparams.pem 2>/dev/null
			openssl dhparam -dsaparam -out - $dh_key_length >${user_path}/dhparams.pem 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				### GENERATE KEY ##################################
				openssl genpkey -paramfile ${user_path}/dhparams.pem -out - >${user_path}/dhkey_send.pem
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					### GET PUBLIC KEY ################################
					openssl pkey -in ${user_path}/dhkey_send.pem -pubout -out - >${user_path}/dhpub_send.pem
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### ENCRYPT ID AND INDEX ##########################
						session_key=$(date -u +%Y%m%d)
						echo "${session_key}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output - --passphrase-fd 0 ${user_path}/dhuser.dat >${user_path}/dhuser.tmp
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### SEND CLIENT INFO, DH PARAMS AND PUBKEY ########
							cat ${user_path}/dhuser.tmp ${user_path}/dhparams.pem ${user_path}/dhpub_send.pem|netcat -q 10 -w 120 ${uca_connect_string} ${uca_rcv_port} >${out_file} 2>/dev/null
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								### GET SIZE OF HEADER AND BODY ###################
								total_lines_header=$(grep -n "END PUBLIC KEY" ${out_file}|cut -d ':' -f1)
								total_lines_header_user=$(grep -n "END PGP MESSAGE" ${out_file}|head -1|cut -d ':' -f1)
								total_lines_header_param=$(( total_lines_header - total_lines_header_user ))
								total_bytes_received=$(wc -c <${out_file})
								total_bytes_header=$(head -$total_lines_header ${out_file}|wc -c)
								total_bytes_count=$(( total_bytes_received - total_bytes_header ))

								### EXTRACT SERVER INFO ###########################
								head -$total_lines_header_user ${out_file} >${user_path}/dhuser_${uca_info_hashed}.tmp

								### EXTRACT PUBKEY ################################
								head -$total_lines_header ${out_file}|tail -$total_lines_header_param >${user_path}/dhpub_receive.pem

								### CALCULATE SHARED SECRET #######################
								openssl pkeyutl -derive -inkey ${user_path}/dhkey_send.pem -peerkey ${user_path}/dhpub_receive.pem -out - >${user_path}/dhsecret_${uca_info_hashed}.dat
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									### EXTRACT SHARED SECRET #########################
									shared_secret=$(sha224sum <${user_path}/dhsecret_${uca_info_hashed}.dat)
									shared_secret=${shared_secret%% *}

									### DECRYPT SERVER INFO ###########################
									echo "${shared_secret}"|gpg --batch --no-tty --pinentry-mode loopback --output - --passphrase-fd 0 --decrypt ${user_path}/dhuser_${uca_info_hashed}.tmp >${user_path}/dhuser_${uca_info_hashed}.dat 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										### CUT OUT BODY AND MOVE FILE ####################
										dd skip=${total_bytes_header} count=${total_bytes_count} if=${out_file} of=${out_file}.tmp bs=1 2>/dev/null
										mv ${out_file}.tmp ${out_file}

										### DECRYPT RECEIVED DATA #########################
										echo "${shared_secret}"|gpg --batch --no-tty --pinentry-mode loopback --output ${sync_file} --passphrase-fd 0 --decrypt ${out_file} 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											### CHECK FILE ####################################
											check_archive ${sync_file} 0
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												### STEP INTO USERDATA/USER/TEMP ##################
												cd ${user_path}/temp || exit 15

												### EXTRACT FILE ##################################
												tar -xzf ${sync_file} -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													process_new_files 0
													set_permissions
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

			### PURGE TEMP FILES ################################
			rm ${out_file} 2>/dev/null
			rm ${sync_file} 2>/dev/null

			### PROGRESSBAR FOR GUI #############################
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
			else
				if [ ! $rt_query = 0 ]
				then
					echo "ERROR: UCA-LINK RCV ${uca_connect_string}:${uca_rcv_port} FAILED"
				fi
			fi
		done <${script_path}/control/uca.conf

		### CLEAN UP FILES ##################################
		rm ${user_path}/dhuser.* 2>/dev/null
		rm ${user_path}/dhparams.pem 2>/dev/null
		rm ${user_path}/dhkey_send.pem 2>/dev/null
		rm ${user_path}/dhpub_send.pem 2>/dev/null
		rm ${user_path}/dhpub_receive.pem 2>/dev/null
		rm ${user_path}/uca_list.tmp 2>/dev/null
}
send_uca(){
		### SET VARIABLES ###################################
		now_stamp=$(date +%s)
		sync_file="${user_path}/${handover_account}_${now_stamp}.sync"
		out_file="${user_path}/${handover_account}_${now_stamp}.out"

		### GET TOTAL NUMBER FOR PROGRESSBAR ################
		if [ $gui_mode = 1 ]
		then
			rm ${user_path}/uca_list.tmp 2>/dev/null
			total_number_uca=$(wc -l <${script_path}/control/uca.conf)
			percent_per_uca=$(echo "scale=10; 100 / $total_number_uca"|bc)
			current_percent=0
			percent_display=0
			while read line
			do
				uca_info=${line#*,*,*,*}
				printf "%b" "\"${uca_info%%,*}\" \"WAITING\"\n" >>${user_path}/uca_list.tmp
			done <${script_path}/control/uca.conf
		fi
		#####################################################

		### READ UCA.CONF LINE BY LINE ######################
		while read line
		do
			### GET VALUES FROM UCA.CONF ########################
			uca_connect_string=${line%%,*}
			uca_snd_port=${line#*,*,*}
			uca_snd_port=${uca_snd_port%%,*}
			uca_info=${line#*,*,*,*}
			uca_info=${uca_info%%,*}
			uca_info_hashed=$(echo "${uca_info}"|sha224sum)
			uca_info_hashed=${uca_info_hashed%% *}

			### STATUS BAR FOR GUI ##############################
			if [ $gui_mode = 1 ]
			then
				sed -i "s/\"${uca_info}\" \"WAITING\"/\"${uca_info}\" \"IN_PROGRESS\"/g" ${user_path}/uca_list.tmp
				dialog --title "$dialog_uca_full" --backtitle "$core_system_name $core_system_version" --mixedgauge "$dialog_uca_send" 0 0 $percent_display --file ${user_path}/uca_list.tmp
			fi

			### ONLY CONTINUE IF SECRET IS THERE ################
			if [ -f ${user_path}/dhsecret_${uca_info_hashed}.dat ] && [ -s ${user_path}/dhsecret_${uca_info_hashed}.dat ]
			then
				### GET CONNECTION DATA #############################
				shared_secret=$(sha224sum <${user_path}/dhsecret_${uca_info_hashed}.dat)
				shared_secret=${shared_secret%% *}

				### COLLECT DATA ####################################
				user_data_lines=$(wc -l <${user_path}/dhuser_${uca_info_hashed}.dat)
				user_data_lines=$(( user_data_lines - 1 ))
				user_dataset=$(tail -$user_data_lines ${user_path}/dhuser_${uca_info_hashed}.dat)
				own_dataset=$(gpg --output - --verify ${script_path}/proofs/${handover_account}/${handover_account}.txt 2>/dev/null)
				shared_dataset=$(echo "${user_dataset}${own_dataset}"|sort -|uniq -d)
				echo "${own_dataset}${shared_dataset}"|sort -|uniq -u|cut -d ' ' -f1 >${user_path}/files_list.tmp
				if [ ! -s ${user_path}/files_list.tmp ]
				then
					echo "proofs/${user_account}/${user_account}.txt" >${user_path}/files_list.tmp
				fi

				### STEP INTO HOMEDIR AND CREATE TARBALL ############
				cd ${script_path} || exit 13
				tar -czf ${out_file} -T ${user_path}/files_list.tmp --dereference --hard-dereference
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					### ENCRYPT USERDATA ################################
					echo "${session_key}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${user_path}/dhuser.tmp --passphrase-fd 0 ${user_path}/dhuser_id.dat
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						### ENCRYPT SYNCFILE ################################
						echo "${shared_secret}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${sync_file} --passphrase-fd 0 ${out_file}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							### SEND KEY AND SYNCFILE VIA DIFFIE-HELLMAN ########
							cat ${user_path}/dhuser.tmp ${sync_file}|netcat -w 5 ${uca_connect_string} ${uca_snd_port} >/dev/null 2>/dev/null
							rt_query=$?
						fi
					fi
				fi
			else
				rt_query=1
			fi
			###PURGE TEMP FILES###############################
			rm ${out_file} 2>/dev/null
			rm ${sync_file} 2>/dev/null
			rm ${user_path}/dhuser_id.dat 2>/dev/null
			rm ${user_path}/dhuser_${uca_info_hashed}.dat 2>/dev/null
			rm ${user_path}/dhuser.tmp 2>/dev/null
			rm ${user_path}/dhsecret_${uca_info_hashed}.dat 2>/dev/null
			rm ${user_path}/files_list.tmp 2>/dev/null

			### PROGRESS BAR ###################################
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
			else
				if [ ! $rt_query = 0 ]
				then
					echo "ERROR: UCA-LINK SND ${uca_connect_string}:${uca_snd_port} FAILED"
				fi
			fi
		done <${script_path}/control/uca.conf
		rm ${user_path}/uca_list.tmp 2>/dev/null
		sleep 1
}
urlencode(){
		### SET INITIAL VALUES #############################
		rt_query=0

		### HANDOVER FILE PATH #############################
		file_path=$1

		### URL ENCODE USING AWK ###########################
		enc_string=$(LC_ALL=C awk '
    		BEGIN {
      			for (i = 1; i <= 255; i++) {
      				hex[sprintf("%c", i)] = sprintf("%%%02X", i)
    			}
    		}
    		function urlencode(s,c,i,r,l) {
      		  l = length(s)
      		  for (i = 1; i <= l; i++) {
      		  	c = substr(s, i, 1)
      		  	r = r "" (c ~ /^[-._~0-9a-zA-Z]$/ ? c : hex[c])
		  }
		  return r
    		}
    		BEGIN {
			for (i = 1; i < ARGC; i++) {
				print urlencode(ARGV[i])
			}
		}' "$(cat ${file_path})") || rt_query = 1
		return $rt_query
}
##################
#Main Menu Screen#
##################
###SET INITIAL VARIABLES####
initial_coinload=365250
check_period_tsa=21600
trx_max_size_bytes=3164
trx_max_size_purpose_bytes=1024
dh_key_length=2048
main_asset="UCC"
last_ledger=""
default_tsa=""
start_date="20250412"
now=$(date -u +%Y%m%d)
user_logged_in=0
uca_trigger=0
action_done=1
make_ledger=1
make_new_index=1
new_ledger=0
no_ledger=0
end_program=0
small_trx=0
script_path=$(dirname $(readlink -f ${0}))
my_pid=$$
gui_mode=1

###VERSION INFO#############
core_system_name="Universal Credit System"
core_system_version=$(cat "${script_path}"/control/version_info)

###SOURCE CONFIG FILE#######
. ${script_path}/control/config.conf

###SET THEME################
export DIALOGRC="${script_path}/theme/${theme_file}"
dialogrc_set="${theme_file}"

###SOURCE LANGUAGE FILE#####
. ${script_path}/lang/${lang_file}

###CHECK FOR STDIN INPUT####
if [ ! -t 0 ]
then
	set -- $(cat) "$@"
fi

###CHECK IF GUI MODE OR CMD MODE AND ASSIGN VARIABLES###
if [ $# -gt 0 ]
then
	###IF ANY VARIABLES ARE HANDED OVER SET INITAL VALUES##########
	main_menu=$dialog_main_logon
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
	cmd_type=""
	cmd_path=""
	cmd_file=""
	cmd_config=""

	###GO THROUGH PARAMETERS ONE BY ONE############################
	while [ $# -gt 0 ]
	do
		###GET TARGET VARIABLES########################################
		case $1 in
			"-new_ledger")	new_ledger=1
					;;
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
			"-config")	cmd_var=$1
					;;
			"-debug")	set -x
					set -v
					;;
			"-version")	echo "${core_system_version}"
					exit 0
					;;
			"-help")	more ${script_path}/control/HELP.txt
					exit 0
					;;
			*)		###SET TARGET VARIABLES########################################
					case $cmd_var in
						"-action")	gui_mode=0
								cmd_action=$1
								case $cmd_action in
									"create_user")		main_menu=$dialog_main_create
												;;
									"create_backup")	main_menu=$dialog_main_backup
												;;
									"restore_backup")	main_menu=$dialog_main_backup
												;;
									"create_trx")		user_menu=$dialog_send
												;;
									"read_trx")		user_menu=$dialog_receive
												;;
									"show_trx")		main_menu=$cmd_action
												;;
									"create_sync")		user_menu=$dialog_sync
												;;
									"read_sync")		user_menu=$dialog_sync
												;;
									"sync_uca")		user_menu=$dialog_uca
												;;
									"show_addressbook")	main_menu=$cmd_action
												;;
									"show_balance")		main_menu=$dialog_main_logon
												;;
									"show_stats")		user_logged_in=1
												user_menu=$dialog_stats
												;;
									*)			echo "ERROR! TRY THIS:"
												echo "./ucs_client.sh -help"
												exit 16
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
											exit 16
											;;
								esac
								;;
						"-path")	cmd_path=$1
								;;
						"-file")	cmd_file=$1
								;;
						"-config")	cmd_config=$1
								if [ -f "${cmd_config}" ] && [ -s "${cmd_config}" ]
								then
									. "${cmd_config}"
								else
									echo "ERROR: -config ${cmd_config}: FILES DOES NOT EXIST OR IS EMPTY"
									exit 17
								fi
								;;
						*)		echo "ERROR! TRY THIS:"
								echo "./ucs_client.sh -help"
								exit 16
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
									account_name_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --output-fd 1 --max-input 30 --inputbox "$dialog_login_display_account" 0 0 "$cmd_user")
									rt_query=$?
								else
									if [ -n "${cmd_user}" ]
									then
										rt_query=0
										account_name_entered=$cmd_user
									else
										if [ -z "${cmd_sender}" ]
										then
											exit 18
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
												account_pin_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --output-fd 1 --max-input 5 --insecure --passwordbox "$dialog_login_display_loginkey" 0 0 "$cmd_pin")
												rt_query=$?
											else
												if [ -n "${cmd_pin}" ]
												then
													rt_query=0
													account_pin_entered=$cmd_pin
												else
													if [ -z "${cmd_sender}" ]
													then
														exit 18
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
															account_password_entered=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name $core_system_version" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_login_display_pw" 0 0 "$cmd_pw")
															rt_query=$?
														else
															if [ -n "${cmd_pw}" ]
															then
																rt_query=0
																account_password_entered=$cmd_pw
															else
																exit 19
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
							###CHECK IF PARAMETER IS SET TO REBUILD LEDGER###############
							if [ $user_logged_in = 1 ] && [ $new_ledger = 1 ] && [ $no_ledger = 0 ]
							then
								rm "${user_path}"/*.dat 2>/dev/null
							fi
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
									if [ -z "${cmd_user}" ]
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
										name_hash=$(echo "${account_name}"|sha224sum)
										name_hash=${name_hash%% *}
										already_there=$(grep -c "${name_hash}" ${script_path}/control/accounts.db)
										if [ $already_there = 0 ]
										then
											account_pin_inputbox=""
											account_pin_entered_correct=0
											while [ $account_pin_entered_correct = 0 ]
											do
												if [ $gui_mode = 1 ]
												then
													account_pin_first=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --title "$dialog_main_create" --backtitle "$core_system_name $core_system_version" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin1" 0 0 "$account_pin_inputbox")
													rt_query=$?
												else
													if [ -z "${cmd_pin}" ]
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
															account_pin_second=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_create" --backtitle "$core_system_name $core_system_version" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin2" 0 0 "$account_pin_inputbox")
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
																		account_password_first=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_create" --backtitle "$core_system_name $core_system_version" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw1" 0 0)
																		rt_query=$?
																	else
																		if [ -z "${cmd_pw}" ]
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
																				account_password_second=$(dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_create" --backtitle "$core_system_name $core_system_version" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw2" 0 0)
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
																					update_tsa
																					create_keys "${account_name}" "${account_pin_second}" "${account_password_second}"
																					rt_query=$?
																					if [ $rt_query = 0 ]
																					then
																						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_success" 0 0
																					else
																						dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_fail" 0 0
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
										else
											if [ $gui_mode = 1 ]
											then
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_keys_exists" 0 0
											else
												exit 20
											fi
										fi
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
															changed=$(dialog --extra-label "$dialog_main_choose" --cancel-label "$dialog_add" --output-fd 1 --inputmenu "CONFIG.CONF" 30 70 10 --file ${script_path}/config_${my_pid}.tmp)
															rt_query=$?
															if [ $rt_query = 3 ]
															then
																entry=$(echo "${changed}"|awk '{print $2}'|awk -F= '{print $1}')
																old_value=$(grep "${entry}" ${script_path}/config_${my_pid}.tmp|awk -F= '{print $2}'|sed 's/ //g')
																new_value=$(echo "${changed}"|awk '{print $3}')
																sed -i "s#${entry}=${old_value}#${entry}=${new_value}#" ${script_path}/control/config.conf
															else
																if [ $rt_query = 1 ]
																then
																	touch ${script_path}/config_${my_pid}_add.tmp
																	dialog --ok-label "$dialog_add" --cancel-label "$dialog_cancel" --title "CONFIG.CONF+" --backtitle "$core_system_name $core_system_version" --editbox ${script_path}/config_${my_pid}_add.tmp 20 80 2>${script_path}/config_${my_pid}_added.tmp
																	rt_query=$?
																	if [ $rt_query = 0 ]
																	then
																		cat ${script_path}/config_${my_pid}_added.tmp >>${script_path}/control/config.conf
																	fi
																	rm ${script_path}/config_${my_pid}_add.tmp
																	rm ${script_path}/config_${my_pid}_added.tmp
																else
																	config_changed=1
																fi
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
								cd ${script_path} || exit 13
								now_stamp=$(date +%s)
								tar -czf ${script_path}/backup/${now_stamp}.bcp assets/ control/ keys/ trx/ proofs/ userdata/ --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									backup_file="${now_stamp}.bcp"
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
										exit 21
									fi
								fi
							else
								if [ ! $rt_query = 255 ]
								then
									if [ $gui_mode = 1 ]
									then
										find ${script_path}/backup/ -maxdepth 1 -type f -name "*.bcp"|sort -r -t . -k1 >${script_path}/backups_list.tmp
										if [ $(wc -l <${script_path}/backups_list.tmp) -gt 0 ]
										then
											while read line
											do
												backup_file=$(basename "${line}")
												backup_stamp=${backup_file%%.*}
												backup_date=$(date +'%F|%H:%M:%S' --date=@${backup_stamp})
												printf "%s" "${backup_date} Backup " >>${script_path}/backup_list.tmp
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
												file_path=$(cat ${script_path}/backups_list.tmp|grep "${bcp_stamp}")
												cd ${script_path} || exit 13
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
										if [ -z "${cmd_path}" ]
										then
											exit 23
										else
											cd ${script_path} || exit 13
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
													echo "BACKUP_FILE_RESTORE:FAILED"
													exit 24
												else
													import_keys
													echo "BACKUP_FILE_RESTORE:FINISHED"
													exit 0
												fi
											else
												exit 25
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
				"show_addressbook")	ls -1 keys/|awk '{ print "ADDRESS:" $1 }'
							exit 0
							;;
				"show_trx")		rt_code=0
							for trx in $(grep -l ":ASST:${cmd_asset}" /dev/null $(grep -l ":RCVR:${cmd_receiver}" /dev/null $(ls -1Xr "${script_path}"/trx/* 2>/dev/null|grep "${cmd_sender}"|grep "${cmd_file}")))
							do
								if [ -f "${trx}" ] && [ -s "${trx}" ]
								then
									sender=$(awk -F: '/:SNDR:/{print $3}' "${trx}")
									receiver=$(awk -F: '/:RCVR:/{print $3}' "${trx}")
									if [ -n "${sender}" ] && [ -n "${receiver}" ]
									then
										signature="ERROR_VERIFY_SIGNATURE"
										gpg --status-fd 1 --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --verify "${trx}" >${script_path}/gpg_${my_pid}_verify.tmp 2>/dev/null
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											signed_correct=$(grep "GOODSIG" ${script_path}/gpg_${my_pid}_verify.tmp|grep -c "${sender}")
											if [ $signed_correct -ge 1 ]
											then
												trx_file=$(basename "${trx}")
												if [ "${trx_file%%.*}" = "${sender}" ]
												then
													signature="OK"
												fi
											fi
										else
											rt_code=1
										fi
										trx_hash=$(sha256sum "${trx}")
										trx_hash=${trx_hash%% *}
										amount=$(awk -F: '/:AMNT:/{print $3}' "${trx}")
										asset=$(awk -F: '/:ASST:/{print $3}' "${trx}")
										trx=$(basename "${trx}")
										trx_stamp=${trx#*.}
										confirmations=$(grep -s -l "trx/${trx} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${sender}\|${receiver}")
										index="ERROR_NOT_INDEXED"
										is_indexed=$(grep -c "trx/${trx} ${trx_hash}" ${script_path}/proofs/${sender}/${sender}.txt)
										if [ $is_indexed -gt 0 ]
										then
											index="OK"
										fi
										echo "TRANSACTION  :trx/${trx}"
										echo "SHA256_HASH  :${trx_hash}"
										echo "TRX_STAMP    :${trx_stamp}"
										echo "TRX_SENDER   :${sender}"
										echo "TRX_RECEIVER :${receiver}"
										echo "TRX_AMOUNT   :${amount}"
										echo "TRX_ASSET    :${asset}"
										echo "SIGNATURE    :${signature}"
										echo "STATUS_INDEX :${index}"
										echo "CONFIRMATIONS:${confirmations}"
										rm ${script_path}/gpg_${my_pid}_verify.tmp 2>/dev/null
									fi
								fi
							done
							if [ $rt_code = 0 ]
							then
								exit 0
							else
								exit 26
							fi
							;;
			esac
		fi

	else
		###IF AUTO-UCA-SYNC########################
		if [ $auto_uca_start = 1 ] && [ $no_ledger = 0 ] && [ ! "${cmd_action}" = "show_stats" ]
		then
			request_uca
		fi

		###DO NOTHING WHEN SHOWING STATS###########
		if [ "${cmd_action}" = "show_stats" ]
		then
			no_ledger=1
			action_done=0
		fi

		###ON EACH START AND AFTER EACH ACTION#####
		if [ $action_done = 1 ]
		then
			update_tsa
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
				if [ "${cmd_action}" = "show_balance" ]
				then
					exit 0
				fi
				make_ledger=0
			fi
			check_blacklist
			account_my_balance=""
			for ledger_entry in $(grep ":${handover_account}" ${user_path}/${now}_ledger.dat)
			do
				balance_asset=${ledger_entry%%:*}
				balance_value=${ledger_entry#*=}
				account_my_balance="${account_my_balance}${balance_value} ${balance_asset}\n"
			done
		fi

		###IF AUTO-UCA-SYNC########################
		if [ $auto_uca_start = 1 ] && [ $no_ledger = 0 ] && [ ! "${cmd_action}" = "show_stats" ]
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
			dialog_main_menu_text_display=$(echo $dialog_main_menu_text|sed -e "s/<login_name>/${login_name}/g" -e "s/<handover_account>/${handover_account}/g" -e "s/<account_my_balance>/${account_my_balance}/g")
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
						grep "${handover_account}" ${user_path}/${now}_ledger.dat|cut -d ':' -f1|sort -t. -k1 -k2 >${user_path}/menu_assets.tmp
						if [ $gui_mode = 1 ]
						then
							def_string_asset=$(head -1 ${user_path}/menu_assets.tmp)
						fi
						while [ $asset_found = 0 ]
						do
							if [ $gui_mode = 1 ]
							then
								quit_asset_loop=0
								while [ $quit_asset_loop = 0 ]
								do
									###ASSET OVERVIEW################################
									order_asset=$(dialog --cancel-label "$dialog_cancel" --extra-button --extra-label "$dialog_show" --default-item "$def_string_asset" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_assets:" 0 0 0 --file ${user_path}/menu_assets.tmp)
									rt_query=$?
									if [ $rt_query = 3 ]
									then
										###SET DEFAULT-ITEM OF DIALOG MENU###############
										def_string_asset=$order_asset

										###DISPLAY DETAILED ASSET INFORMATION############
										dialog --exit-label "$dialog_main_back" --title "$dialog_assets : $order_asset" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/assets/${order_asset}" 0 0						
									else
										quit_asset_loop=1
									fi
								done
							else
								if [ -z "${cmd_asset}" ] && [ $(wc -l <${user_path}/menu_assets.tmp) = 1 ]
								then
									order_asset=$main_asset
								else
									order_asset=$cmd_asset
								fi
								asset_there=$(grep -c -w "${order_asset}" ${user_path}/menu_assets.tmp)
								if [ $asset_there = 1 ]
								then
									rt_query=0
								else
									exit 27
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
										if [ -n "${order_receipient}" ]
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
														exit 28
													fi
												fi
											fi
											while [ $amount_selected = 0 ]
											do
												account_my_balance=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_ledger.dat)
												account_my_balance=${account_my_balance#*=}
												if [ $gui_mode = 1 ]
												then
													dialog_send_amount_display=$(echo $dialog_send_amount|sed -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g")
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
														amount_big_enough=$(echo "${amount_mod} > 0"|bc)
														if [ $amount_big_enough = 0 ]
														then
															order_amount_formatted=$(echo "scale=9; ${order_amount_formatted} / 1"|bc|sed 's/^\./0./g')
															if [ $receipient_is_asset = 1 ]
															then
																asset=$order_receipient
															else
																asset=$main_asset
															fi
															asset_price=$(grep "asset_price=" ${script_path}/assets/${asset})
															asset_price=${asset_price#*=}
															asset_value=$(echo "scale=9; 0.000000001 * ${asset_price}"|bc|sed 's/^\./0./g')
															amount_big_enough=$(echo "${order_amount_formatted} < ${asset_value}"|bc)
															dialog_send_amount_not_big_enough=$(echo "$dialog_send_amount_not_big_enough"|sed "s/0.000000001/${asset_value}/g")
														fi
														if [ $amount_big_enough = 0 ]
														then
															enough_balance=$(echo "${account_my_balance} - ${order_amount_formatted} >= 0"|bc)
															if [ $enough_balance = 1 ]
															then
																amount_selected=1
															else
																if [ $gui_mode = 1 ]
																then
																	dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail_nobalance" 0 0
																else
																	exit 29
																fi
															fi
														else
															if [ $gui_mode = 1 ]
															then
																dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_amount_not_big_enough" 0 0
															else
																exit 30
															fi
														fi
													else
														if [ $gui_mode = 1 ]
														then
															dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail_amount" 0 0
														else
															exit 31
														fi
													fi
												else
													amount_selected=1
													receipient_found=1
													order_aborted=1
												fi
											done
										fi
									else
										if [ $rt_query = 1 ]
										then
											rm ${user_path}/menu_addresses_fungible.tmp 2>/dev/null
											touch ${user_path}/menu_addresses_fungible.tmp
											is_order_asset_fungible=$(grep -c "asset_fungible=1" ${script_path}/assets/${order_asset})
											if [ $is_order_asset_fungible = 1 ]
											then
												while read line
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
												order_purpose=$(dialog --ok-label "$dialog_next" --cancel-label "..." --help-button --help-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name $core_system_version" --max-input $trx_max_size_purpose_bytes --output-fd 1 --inputbox "$dialog_send_purpose" 0 0 "")
												rt_query=$?
												if [ $rt_query = 1 ]
												then
													###IF USER WANTS EDITBOX##############################
													dialog --ok-label "$dialog_next" --cancel-label "..." --help-button --help-label "$dialog_cancel" --title "$dialog_send_purpose" --backtitle "$core_system_name $core_system_version" --editbox ${user_path}/trx_purpose_blank.tmp 20 80 2>${user_path}/trx_purpose_edited.tmp
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														### CHECK FOR MAX PURPOSE SIZE #################################
														if [ $(wc -c <${user_path}/trx_purpose_edited.tmp) -le $trx_max_size_purpose_bytes ]
														then
															order_purpose=$(cat ${user_path}/trx_purpose_edited.tmp)
															quit_purpose_loop=1
														else
															dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_size $trx_max_size_purpose_bytes Bytes!" 0 0		
															cp ${user_path}/trx_purpose_edited.tmp ${user_path}/trx_purpose_blank.tmp
														fi
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
																	if [ -f "${file_path}" ] && [ -s "${file_path}" ]
																	then
																		### CHECK FOR MAX PURPOSE SIZE #################################
																		if [ $(wc -c <${file_path}) -le $trx_max_size_purpose_bytes ]
																		then
																			quit_file_path=1
																			quit_purpose_loop=1
																			order_purpose_path=$file_path
																			is_file=1
																			is_text=$(file ${order_purpose_path}|grep -c -v "text")
																		else
																			path_to_search=$file_path
																			dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_size $trx_max_size_purpose_bytes Bytes!" 0 0
																		fi
																	else
																		if [ -d "${file_path}" ]
																		then
																			path_to_search=$file_path
																		fi
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
											if [ -n "${cmd_file}" ] && [ -f "${cmd_file}" ] && [ -s "${cmd_file}" ]
											then
												### CHECK SIZE #######################################
												if [ $(wc -c <${cmd_file}) -gt $trx_max_size_purpose_bytes ] 
												then
													exit 32
												fi
												order_purpose_path=$cmd_file
												is_file=1
												is_text=$(file ${order_purpose_path}|grep -c -v "text")
											else
												### CHECK SIZE #######################################
												if [ $(printf "%s" "${order_purpose}"|wc -c) -gt $trx_max_size_purpose_bytes ] 
												then
													exit 32
												fi
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
											receiver=$order_receipient
										else
											receiver=$handover_account
										fi
										###GET RANDOM KEY#######################################
										random_key=$(head -50 /dev/urandom|tr -dc "[:alnum:]"|head -c 32)
										echo "${random_key}" >${user_path}/trx_purpose_key.tmp
										###ENCRYPT KEY##########################################
										order_purpose_key=$(gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always -r ${receiver} --pinentry-mode loopback --armor --output - --encrypt ${user_path}/trx_purpose_key.tmp 2>/dev/null|awk '/-----BEGIN PGP MESSAGE-----/{next} /-----END PGP MESSAGE-----/{next} NF>0 {print}' -)
										###ENCRYPT PURPOSE######################################
										order_purpose_encrypted=$(echo "${random_key}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output - --passphrase-fd 0 ${user_path}/trx_purpose_edited.tmp|awk '/-----BEGIN PGP MESSAGE-----/{next} /-----END PGP MESSAGE-----/{next} NF>0 {print}' -)
										rm ${user_path}/trx_purpose_key.tmp
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
											trx_now=$(date +%s.%3N)
											make_signature ":TIME:${trx_now}\n:AMNT:${order_amount_formatted}\n:ASST:${order_asset}\n:SNDR:${handover_account}\n:RCVR:${order_receipient}\n:PRPK:\n${order_purpose_key}\n:PRPS:\n${order_purpose_encrypted}" ${trx_now} 0
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
															if [ $small_trx = 0 ] && [ -f $receipient_index_file ] && [ -s $receipient_index_file ]
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
																	for tsa_file in $(ls -1 ${script_path}/proofs/${line}/*.ts*)
																	do
																		file=$(basename $tsa_file)
																		tsa_file_there=$(grep -c "proofs/${line}/${file}" $receipient_index_file)
																		if [ $tsa_file_there = 0 ]
																		then
																			echo "proofs/${line}/${file}"
																		fi
																	done
																	if [ -f ${script_path}/proofs/${line}/${line}.txt ] && [ -s ${script_path}/proofs/${line}/${line}.txt ]
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
																	if [ -f ${script_path}/proofs/${line}/${line}.txt ] && [ -s ${script_path}/proofs/${line}/${line}.txt ]
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
														trx_now_form=$(echo "$trx_now"|sed 's/\./_/g')
														if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
														then
															cd ${script_path} || exit 13
															tar -czf ${handover_account}_${trx_now_form}.trx.tmp -T ${user_path}/files_list.tmp --dereference --hard-dereference
															rt_query=$?
															rm ${user_path}/files_list.tmp 2>/dev/null
														fi
														if [ $rt_query = 0 ]
														then
															###COMMANDS TO REPLACE BUILD LEDGER CALL######################################
															###SET BALANCE################################################################
															account_new_balance=$(echo "${account_my_balance} - ${order_amount_formatted}"|bc|sed 's/^\./0./g')
															sed -i "s/${order_asset}:${handover_account}=${account_my_balance}/${order_asset}:${handover_account}=${account_new_balance}/g" ${user_path}/${now}_ledger.dat
															##############################################################################

															###WRITE ENTRIES TO FILES#####################################################
															echo "${handover_account}.${trx_now}" >>${user_path}/all_trx.dat
															echo "${handover_account}.${trx_now}" >>${user_path}/depend_trx.dat
															##############################################################################
															##############################################################################

															###WRITE OUTPUT IN CMD MODE BEFORE LEDGER IS DELETED ARE DELETED##############
															if [ $gui_mode = 0 ]
															then
																out_stamp=$(date +%s.%3N)
																cmd_output=$(grep "${order_asset}:${handover_account}" ${user_path}/${now}_ledger.dat)
																echo "BALANCE_${out_stamp}:${cmd_output}"
															fi

															###SET VARIABLES FOR NEXT LOOP RUN###########################################
															make_ledger=1
															get_dependencies
															ledger_mode=$?

															###ENCRYPT TRX FILE SO THAT ONLY THE RECEIVER CAN READ IT####################
															if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
															then
																echo "${order_receipient}"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output ${handover_account}_${trx_now_form}.trx --passphrase-fd 0 ${handover_account}_${trx_now_form}.trx.tmp
																rt_query=$?
															fi
															if [ $rt_query = 0 ]
															then
																if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
																then
																	###REMOVE GPG TMP FILE#######################################################
																	rm ${script_path}/${handover_account}_${trx_now_form}.trx.tmp 2>/dev/null

																	###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER##########################
																	#cp ${script_path}/${handover_account}_${trx_now_form}.trx ${user_path}/${handover_account}_${trx_now_form}.trx
																	#############################################################################
																	if [ ! $trx_path_output = $script_path ] && [ -d $trx_path_output ]
																	then
																		mv ${script_path}/${handover_account}_${trx_now_form}.trx ${trx_path_output}/${handover_account}_${trx_now_form}.trx
																	else
																		if [ -z "${trx_path_output}" ]
																		then
																			rm ${script_path}/${handover_account}_${trx_now_form}.trx
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
																	echo "TRX:trx/${handover_account}.${trx_now}"
																	if [ $receipient_is_asset = 0 ] && [ ! $small_trx = 255 ]
																	then
																		if [ -n "${cmd_path}" ] && [ ! "${trx_path_output}" = "${cmd_path}" ]
																		then
																			mv ${trx_path_output}/${handover_account}_${trx_now_form}.trx ${cmd_path}/${handover_account}_${trx_now_form}.trx
																			echo "FILE:${cmd_path}/${handover_account}_${trx_now_form}.trx"
																		else
																			echo "FILE:${trx_path_output}/${handover_account}_${trx_now_form}.trx"
																		fi
																	fi
																	exit 0
																fi
															else
																rm ${trx_path_output}/${handover_account}_${trx_now_form}.trx.tmp 2>/dev/null
																rm ${trx_path_output}/${handover_account}_${trx_now_form}.trx 2>/dev/null
																rm ${last_trx} 2>/dev/null
															fi
														else
															rm ${script_path}/${handover_account}_${trx_now_form}.trx.tmp 2>/dev/null
															rm ${last_trx} 2>/dev/null
														fi
													fi
												fi
											fi
											if [ ! $rt_query = 0 ]
											then
												if [ $gui_mode = 1 ]
												then
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_send_fail" 0 0
												else
													exit 33
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
									rt_query=1
									if [ ! -d "${file_path}" ] && [ -f "${file_path}" ] && [ -s "${file_path}" ]
									then
										cd ${script_path} || exit 13
										if [ $gui_mode = 1 ]
										then
											all_extract=0
										else
											all_extract=$extract_all
										fi

										###DECRYPT TRANSACTION FILE################################
										echo "${handover_account}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --output ${file_path}.tmp --decrypt ${file_path} 1>/dev/null 2>/dev/null
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
												cd ${user_path}/temp || exit 15
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
														update_tsa
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
																exit 34
															else
																exit 0
															fi
														else
															exit 1
														fi
													fi
												fi
											fi
										fi
										rm ${file_path}.tmp 2>/dev/null
									fi
									if [ ! $rt_query = 0 ]
									then
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
											dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
										else
											exit 35
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
								*)		exit 16
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
									rt_query=1
									if [ ! -d "${file_path}" ] && [ -f "${file_path}" ] && [ -s "${file_path}" ]
		  							then
										cd ${script_path} || exit 13
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
												*)		exit 16
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
												cd ${user_path}/temp || exit 15
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
														update_tsa
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
																exit 34
															else
																exit 0
															fi
														else
															exit 0
														fi
													fi
												fi
											fi
										else
											file_found=1
										fi
									fi
									if [ ! $rt_query = 0 ]
									then
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=$(echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g")
			       								dialog --title "$dialog_type_title_error" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_sync_import_fail_display" 0 0
										else
											exit 35
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
									###SET VARIABLES#############################
									if [ $gui_mode = 0 ] && [ $cmd_type = "partial" ]
									then
										accounts_list="${user_path}/depend_accounts.dat"
										trx_list="${user_path}/depend_trx.dat"
									else
										accounts_list="${user_path}/all_accounts.dat"
										trx_list="${user_path}/all_trx.dat"
									fi

									###WRITE ASSETS TO FILE LIST#################
									awk '{print "assets/" $1}' ${user_path}/all_assets.dat

									###WRITE ACCOUNTS TO FILE LIST###############
									while read user
									do
										echo "keys/${user}"
										for tsa_file in $(ls -1 ${script_path}/proofs/${user}/*.ts*)
										do
											file=$(basename $tsa_file)
											echo "proofs/${user}/${file}"
										done
										if [ -f ${script_path}/proofs/${user}/${user}.txt ] && [ -s ${script_path}/proofs/${user}/${user}.txt ]
										then
											echo "proofs/${user}/${user}.txt"

										fi
									done <${accounts_list}

									###WRITE TRX TO FILE LIST####################
									awk '{print "trx/" $1}' ${trx_list}
								} >${user_path}/files_list.tmp

								###GET CURRENT TIMESTAMP#################################
								now_stamp=$(date +%s)

								###SWITCH TO SCRIPT PATH AND CREATE TAR-BALL#############
								cd ${script_path} || exit 13
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
										if [ -n "${cmd_path}" ] && [ ! "${sync_path_output}" = "${cmd_path}" ]
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
								update_tsa
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
										"$dialog_assets")	###SET DEFAULT-ITEM OF DIALOG MENU#######################
													def_string_asset=$(head -1 ${user_path}/all_assets.dat)								
													quit_asset_menu=0
													while [ $quit_asset_menu = 0 ]
													do
														###ASSET OVERVIEW########################################
														asset=$(dialog --ok-label "$dialog_show" --extra-button --extra-label "$dialog_add" --cancel-label "$dialog_cancel" --default-item "$def_string_asset" --title "$dialog_browser : $dialog_assets" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/all_assets.dat)
														rt_query=$?
														if [ $rt_query = 0 ] || [ $rt_query = 3 ]
														then
															###SET DEFAULT-ITEM OF DIALOG MENU#######################
															def_string_asset=$asset
															if [ $rt_query = 0 ]
															then
																###DISPLAY DETAILED ASSET INFORMATION####################
																dialog --exit-label "$dialog_main_back" --title "$dialog_assets : $asset" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/assets/${asset}" 0 0
															else
																asset_name=""
																quit_asset_name=0
																while [ $quit_asset_name = 0 ]
																do
																	###ASK FOR A NAME########################################
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
																				enc_string=""

																				###ENCODE DESCRIPTION############################
																				urlencode "${user_path}/asset_description.tmp"
																				rm ${user_path}/asset_description.tmp

																				###ASSIGN ENCODED RESULT#########################
																				asset_description=$enc_string

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
																											echo "asset_name=\"${asset_name}\""
																											echo "asset_fungible=${fungible}"
																											if [ $fungible = 0 ]
																											then
																												echo "asset_quantity=${asset_value_formatted}"
																												echo "asset_owner=\"${handover_account}\""
																											else
																												echo "asset_price=${asset_value_formatted}"
																											fi
																											echo "asset_description=\"${asset_description}\""
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
																												if [ $fungible = 0 ] && [ ! $(grep -c "${asset_name}.${asset_stamp}" "${user_path}"/all_assets.dat) = 0 ]
																												then
																													###CREATE LEDGER ENTRY###################
																													last_ledger=$(basename -a ${user_path}/*_ledger.dat|tail -1)
																													echo "${asset_name}.${asset_stamp}:${handover_account}=${asset_quantity}" >>${user_path}/${last_ledger}
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
																			rm ${user_path}/asset_description_blank.tmp 2>/dev/null
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
										"$dialog_users")	###SET DEFAULT-ITEM OF DIALOG MENU#######################
													def_string_user=$(head -1 ${user_path}/all_accounts.dat)
													quit_user_menu=0
													while [ $quit_user_menu = 0 ]
													do
														###USERS OVERVIEW########################################
														user=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --default-item "$def_string_user" --title "$dialog_browser : $dialog_users" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/all_accounts.dat)
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															###SET DEFAULT ITEM######################################
															def_string_user=$user

															###USERS TRX OVERVIEW####################################
															grep "${user}" ${user_path}/all_trx.dat >${user_path}/dialog_browser_trx.tmp
															if [ ! -s ${user_path}/dialog_browser_trx.tmp ]
															then
																echo "0" >${user_path}/dialog_browser_trx.tmp
															fi

															###SET DEFAULT-ITEM OF DIALOG MENU#######################
															def_string_trx=$(head -1 ${user_path}/dialog_browser_trx.tmp)

															quit_trx_menu=0
															while [ $quit_trx_menu = 0 ]
															do
																selected_trx=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --default-item "$def_string_trx" --title "$dialog_browser : $dialog_trx" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$user:" 0 0 0 --file ${user_path}/dialog_browser_trx.tmp)
																rt_query=$?
																if [ $rt_query = 0 ] && [ ! "${selected_trx}" = "0" ]
																then
																	def_string_trx=$selected_trx
																	dialog --exit-label "$dialog_main_back" --title "$dialog_browser:" --backtitle "$core_system_name $core_system_version" --textbox "${script_path}/trx/$selected_trx" 0 0
																else
																	quit_trx_menu=1	
																fi
															done
															rm ${user_path}/dialog_browser_trx.tmp
														else
															quit_user_menu=1
														fi
													done
													;;
										"$dialog_trx")		###TRX OVERVIEW##########################################
													if [ ! -s ${user_path}/all_trx.dat ]
													then
														echo "0" >${user_path}/dialog_browser_trx.tmp
													else
														sort -r -t . -k2 ${user_path}/all_trx.dat >${user_path}/dialog_browser_trx.tmp
													fi
													quit_trx_loop=0
													def_string=$(head -1 ${user_path}/dialog_browser_trx.tmp)
													while [ $quit_trx_loop = 0 ]
													do
														selected_trx=$(dialog --ok-label "$dialog_show" --cancel-label "$dialog_cancel" --default-item "${def_string}" --title "$dialog_browser : $dialog_trx" --backtitle "$core_system_name $core_system_version" --no-items --output-fd 1 --menu "$dialog_overview:" 0 0 0 --file ${user_path}/dialog_browser_trx.tmp)
														rt_query=$?
														if [ $rt_query = 0 ] && [ ! "${selected_trx}" = "0" ]
														then
															def_string=$selected_trx
															dialog --exit-label "$dialog_main_back" --title "$dialog_browser:" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${script_path}/trx/${selected_trx}" 0 0
														else
															quit_trx_loop=1
														fi
													done
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
							grep -s -l ":${handover_account}" ${script_path}/trx/*|sort -r -t . -k2 >${user_path}/my_trx.tmp
							no_trx=$(wc -l <${user_path}/my_trx.tmp)
							if [ $no_trx -gt 0 ]
							then
								while read trx_file
								do
									trx_filename=$(basename "${trx_file}")
									sender=$(awk -F: '/:SNDR:/{print $3}' $trx_file)
									receiver=$(awk -F: '/:RCVR:/{print $3}' $trx_file)
									trx_date_tmp=${trx_filename#*.}
									trx_date=$(date +'%F|%H:%M:%S.%3N' --date=@${trx_date_tmp})
			      						trx_amount=$(awk -F: '/:AMNT:/{print $3}' $trx_file)
									trx_asset=$(awk -F: '/:ASST:/{print $3}' $trx_file)
									trx_hash=$(sha256sum $trx_file)
									trx_hash=${trx_hash%% *}
									trx_confirmations=$(grep -s -l "trx/${trx_filename} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${sender}\|${receiver}")
									if [ -f ${script_path}/proofs/${sender}/${sender}.txt ] && [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
									then
										trx_signed=$(grep -c "${trx_filename} ${trx_hash}" ${script_path}/proofs/${sender}/${sender}.txt)
									else
										trx_signed=0
									fi
									if [ $trx_signed -gt 0 ]
									then
										if [ $trx_confirmations -ge $confirmations_from_users ]
										then
											trx_blacklisted=$(grep -c "${trx_filename}" ${user_path}/blacklisted_trx.dat)
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
									if [ ! "${decision}" = "${dialog_history_noresults}" ]
									then
										trx_date_extracted=${decision%%|*}
										trx_time_extracted=${decision#*|*}
										trx_time_extracted=${trx_time_extracted%%|*}
										trx_date=$(date +%s --date="${trx_date_extracted} ${trx_time_extracted}")
										if [ $(grep -c "${trx_date}" ${user_path}/my_trx.tmp) = 0 ]
										then
											trx_date=${trx_date%%.*}
										fi
										trx_file=$(basename $(grep "${trx_date}" ${user_path}/my_trx.tmp))
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
											} >${user_path}/history_purpose_key_encrypted.tmp
											echo "${login_password}"|gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase-fd 0 --pinentry-mode loopback --output ${user_path}/history_purpose_key_decrypted.tmp --decrypt ${user_path}/history_purpose_key_encrypted.tmp 2>/dev/null
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												purpose_key=$(cat ${user_path}/history_purpose_key_decrypted.tmp)
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
												echo "${purpose_key}"|gpg --batch --no-tty --pinentry-mode loopback --output ${user_path}/history_purpose_decrypted.tmp --passphrase-fd 0 --decrypt ${user_path}/history_purpose_encrypted.tmp 2>/dev/null
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													if [ -f ${user_path}/history_purpose_decrypted.tmp ] && [ -s ${user_path}/history_purpose_decrypted.tmp ]
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
										fi
										rm ${user_path}/history_purpose_encrypted.tmp 2>/dev/null
										trx_status=""
										if [ -f ${script_path}/proofs/${sender}/${sender}.txt ] && [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
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
										if [ $trx_signed = 1 ] && [ $trx_blacklisted = 0 ] && [ $sender_blacklisted = 0 ] && [ $receiver_blacklisted = 0 ]
										then
											trx_status="OK"
										fi
										user_total_depend=$(grep -c -v "${sender}\|${receiver}" ${user_path}/depend_accounts.dat)
										user_total_all=$(grep -c -v "${sender}\|${receiver}" ${user_path}/all_accounts.dat)
										trx_confirmations_depend=$(grep -s -l "trx/${trx_file} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -f ${user_path}/depend_accounts.dat|grep -c -v "${sender}\|${receiver}")
										trx_confirmations_all=$(grep -s -l "trx/${trx_file} ${trx_hash}" ${script_path}/proofs/*/*.txt|grep -c -v "${sender}\|${receiver}")
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
													rt_query=$?
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
				"$dialog_stats")	###IF CMD_ASSET NOT SET USE UCC################
							if [ -z "${cmd_asset}" ]
							then
								order_asset=$main_asset
							else
								order_asset=$cmd_asset
							fi

							###CALCULATE TOTAL NUMBER OF COINS#############
							counter=1
							total_users=0
							total_number_coins=0
							daily_payout=365250
							today=$(date +%s)
							focus=$(date -u +%s --date="$start_date")
							user_dates_list=$(gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys|grep "uid"|grep "$(ls -1 ${script_path}/keys/)" -|cut -d ':' -f6)
							while [ $focus -le $today ]
							do
								total_payout=$(echo "$total_users * $daily_payout"|bc)
								total_number_coins=$(echo "$total_number_coins + $total_payout"|bc)
								focus_next_day=$(( focus + 86400 ))
								total_users_today=$(echo "${user_dates_list}"|awk -F. -v focus="${focus}" -v focus_next_day="${focus_next_day}" '$1 > focus && $1 < focus_next_day'|wc -l)
								total_users=$(( total_users + total_users_today ))
								if [ $counter -ge 2 ]
								then
									daily_payout=1
								fi
								counter=$(( counter + 1 ))
								focus=$(( focus + 86400 ))
							done

							###TOTAL NUMBER OF ASSETS######################
							total_number_assets=$(ls -1 ${script_path}/assets|wc -l)

							###TOTAL NUMBER OF PUBLIC KEYS#################
							total_number_users=$(ls -1 ${script_path}/keys|wc -l)

							###TOTAL NUMBER OF PRIVATE KEYS################
							total_number_users_local=$(ls -1 ${script_path}/control/keys/*.sct 2>/dev/null|wc -l)

							###TOTAL NUMBER OF TRANSACTIONS################
							total_number_trx=$(grep -s -l "ASST:${cmd_asset}" ${script_path}/trx/*|wc -l)

							###TOTAL NUMBER OF TRANSACTIONS TODAY##########
							total_number_trx_today=$(grep -s -l "ASST:${cmd_asset}" ${script_path}/trx/*|awk -F. -v date_stamp=$(date -u +%s --date="$(date +%Y%m%d)") -v date_stamp_tomorrow="$(( $(date -u +%s --date="$(date +%Y%m%d)") + 86400 ))" '$2 > date_stamp && $2 < date_stamp_tomorrow'|wc -l)

							###TRANSACTION VOLUME TOTAL####################
							total_volume_trx=0
							for amount in $(grep "AMNT:" /dev/null $(grep -s -l "ASST:${cmd_asset}" ${script_path}/trx/*)|cut -d ':' -f4)
							do
								total_volume_trx=$(echo "scale=9;$total_volume_trx + $amount"|bc|sed 's/^\./0./g')
							done

							###TRANSACTION VOLUME TODAY####################
							total_volume_trx_today=0
							for trx in $(grep -s -l "ASST:${cmd_asset}" ${script_path}/trx/*|awk -F. -v date_stamp=$(date -u +%s --date="$(date +%Y%m%d)") -v date_stamp_tomorrow="$(( $(date -u +%s --date="$(date +%Y%m%d)") + 86400 ))" '$2 > date_stamp && $2 < date_stamp_tomorrow')
							do
								amount=$(grep "AMNT:" "${trx}"|cut -d ':' -f3)
								total_volume_trx_today=$(echo "scale=9;$total_volume_trx_today + $amount"|bc|sed 's/^\./0./g')
							done

							if [ $gui_mode = 1 ]
							then
								###IF GUI MODE DISPLAY STATISTICS##############
								dialog_statistic_display=$(echo $dialog_statistic|sed -e "s/<total_number_coins>/${total_number_coins}/g" -e "s/<total_number_assets>/${total_number_assets}/g" -e "s/<total_number_users>/${total_number_users}/g" -e "s/<total_number_users_local>/${total_number_users_local}/g" -e "s/<total_number_trx>/${total_number_trx}/g" -e "s/<total_number_trx_today>/${total_number_trx_today}/g" -e "s/<total_volume_trx>/${total_volume_trx}/g" -e "s/<total_volume_trx_today>/${total_volume_trx_today}/g")
								dialog --title "$dialog_stats" --backtitle "$core_system_name $core_system_version" --msgbox "$dialog_statistic_display" 0 0
							else
								###IF CMD MODE DISPLAY STATISTICS##############
								echo "TOTAL_NUMBER_COINS      :${total_number_coins}"
								echo "TOTAL_NUMBER_ASSETS     :${total_number_assets}"
								echo "TOTAL_NUMBER_USERS      :${total_number_users}"
								echo "TOTAL_NUMBER_USERS_LOCAL:${total_number_users_local}"
								echo "TOTAL_NUMBER_TRX        :${total_number_trx}"
								echo "TOTAL_NUMBER_TRX_TODAY  :${total_number_trx_today}"
								echo "TOTAL_VOLUME_TRX        :${total_volume_trx}"
								echo "TOTAL_VOLUME_TRX_TODAY  :${total_volume_trx_today}"
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
