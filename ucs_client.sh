#!/bin/sh
login_account(){
		login_name=$1
		login_pin=$2
		login_password=$3
		account_found=0
		handover_account=""

		###READ LIST OF KEYS LINE BY LINE############################
		for key_file in `ls -1 ${script_path}/keys/|sort -t . -k2`
		do
			###EXTRACT KEY DATA##########################################
			keylist_name=`echo $key_file|cut -d '.' -f1`
			keylist_stamp=`echo $key_file|cut -d '.' -f2`
			if [ ! "${cmd_sender}" = "" ]
			then
				keylist_hash=`echo $cmd_sender|cut -d '.' -f1`
			else
				keylist_hash=`echo "${login_name}_${keylist_stamp}_${login_pin}"|sha256sum|cut -d ' ' -f1`
			fi
			#############################################################

			###IF ACCOUNT MATCHES########################################
			if [ $keylist_name = $keylist_hash ]
			then
				account_found=1
				echo "${keylist_hash}.${keylist_stamp}" >>${script_path}/logon_${my_pid}.tmp
			fi
			##############################################################
		done
		#############################################################

		###CHECK IF ACCOUNT HAS BEEN FOUND###########################
		if [ $account_found = 1 ]
		then
			for each_user in `cat ${script_path}/logon_${my_pid}.tmp`
			do
				handover_account=$each_user
				if [ ! -d ${script_path}/userdata/${handover_account} ]
				then
					mkdir ${script_path}/userdata/${handover_account}
					mkdir ${script_path}/userdata/${handover_account}/temp
					mkdir ${script_path}/userdata/${handover_account}/temp/keys
					mkdir ${script_path}/userdata/${handover_account}/temp/proofs
					mkdir ${script_path}/userdata/${handover_account}/temp/trx
				else
	       	 			rm ${user_path}/account.acc.gpg 2>/dev/null
					rm ${user_path}/account.acc 2>/dev/null
				fi
				user_path="${script_path}/userdata/${handover_account}"

				###TEST KEY BY ENCRYPTING A MESSAGE##########################
				echo $login_name >${user_path}/account.acc
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --local-user ${handover_account} -r ${handover_account} --passphrase ${login_password} --pinentry-mode loopback --encrypt --sign ${user_path}/account.acc 1>/dev/null 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###REMOVE ENCRYPTION SOURCE FILE#############################
					rm ${user_path}/account.acc

					####TEST KEY BY DECRYPTING THE MESSAGE#######################
					gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase ${login_password} --pinentry-mode loopback --output ${user_path}/account.acc --decrypt ${user_path}/account.acc.gpg 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						extracted_name=`cat ${user_path}/account.acc`
						if [ "${extracted_name}" = "${login_name}" ]
						then
							user_logged_in=1
							break
						fi
					fi
				fi
			done
			if [ $user_logged_in = 1 ]
			then
				if [ $gui_mode = 1 ]
				then
					###IF SUCCESSFULL DISPLAY WELCOME MESSAGE AND SET LOGIN VARIABLE###########
					dialog_login_welcome_display=`echo $dialog_login_welcome|sed "s/<login_name>/${login_name}/g"`
					dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --infobox "$dialog_login_welcome_display" 0 0
					sleep 1
				fi
			else
				if [ $gui_mode = 1 ]
				then
					###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND###############
					dialog_login_nokey_display="${dialog_login_nokey} (-> ${login_name})!"
					dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name" --msgbox "$dialog_login_nokey_display" 0 0
					clear
				else
					exit 1
				fi
			fi
		else
			if [ $gui_mode = 1 ]
			then
				###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND###############
				dialog_login_nokey2_display=`echo $dialog_login_nokey2|sed "s/<account_name>/${login_name}/g"`
				dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name" --msgbox "$dialog_login_nokey2_display" 0 0
				clear
			else
				exit 1
			fi
		fi
		rm ${user_path}/message_blank.dat.gpg 2>/dev/null
		rm ${user_path}/account.acc.gpg 2>/dev/null
		rm ${user_path}/account.acc 2>/dev/null
		action_done=1
		make_ledger=1
		rm ${script_path}/logon_${my_pid}.tmp 2>/dev/null
}
create_keys(){
		create_name=$1
		create_pin=$2
		create_password=$3

		###SET REMOVE TRIGGER TO 0###################################
		key_remove=0

		###SET FILESTAMP TO NOW######################################
		file_stamp=`date +%s`

		###CREATE ADDRESS BY HASHING NAME,STAMP AND PIN##############
		create_name_hashed=`echo "${create_name}_${file_stamp}_${create_pin}"|sha256sum|cut -d ' ' -f1`

		if [ $gui_mode = 1 ]
		then
			###DISPLAY PROGRESS BAR######################################
			echo "0"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create1" 0 0 0
		fi

		###GENERATE KEY##############################################
		gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --no-default-keyring --keyring=${script_path}/control/keyring.file --passphrase ${create_password} --pinentry-mode loopback --quick-gen-key ${create_name_hashed}.${file_stamp} rsa4096 sign,auth,encr none 1>/dev/null 2>/dev/null
		rt_query=$?
		if [ $rt_query = 0 ]
		then
			if [ $gui_mode = 1 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR############################
				echo "33"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create2" 0 0 0
			fi

			###CREATE USER DIRECTORY AND SET USER_PATH###########
			mkdir ${script_path}/userdata/${create_name_hashed}.${file_stamp}
			mkdir ${script_path}/userdata/${create_name_hashed}.${file_stamp}/temp
			mkdir ${script_path}/userdata/${create_name_hashed}.${file_stamp}/temp/keys
			mkdir ${script_path}/userdata/${create_name_hashed}.${file_stamp}/temp/proofs
			mkdir ${script_path}/userdata/${create_name_hashed}.${file_stamp}/temp/trx
			user_path="${script_path}/userdata/${create_name_hashed}.${file_stamp}"

			###EXPORT PUBLIC KEY#########################################
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_pin}_${file_stamp}_pub.asc --passphrase ${create_password} --pinentry-mode loopback --export ${create_name_hashed}.${file_stamp}
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				if [ $gui_mode = 1 ]
				then
					###DISPLAY PROGRESS ON STATUS BAR############################
					echo "66"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create3" 0 0 0

					###CLEAR SCREEN
					clear
				fi

				###EXPORT PRIVATE KEY########################################
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${create_name_hashed}_${create_pin}_${file_stamp}_priv.asc --pinentry-mode loopback --passphrase ${create_password} --export-secret-keys ${create_name_hashed}.${file_stamp}
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###STEP INTO USER DIRECTORY##################################
					cd ${user_path}

					###CREATE TSA QUERY FILE#####################################
					openssl ts -query -data ${user_path}/${create_name_hashed}_${create_pin}_${file_stamp}_pub.asc -no_nonce -sha512 -out ${user_path}/${default_tsa}.tsq 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###GET TSA DATA##############################################
						tsa_config_line=`grep "${default_tsa}" ${script_path}/control/tsa.conf`
						tsa_connect_string=`echo "${tsa_config_line}"|cut -d ',' -f5`

						###SENT QUERY TO TSA#########################################
						curl --silent -H "Content-Type: application/timestamp-query" --data-binary @${default_tsa}.tsq ${tsa_connect_string} >${user_path}/${default_tsa}.tsr
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###STEP INTO CERTS DIRECTORY#################################
							cd ${script_path}/certs

							###DOWNLOAD LATEST TSA CERTIFICATES##########################
							tsa_cert_url=`echo "${tsa_config_line}"|cut -d ',' -f2`
							wget -q -O tsa.crt ${tsa_cert_url}
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								tsa_cert_url=`echo "${tsa_config_line}"|cut -d ',' -f3`
								wget -q -O cacert.pem ${tsa_cert_url}
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									mv ${script_path}/certs/tsa.crt ${script_path}/certs/${default_tsa}/tsa.crt
									mv ${script_path}/certs/cacert.pem ${script_path}/certs/${default_tsa}/cacert.pem
									openssl ts -verify -queryfile ${user_path}/${default_tsa}.tsq -in ${user_path}/${default_tsa}.tsr -CAfile ${script_path}/certs/${default_tsa}/cacert.pem -untrusted ${script_path}/certs/${default_tsa}/tsa.crt 1>/dev/null 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										if [ $gui_mode = 1 ]
										then
											###DISPLAY PROGRESS ON STATUS BAR############################
											echo "100"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create4" 0 0 0
											clear
										fi
										###CREATE PROOFS DIRECTORY AND COPY TSA FILES###################
										mkdir ${script_path}/proofs/${create_name_hashed}.${file_stamp}
										mv ${user_path}/${default_tsa}.tsq ${script_path}/proofs/${create_name_hashed}.${file_stamp}/${default_tsa}.tsq
										mv ${user_path}/${default_tsa}.tsr ${script_path}/proofs/${create_name_hashed}.${file_stamp}/${default_tsa}.tsr

										###COPY EXPORTED PUB-KEY INTO KEYS-FOLDER#######################
										cp ${user_path}/${create_name_hashed}_${create_pin}_${file_stamp}_pub.asc ${script_path}/keys/${create_name_hashed}.${file_stamp}

										###COPY EXPORTED PRIV-KEY INTO CONTROL-FOLDER#######################
										cp ${user_path}/${create_name_hashed}_${create_pin}_${file_stamp}_priv.asc ${script_path}/control/keys/${create_name_hashed}.${file_stamp}

										if [ $gui_mode = 1 ]
										then
											###DISPLAY NOTIFICATION THAT EVERYTHING WAS FINE#############
											dialog_keys_final_display=`echo $dialog_keys_final|sed -e "s/<create_name>/${create_name}/g" -e "s/<create_name_hashed>/${create_name_hashed}.${file_stamp}/g" -e "s/<create_pin>/${create_pin}/g" -e "s/<file_stamp>/${file_stamp}/g"`
											dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_final_display" 0 0
											clear
										else
											echo "USER:${create_name}"
											echo "PIN:${create_pin}"
											echo "PASSWORD:>${create_password}<"
											echo "ADRESS:${create_name_hashed}.${file_stamp}"
											echo "KEY:${create_name_hashed}.${file_stamp}"
											echo "KEY_PUB:/keys/${create_name_hashed}.${file_stamp}"
											echo "KEY_PRV:/control/keys/${create_name_hashed}.${file_stamp}"
											exit 0
										fi
									else
										key_remove=1
									fi
								else
									key_remove=1
								fi
							else
								key_remove=1
							fi
						else
							key_remove=1
						fi
					else
						key_remove=1
					fi
				else
					key_remove=1
				fi
			else
				key_remove=1
			fi
		fi
		if [ ! $rt_query = 0 ]
		then
			if [ $key_remove = 1 ]
			then
				###REMOVE PROOFS DIRECTORY OF USER###########################
				rm -r ${script_path}/proofs/${create_name_hashed}.${file_stamp} 2>/dev/null

				###REMOVE USERDATA DIRECTORY OF USER#########################
				rm -r ${script_path}/userdata/${create_name_hashed}.${file_stamp} 2>/dev/null

				###REMOVE KEYS FROM KEYRING##################################
				key_fp=`gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${create_name_hashed}.${file_stamp}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
					gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-keys ${key_fp} 2>/dev/null
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
				printf "${transaction_message}" >>${message_blank}
				#################################################################
			else
				###IF YES.....###################################################
				message=${script_path}/proofs/${handover_account}/${handover_account}.txt
				message_blank=${user_path}/message_blank.dat
				touch ${message_blank}
				for key_file in `cat ${user_path}/all_accounts.dat`
				do
					###WRITE KEYFILE TO INDEX FILE###################################
					key_hash=`sha256sum ${script_path}/keys/${key_file}|cut -d ' ' -f1`
					echo "keys/${key_file} ${key_hash}" >>${message_blank}
					#################################################################

					for tsa_service in `ls -1 ${script_path}/certs`
					do
						###IF TSA QUERY FILE IS AVAILABLE ADD TO INDEX FILE#############
						tsa_qfile="${script_path}/proofs/${key_file}/${tsa_service}.tsq"
						if [ -s $tsa_qfile ]
						then
							tsa_qfile_path="proofs/${key_file}/${tsa_service}.tsq"
							tsa_qfile_hash=`sha256sum ${script_path}/proofs/${key_file}/${tsa_service}.tsq|cut -d ' ' -f1`
							echo "${tsa_qfile_path} ${tsa_qfile_hash}" >>${message_blank}
						fi
						#################################################################

						###IF TSA RESPONSE FILE IS AVAILABLE ADD TO INDEX FILE###########
						tsa_rfile="${script_path}/proofs/${key_file}/${tsa_service}.tsr"
						if [ -s $tsa_rfile ]
						then
							tsa_rfile_path="proofs/${key_file}/${tsa_service}.tsr"
							tsa_rfile_hash=`sha256sum ${script_path}/proofs/${key_file}/${tsa_service}.tsr|cut -d ' ' -f1`
							echo "${tsa_rfile_path} ${tsa_rfile_hash}" >>${message_blank}
						fi
						#################################################################
					done
				done

				####WRITE TRX LIST TO INDEX FILE#################################
				cat ${user_path}/index_trx.dat >>${message_blank}
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
				signed_correct=`grep "GOODSIG" ${user_path}/gpg_verify.tmp|grep -c "${user_signed}"`
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
		length_counter=`echo "${input_string}"|wc -m`

		###IF INPUT LESS OR EQUAL 1 DISPLAY NOTIFICATION#######################
		if [ $length_counter -le 1 ]
		then
			if [ $gui_mode = 1 ]
			then
				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_check_msg2" 0 0
				rt_query=1
			else
				exit 1
			fi
		fi
		#######################################################################

		case $check_mode in
			 0 )	###CHECK IF ONLY CHARS ARE IN INPUT STRING###################
				string_check=`echo "${input_string}"|grep -c '[^[:alnum:]]'`

				###IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION##############
				if [ $string_check = 1 ]
				then
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_check_msg3" 0 0
						rt_query=1
					else
						exit 1
					fi
				fi
				;;
			1 )	###CHECK IF ONLY DIGITS ARE IN INPUT STRING############################
				string_check=`echo "${input_string}"|grep -c '[^[:digit:]]'`

				###IF NOT CHECK IF ALPHA NUM ARE IN INPUT STRING#######################
				if [ string_check = 0 ]
				then
					###CHECK IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION########
					string_check=`echo "${input_string}"|grep -c '[^[:alnum:]]'`
				fi

				###IF DIGIT CHECK FAILS DISPLAY NOTIFICATION###########################
				if [ $string_check = 1 ]
				then
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_check_msg1" 0 0
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
		now=`date -u +%Y%m%d`
		start_date="20210216"

		###CHECK IF OLD LEDGER THERE########################
		old_ledger_there=`ls -1 ${user_path}/|grep -c "ledger.dat"`

		###CHECK IF OLD SCORETABLE IS THERE#################
		old_scoretable_there=`ls -1 ${user_path}/|grep -c "scoretable.dat"`

		if [ $old_ledger_there -gt 0 -a $old_scoretable_there = 1 -a $new = 0 ]
		then
			###GET LATEST LEDGER AND EXTRACT DATE###############
			last_ledger=`ls -1 ${user_path}/|grep "ledger.dat"|sort -t _ -k1|tail -1`
			last_ledger_date=`echo $last_ledger|cut -d '_' -f1`
			last_ledger_date_stamp=`date -u +%s --date="${last_ledger_date}"`

			###SET DATESTAMP TO NEXTDAY OF LAST LEDGER##########
			date_stamp=$(( $last_ledger_date_stamp + 86400 ))

			###MOVE LEDGER######################################
			mv ${user_path}/${last_ledger_date}_ledger.dat ${user_path}/${now}_ledger.dat 2>/dev/null

			###CALCULATE DAY COUNTER############################
			date_stamp_last=`date -u +%s --date="${start_date}"`
			no_seconds_last=$(( $date_stamp - $date_stamp_last ))
			day_counter=`expr $no_seconds_last / 86400`
		else
			###SET DATESTAMP####################################
			date_stamp=`date -u +%s --date=$(date -u +%Y%m%d --date=@$(sort -t . -k2 ${user_path}/depend_accounts.dat|head -1|cut -d '.' -f2))`

			###EMPTY LEDGER#####################################
			rm ${user_path}/*_ledger.dat 2>/dev/null
			touch ${user_path}/${now}_ledger.dat
			####################################################

			###EMPTY SCORE TABLE################################
			rm ${user_path}/scoretable.dat 2>/dev/null
			touch ${user_path}/scoretable.dat

			###EMPTY INDEX FILE#################################
			rm ${user_path}/index_trx.dat 2>/dev/null
			touch ${user_path}/index_trx.dat
			####################################################

			###EMPTY IGNORE TRX#################################
			rm ${user_path}/ignored_trx.dat 2>/dev/null
			####################################################

			###CALCULATE DAY COUNTER############################
			date_stamp_last=`date -u +%s --date="${start_date}"`
			no_seconds_last=$(( $date_stamp_last - $date_stamp ))
			day_counter=`expr $no_seconds_last / 86400`
			day_counter=$(( $day_counter + 1 ))
		fi
		####################################################

		###SET FOCUS########################################
		focus=`date -u +%Y%m%d --date=@${date_stamp}`
		now_stamp=`date +%s`
		months=0
		####################################################

		if [ $focus -le $now ]
		then
			###INIT STATUS BAR##################################
			now_date_status=`date -u +%s --date=${now}`
			now_date_status=$(( $now_date_status + 86400 ))
			no_seconds_total=$(( $now_date_status - $date_stamp ))
			no_days_total=`expr $no_seconds_total / 86400`
			percent_per_day=`echo "scale=10; 100 / ${no_days_total}"|bc`
			current_percent=0
			current_percent_display=0
			current_percent=`echo "scale=10;${current_percent} + ${percent_per_day}"|bc`
			current_percent_display=`echo "${current_percent} / 1"|bc`
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
			current_percent=`echo "scale=10;${current_percent} + ${percent_per_day}"|bc`
			current_percent_display=`echo "${current_percent} / 1"|bc`
			#################################################

			###CALCULATE CURRENT COINLOAD####################
			if [ $day_counter = 2 ]
			then
				coinload=$initial_coinload
			else
				coinload=1
			fi
			#################################################

			###GRANT COINLOAD OF THAT DAY####################
			awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' ${user_path}/${now}_ledger.dat >${user_path}/${now}_ledger.tmp
			if [ -s ${user_path}/${now}_ledger.tmp ]
			then
				mv ${user_path}/${now}_ledger.tmp ${user_path}/${now}_ledger.dat 2>/dev/null
			fi

			###UPDATE SCORETABLE#############################
			awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' ${user_path}/scoretable.dat >${user_path}/scoretable.tmp
			if [ -s ${user_path}/scoretable.dat ]
			then
				mv ${user_path}/scoretable.tmp ${user_path}/scoretable.dat 2>/dev/null
			fi

			###CREATE LIST OF ACCOUNTS CREATED THAT DAY######
			date_stamp_tomorrow=$(( $date_stamp + 86400 ))
			awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 > date_stamp && $2 < date_stamp_tomorrow' ${user_path}/depend_accounts.dat >${user_path}/accounts.tmp

			###CREATE LEDGER AND SCORETABEL ENTRY############
			awk -F. '{print $1"."$2"=0"}' ${user_path}/accounts.tmp >>${user_path}/${now}_ledger.dat
			awk -F. '{print $1"."$2"=0"}' ${user_path}/accounts.tmp >>${user_path}/scoretable.dat
			rm ${user_path}/accounts.tmp 2>/dev/null

			###GO TROUGH TRX OF THAT DAY LINE BY LINE#####################
			for trx_filename in `awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$3 > date_stamp && $3 < date_stamp_tomorrow' ${user_path}/depend_trx.dat` 
			do
				###EXRACT DATA FOR CHECK######################################
				trx_stamp=`echo $trx_filename|cut -d '.' -f3`
				trx_sender=`sed -n '6p' ${script_path}/trx/${trx_filename}|cut -d ':' -f2`
				trx_receiver=`sed -n '7p' ${script_path}/trx/${trx_filename}|cut -d ':' -f2`
				trx_hash=`sha256sum ${script_path}/trx/${trx_filename}|cut -d ' ' -f1`
				trx_path="trx/${trx_filename}"
				##############################################################

				###CHECK IF INDEX-FILE EXISTS#################################
				if [ -s ${script_path}/proofs/${trx_sender}/${trx_sender}.txt -o $trx_sender = ${handover_account} ]
				then
					###CHECK IF TRX IS SIGNED BY USER#############################
					is_signed=`grep -c "trx/${trx_filename} ${trx_hash}" ${script_path}/proofs/${trx_sender}/${trx_sender}.txt`
					if [ $is_signed -gt 0 -o $trx_sender = $handover_account ]
					then
						###EXTRACT TRX DATA###########################################
						trx_amount=`sed -n '5p' ${script_path}/trx/${trx_filename}|cut -d ':' -f2`
						account_balance=`grep "${trx_sender}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
						##############################################################

						###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
						account_check_balance=`echo "${account_balance} - ${trx_amount}"|bc`
						enough_balance=`echo "${account_check_balance} >= 0"|bc`
						##############################################################

						###SCORING####################################################
						sender_score_balance=`grep "${trx_sender}" ${user_path}/scoretable.dat|cut -d '=' -f2`
						is_score_ok=`echo "${sender_score_balance} >= ${trx_amount}"|bc`
						##############################################################

						###CHECK IF BALANCE AND SCORE ARE OK##########################
						if [ $enough_balance = 1 -a $is_score_ok = 1 ]
						then
							####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)############
							echo "${trx_path} ${trx_hash}" >>${user_path}/index_trx.dat
							##############################################################

							###SET BALANCE FOR SENDER#####################################
							account_new_balance=$account_check_balance
							is_greater_one=`echo "${account_new_balance} >= 1"|bc`
							if [ $is_greater_one = 0 ]
							then
								account_new_balance="0${account_new_balance}"
							fi
							sed -i "s/${trx_sender}=${account_balance}/${trx_sender}=${account_new_balance}/g" ${user_path}/${now}_ledger.dat
							##############################################################

							###SET SCORE FOR SENDER#######################################
							sender_new_score_balance=`echo "${sender_score_balance} - ${trx_amount}"|bc`
							is_greater_one=`echo "${sender_new_score_balance} >= 1"|bc`
							if [ $is_greater_one = 0 ]
							then
								sender_new_score_balance="0${sender_new_score_balance}"
							fi
							sed -i "s/${trx_sender}=${sender_score_balance}/${trx_sender}=${sender_new_score_balance}/g" ${user_path}/scoretable.dat
							##############################################################

							###CHECK CONFIRMATIONS########################################
							total_confirmations=`grep -l "trx/${line} ${trx_hash}" ${script_path}/proofs/*.*/*.txt|grep -v "${handover_account}\|${trx_sender}"|wc -l`
							if [ $total_confirmations -ge $confirmations_from_users ]
							then
								receiver_in_ledger=`grep -c "${trx_receiver}" ${user_path}/${now}_ledger.dat`
								if [ $receiver_in_ledger = 1 ]
								then
									###SET SCORE FOR SENDER#######################################
									sed -i "s/${trx_sender}=${sender_new_score_balance}/${trx_sender}=${sender_score_balance}/g" ${user_path}/scoretable.dat
									##############################################################
									###SET BALANCE FOR RECEIVER###################################
									receiver_old_balance=`grep "${trx_receiver}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
									receiver_new_balance=`echo "${receiver_old_balance} + ${trx_amount}"|bc`
									is_greater_one=`echo "${receiver_new_balance} >= 1"|bc`
									if [ $is_greater_one = 0 ]
									then
										receiver_new_balance="0${receiver_new_balance}"
									fi
									sed -i "s/${trx_receiver}=${receiver_old_balance}/${trx_receiver}=${receiver_new_balance}/g" ${user_path}/${now}_ledger.dat
									##############################################################
								fi
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
			date_stamp=$(( $date_stamp + 86400 ))
			focus=`date -u +%Y%m%d --date=@${date_stamp}`
			day_counter=$(( $day_counter + 1 ))
			##############################################################
		done|dialog --title "$dialog_ledger_title" --backtitle "$core_system_name" --gauge "$dialog_ledger" 0 0 0 2>/dev/null 1>&${progress_bar_redir}
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
			esac
			if [ $show_balance = 1 ]
			then
				cmd_output=`grep "${handover_account}" ${user_path}/${now}_ledger.dat`
				echo "BALANCE_${now_stamp}:${cmd_output}"
				cmd_output=`grep "${handover_account}" ${user_path}/scoretable.dat`
				echo "UNLOCKED_BALANCE_${now_stamp}:${cmd_output}"
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
				sort ${user_path}/tar_check_temp.tmp|uniq >${user_path}/tar_check_full.tmp

				###WRITE FILE LIST############################################
				awk '{print $6}' ${user_path}/tar_check_full.tmp >${user_path}/tar_check.tmp

				###CHECK FOR EXECUTABLES######################################
				executables_there=`awk '{print $1}' ${user_path}/tar_check_full.tmp|grep -v "d"|grep -c "x"`
				if [ $executables_there -eq 0 ]
				then
					###CHECK FOR BAD CHARACTERS###################################
					bad_chars_there=`cat ${user_path}/tar_check.tmp|sed 's#/##g'|sed 's/\.//g'|grep -c '[^[:alnum:]]'`
					if [ $bad_chars_there -eq 0 ]
					then
						files_not_homedir=""

						###GO THROUGH CONTENT LIST LINE BY LINE#######################
						while read line
						do
							###CHECK IF FILES MATCH TARGET-DIRECTORIES AND IGNORE OTHERS##
							files_not_homedir=`echo $line|cut -d '/' -f1`
							case $files_not_homedir in
								"keys")		if [ ! -d ${script_path}/$line ]
										then
											file_full=`echo $line|cut -d '/' -f2`
											file_ext=`echo $file_full|cut -d '.' -f2`
											file_ext_correct=`echo $file_ext|grep -c '[^[:digit:]]'`
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
			       					"trx")		if [ ! -d ${script_path}/$line ]
										then
											file_full=`echo $line|cut -d '/' -f2`
											file_ext=`echo $file_full|cut -d '.' -f2`
											file_ext_correct=`echo $file_ext|grep -c '[^[:digit:]]'`
											if [ $file_ext_correct -gt 0 ]
											then
												rt_query=1
											else
												file_ext=`echo $file_full|cut -d '.' -f3`
												file_ext_correct=`echo $file_ext|grep -c '[^[:digit:]]'`
												if [ $file_ext_correct = 0 ]
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
												else
													rt_query=1
												fi
											fi
										fi
					       					;;
								"proofs")	if [ ! -d ${script_path}/$line ]
										then
											file_usr=`echo $line|cut -d '/' -f2`
											file_usr_correct=`echo $file_usr|cut -d '.' -f2|grep -c '[^[:digit:]]'`
											if [ $file_usr_correct = 0 ]
											then	
												file_full=`echo $line|cut -d '/' -f3`
												file_ext=`echo $line|cut -d '/' -f3|cut -d '.' -f2`
												case $file_ext in
													"tsq")	tsa_name=`echo $line|cut -d '/' -f3|cut -d '.' -f1`
														for tsa_service in `ls -1 ${script_path}/certs`
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
													"tsr")	tsa_name=`echo $line|cut -d '/' -f3|cut -d '.' -f1`
														for tsa_service in `ls -1 ${script_path}/certs`
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
check_tsa(){
			cd ${script_path}/certs

			###SET NOW STAMP#########
			now_stamp=`date +%s`

			###PURGE OLD TMP FILES###
			rm ${script_path}/certs/*.crt 2>/dev/null
			rm ${script_path}/certs/*.crl 2>/dev/null
			rm ${script_path}/certs/*.pem 2>/dev/null

			###FOR EACH TSA-SERVICE IN CERTS/-FOLDER#################
			for tsa_service in `ls -1 ${script_path}/certs`
			do
				###VARIABLE FOR TSA CERTIFICATE DOWNLOAD CHECK###########
				tsa_update_required=0
				tsa_available=0
				tsa_cert_available=0
				tsa_rootcert_available=0
				crl_retry_counter=0
				retry_counter=0
				while [ $tsa_available = 0 ]
				do
					###IF TSA.CRT NOT AVAILABLE...############
					if [ -s ${script_path}/certs/${tsa_service}/tsa.crt ]
					then
						old_cert_valid_from=`date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -noout -dates|grep "notBefore"|cut -d '=' -f2)"`
						old_cert_valid_till=`date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -noout -dates|grep "notAfter"|cut -d '=' -f2)"`
						if [ $now_stamp -gt $old_cert_valid_from -a $now_stamp -lt $old_cert_valid_till ]
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
						###GET URL FROM TSA.CONF#################
						tsa_cert_url=`grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f2`

						###DOWNLOAD TSA.CRT######################
						wget -q -O tsa.crt ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							new_cert_valid_from=`date +%s --date="$(openssl x509 -in ${script_path}/certs/tsa.crt -noout -dates|grep "notBefore"|cut -d '=' -f2)"`
							new_cert_valid_till=`date +%s --date="$(openssl x509 -in ${script_path}/certs/tsa.crt -noout -dates|grep "notAfter"|cut -d '=' -f2)"`
							if [ $now_stamp -gt $new_cert_valid_from -a $now_stamp -lt $new_cert_valid_till ]
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

					###IF CACERT.PEM NOT AVAILABLE...#########
					if [ -s ${script_path}/certs/${tsa_service}/cacert.pem ]
					then
						old_cert_valid_from=`date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/cacert.pem -noout -dates|grep "notBefore"|cut -d '=' -f2)"`
						old_cert_valid_till=`date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/cacert.pem -noout -dates|grep "notAfter"|cut -d '=' -f2)"`
						if [ $now_stamp -gt $old_cert_valid_from -a $now_stamp -lt $old_cert_valid_till ]
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
						###GET URL FROM TSA.CONF#################
						tsa_cert_url=`grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f3`

						###DOWNLOAD CACERT.PEM####################
						wget -q -O cacert.pem ${tsa_cert_url}
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							new_cert_valid_from=`date +%s --date="$(openssl x509 -in ${script_path}/certs/cacert.pem -noout -dates|grep "notBefore"|cut -d '=' -f2)"`
							new_cert_valid_till=`date +%s --date="$(openssl x509 -in ${script_path}/certs/cacert.pem -noout -dates|grep "notAfter"|cut -d '=' -f2)"`
							if [ $now_stamp -gt $new_cert_valid_from -a $now_stamp -lt $new_cert_valid_till ]
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

					###IF BOTH TSA.CRT AND CACERT.PEM ARE THERE SET FLAG####################
					if [ $tsa_cert_available = 1 -a $tsa_rootcert_available = 1 ]
					then
						###GET TSA CRL URL FIRST BY CRT THEN BY CONFIG#######
						tsa_crl_url=""
						tsa_crl_url=`openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -text -noout|grep -A4 "X509v3 CRL Distribution Points:"|grep "URI"|awk -F: '{print $2":"$3}'`
						if [ "${tsa_crl_url}" = "" ]
						then
							###GET CRL URL FROM TSA.CONF#################
							tsa_crl_url=`grep "${tsa_service}" ${script_path}/control/tsa.conf|cut -d ',' -f4`
							if [ "${tsa_crl_url}" = "" ]
							then
								###IF NO CRL IS THERE###################
								tsa_available=1
							fi
						fi
						if [ $tsa_available = 0 ]
						then
							###DOWNLOAD CRL FILE####################
							wget -q -O root_ca.crl ${tsa_crl_url}
							if [ -s ${script_path}/certs/root_ca.crl ]
							then
								###CHECK IF OLD CRL IS THERE############
								if [ -s ${script_path}/certs/${tsa_service}/root_ca.crl ]
								then
									###GET CRL DATES########################
									crl_old_valid_from=`date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)"`
									crl_old_valid_till=`date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)"`
									crl_new_valid_from=`date +%s --date="$(openssl crl -in ${script_path}/certs/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)"`
									crl_new_valid_till=`date +%s --date="$(openssl crl -in ${script_path}/certs/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)"`
									
									###COMPARE VALID FROM AND VALID TILL####
									if [ $crl_old_valid_from -eq $crl_new_valid_from -a $crl_old_valid_till -eq $crl_new_valid_till ]
									then
										###GET HASHES TO COMPARE################
										new_crl_hash=`sha224sum ${script_path}/certs/root_ca.crl|cut -d ' ' -f1`
										old_crl_hash=`sha224sum ${script_path}/certs/${tsa_service}/root_ca.crl|cut -d ' ' -f1`
										if [ ! "${new_crl_hash}" = "${old_crl_hash}" ]
										then
											mv ${script_path}/certs/root_ca.crl ${script_path}/certs/${tsa_service}/root_ca.crl
										fi
									else
										###UNCOMMENT TO ENABLE SAVESTORE OF CRL#
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
								crl_valid_from=`date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Last Update:"|cut -c 22-45)"`
								crl_valid_till=`date +%s --date="$(openssl crl -in ${script_path}/certs/${tsa_service}/root_ca.crl -text|grep "Next Update:"|cut -c 22-45)"`
								if [ $crl_valid_from -lt $now_stamp -a $crl_valid_till -gt $now_stamp ]
								then
									cat ${script_path}/certs/${tsa_service}/cacert.pem ${script_path}/certs/${tsa_service}/root_ca.crl >${script_path}/certs/${tsa_service}/crl_chain.pem
									openssl verify -crl_check -CAfile ${script_path}/certs/${tsa_service}/crl_chain.pem ${script_path}/certs/${tsa_service}/tsa.crt >/dev/null 2>/dev/null
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										tsa_available=1
									else
										tsa_update_required=1
										if [ $crl_retry_counter = 1 ]
										then
											cert_valid_from=`date +%s --date="$(openssl x509 -in ${script_path}/certs/${tsa_service}/tsa.crt -text -noout|grep -A2 "Validity"|grep "Not Before"|cut -c 25-48)"`
											mv ${script_path}/certs/${tsa_service}/tsa.crt ${script_path}/certs/${tsa_service}/tsa.${cert_valid_from}-${crl_valid_from}.crt
											tsa_available=1
										fi
										crl_retry_counter=$(( $crl_retry_counter + 1 ))
									fi
								else
									tsa_available=1
								fi	
							fi
						fi
					else
						retry_counter=$(( $retry_counter + 1 ))
						if [ $retry_counter -le $retry_limit ]
						then
							sleep $retry_wait_seconds
						else
							if [ $gui_mode = 1 ]
							then
								dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --infobox "$dialog_no_network" 0 0
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
			flock ${script_path}/keys ls -1 ${script_path}/keys|sort -t . -k2 >${user_path}/all_accounts.dat
			cat ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat|sort -t . -k2|uniq -u >${user_path}/all_accounts.tmp
			while read line
			do
				###SET FLAG##############################################
				account_verified=0

				###CHECK IF KEY-FILENAME IS EQUAL TO NAME INSIDE KEY#####
				accountname_key_name=`echo $line`
				accountname_key_stamp=`echo $line|cut -d '.' -f2`
				accountname_key_content=`gpg --list-packets ${script_path}/keys/${line}|grep "user ID"|awk '{print $4}'|sed 's/"//g'`
				if [ $accountname_key_name = $accountname_key_content ]
				then
					###CHECK IF TSA QUERY AND RESPONSE ARE THERE#############
					if [ -s ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsq -a -s ${script_path}/proofs/${accountname_key_name}/${tsa_service}.tsr ]
					then
						###FOR EACH TSA-SERVUCE IN CERTS/-FOLDER#################
						for tsa_service in `ls -1 ${script_path}/certs`
						do
							cacert_file_found=0
							for cacert_file in `ls -1 ${script_path}/certs/${tsa_service}/cacert.*`
							do
								for crt_file in `ls -1 ${script_path}/certs/${tsa_service}/tsa.*`
								do
									###GET DATES FROM CERTIFICATE###########################
									crt_file_base=`basename ${crt_file}`
									if [ ! "${crt_file_base}" = "tsa.crt" ]
									then
										valid_from=`echo $crt_file_base|cut -d '.' -f2|cut -d '-' -f1`
										valid_till=`echo $crt_file_base|cut -d '.' -f2|cut -d '-' -f2`
									else
										valid_from=`date +%s --date="$(openssl x509 -in ${crt_file} -noout -dates|grep "notBefore"|cut -d '=' -f2)"`
										valid_till=`date +%s --date="$(openssl x509 -in ${crt_file} -noout -dates|grep "notAfter"|cut -d '=' -f2)"`
									fi

									###IF CERT WAS VALID AT TIMESTAMP OF ACCOUNT CREATION..##
									if [ $accountname_key_stamp -gt $valid_from -a $accountname_key_stamp -lt $valid_till ]
									then	 
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
													###CHECK IF TSA RESPONSE WAS CREATED WITHIN 120 SECONDS AFTER KEY CREATION###########
													date_to_verify=`grep "Time stamp:" ${user_path}/timestamp_check.tmp|cut -c 13-37`
													date_to_verify_converted=`date -u +%s --date="${date_to_verify}"`
													accountdate_to_verify=`echo $line|cut -d '.' -f2`
													creation_date_diff=$(( $date_to_verify_converted - $accountdate_to_verify ))
													if [ $creation_date_diff -ge 0 ]
													then
														if [ $creation_date_diff -le 120 ]
														then
															###SET VARIABLE THAT TSA HAS BEEN FOUND##################
															account_verified=1
			
															###STEP OUT OF LOOP CACERT_FILE##########################
															cacert_file_found=1
													
															###STEP OUT OF LOOP CRT_FILE#############################
															break
														fi
													fi
												fi
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
				user_path=`pwd`
				base_dir=`dirname $user_path`
				script_path=`dirname $base_dir`
				handover_account=`basename $user_path`
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
			cat ${user_path}/all_accounts.tmp ${user_path}/blacklisted_accounts.dat|sort -t . -k2|uniq -u >${user_path}/all_accounts.dat

			###ADD ACKNOWLEDGED ACCOUNTS TO FINAL LIST#########################
			cat ${user_path}/all_accounts.dat ${user_path}/ack_accounts.dat|sort -t . -k2 >${user_path}/all_accounts.tmp
			mv ${user_path}/all_accounts.tmp ${user_path}/all_accounts.dat
			rm ${user_path}/ack_accounts.dat
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
		cat ${user_path}/all_keys.dat ${user_path}/ack_keys.dat|sort -t . -k2|uniq -u >${user_path}/all_keys.tmp

		###CHECK KEYS IF ALREADY IN KEYRING AND IMPORT THEM IF NOT#########
		touch ${user_path}/keylist_gpg.tmp
		gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys >${user_path}/keylist_gpg.tmp 2>/dev/null
  	       	while read line
  	      	do
		       	key_uname=$line
 			key_imported=`grep -c "${key_uname}" ${user_path}/keylist_gpg.tmp`
			if [ $key_imported = 0 ]
	      		then
			       	gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/keys/${line} 2>/dev/null
	      			rt_query=$?
			       	if [ $rt_query -gt 0 ]
			       	then
					dialog_import_fail_display=`echo $dialog_import_fail|sed -e "s/<key_uname>/${key_uname}/g" -e "s/<file>/${line}/g"`
		       			dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_import_fail_display" 0 0
				       	key_already_blacklisted=`grep -c "${key_uname}" ${user_path}/blacklisted_accounts.dat`
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
			user_path=`pwd`
			base_dir=`dirname $user_path`
			script_path=`dirname $base_dir`
			handover_account=`basename $user_path`
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
		cat ${user_path}/all_keys.tmp ${user_path}/blacklisted_accounts.dat|sort -t . -k2|uniq -u >${user_path}/all_keys.dat

		###ADD ACKNOWLEDGED ACCOUNTS TO FINAL LIST#########################
		cat ${user_path}/all_keys.dat ${user_path}/ack_keys.dat|sort -t . -k2 >${user_path}/all_keys.tmp
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

		###CHECK IF INDEX/IGNORE/LEDGER THERE IF NOT BUILD LEDGE###########
		index_there=0
		ignore_there=0
		new_ledger=1
		total_ledgers=`ls -1 ${user_path}/|grep "_ledger.dat"|wc -l`
		if [ $total_ledgers -gt 0 ]
		then
			if [ -s ${script_path}/proofs/${handover_account}/${handover_account}.txt ]
			then
				new_ledger=0
				index_there=1
				if [ -s ${user_path}/ignored_trx.dat ]
				then
					ignore_there=1
				fi
			fi
		fi
		###################################################################

		###WRITE INITIAL LIST OF TRANSACTIONS TO FILE######################
		ls -1 ${script_path}/trx >${user_path}/trx_list_all.tmp
		while read line
		do
			grep "${line}" ${user_path}/trx_list_all.tmp >>${user_path}/all_trx.dat
		done <${user_path}/all_accounts.dat
		rm ${user_path}/trx_list_all.tmp 2>/dev/null
		###################################################################

		###SORT LIST OF TRANSACTION PER DATE###############################
		cat ${user_path}/all_trx.dat ${user_path}/ack_trx.dat|sort -t . -k3|uniq -u >${user_path}/all_trx.tmp

		###GO THROUGH TRANSACTIONS LINE PER LINE###########################
		while read line
		do
			###SET ACKNOWLEDGED VARIABLE###############################
			trx_acknowledged=0

			###CHECK IF HEADER MATCHES OWNER###################################
			file_to_check=${script_path}/trx/${line}
			user_to_check=`echo $line|awk -F. '{print $1"."$2}'`
			user_to_check_sender=`sed -n '6p' ${file_to_check}|cut -d ':' -f2`
			if [ $user_to_check = $user_to_check_sender ]
			then
				###VERIFY SIGNATURE OF TRANSACTION#################################
				verify_signature $file_to_check $user_to_check
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###CHECK IF DATE IN HEADER MATCHES DATE OF FILENAME################
					trx_date_filename=`echo $line|cut -d '.' -f3`
					trx_date_inside=`sed -n '4p' ${file_to_check}|cut -d ':' -f2`
					if [ $trx_date_filename = $trx_date_inside ]
					then
						###CHECK IF TRANSACTION WAS CREATED BEFORE RECEIVER EXISTED##############
						user_to_check_receiver_date=`echo $user_to_check|cut -d '.' -f2`
						if [ $trx_date_inside -gt $user_to_check_receiver_date ]
						then
							###CHECK IF PURPOSE CONTAINS ALNUM CHARS#################################
							trx_purpose=`sed -n '8p' ${file_to_check}|cut -d ':' -f2`
							purpose_contains_alnum=`printf "${trx_purpose}"|grep -c '[^[:alnum:]]'`
							if [ $purpose_contains_alnum = 0 ]
							then
								###CHECK IF USER HAS CREATED A INDEX FILE################################
								if [ -s ${script_path}/proofs/${user_to_check}/${user_to_check}.txt ]
								then
									####CHECK IF USER HAS INDEXED THE TRANSACTION############################
									is_trx_signed=`grep -c "trx/${line}" ${script_path}/proofs/${user_to_check}/${user_to_check}.txt`

									###CHECK IF AMOUNT IS MINIMUM 0.000000001################################
									trx_amount=`sed -n '5p' ${file_to_check}|cut -d ':' -f2`
									is_amount_ok=`echo "${trx_amount} >= 0.000000001"|bc`
									is_amount_mod=`echo "${trx_amount} % 0.000000001"|bc`
									is_amount_mod=`echo "${is_amount_mod} > 0"|bc`
									if [ $is_trx_signed = 0 -a $delete_trx_not_indexed = 1 -o $is_amount_ok = 0 -o $is_amount_mod = 1 ]
									then
										###DELETE IF NOT SIGNED AND DELETE_TRX_NOT_INDEX SET TO 1 IN CONFIG.CONF##
										rm $file_to_check 2>/dev/null
									else
										if [ $is_trx_signed = 1 ]
										then
											if [ $index_there = 1 ]
											then
												is_indexed=`grep -c "trx/${line}" ${script_path}/proofs/${handover_account}/${handover_account}.txt`
											else
												is_indexed=0
											fi
											if [ $is_indexed = 0 ]
											then
												if [ $ignore_there = 1 ]
												then
													is_ignored=`grep -c "${line}" ${user_path}/ignored_trx.dat`
													if [ $is_ignored = 0 ]
													then
														trx_acknowledged=1
													fi
												else
													trx_acknowledged=1
												fi
											else
												trx_acknowledged=1
											fi
										else
											if [ ${user_to_check} = ${handover_account} ]
											then
												trx_acknowledged=1
											fi
										fi
									fi
								else
									if [ ${user_to_check} = ${handover_account} ]
									then
										trx_acknowledged=1
									else
										if [ $delete_trx_not_indexed = 1 ]
										then
											rm $file_to_check 2>/dev/null
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
				echo $line >>${user_path}/blacklisted_trx.dat
			fi
		done <${user_path}/all_trx.tmp

		###GO THROUGH BLACKLISTED TRX LINE BY LINE AND REMOVE THEM#########
		if [ -s ${user_path}/blacklisted_trx.dat ]
		then
			while read line
			do
				trx_account=`echo $line|awk -F. '{print $1"."$2}'`
				if [ ! $trx_account = $handover_account ]
				then
					rm ${script_path}/trx/${line} 2>/dev/null
				fi
			done <${user_path}/blacklisted_trx.dat
		fi
		###################################################################

		###REMOVE BLACKLISTED TRX FROM ACCOUNT LIST########################
		cat ${user_path}/all_trx.tmp ${user_path}/blacklisted_trx.dat|sort -t . -k3|uniq -u >${user_path}/all_trx.dat

		###ADD ACKNOWLEDGED TRX TO FINAL LIST##############################
		cat ${user_path}/all_trx.dat ${user_path}/ack_trx.dat|sort -t . -k3 >${user_path}/all_trx.tmp
		mv ${user_path}/all_trx.tmp ${user_path}/all_trx.dat
		rm ${user_path}/ack_trx.dat

		cd ${script_path}/
		return $new_ledger
}
process_new_files(){
			process_mode=$1
			if [ $process_mode = 0 ]
			then
				touch ${user_path}/new_index_filelist.tmp
				touch ${user_path}/old_index_filelist.tmp
				touch ${user_path}/remove_list.tmp
				touch ${user_path}/temp_filelist.tmp
				for new_index_file in `grep "proofs/" ${user_path}/files_to_fetch.tmp|grep ".txt"`
				do
					user_to_verify_name=`basename $new_index_file|cut -d '.' -f1`
					user_to_verify_date=`basename $new_index_file|cut -d '.' -f2`
					user_to_verify="${user_to_verify_name}.${user_to_verify_date}"
					user_already_there=`cat ${user_path}/all_accounts.dat|grep -c "${user_to_verify}"`
					if [ $user_already_there = 1 ]
					then
						verify_signature ${user_path}/temp/${new_index_file} $user_to_verify
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							touch ${user_path}/new_index_filelist.tmp
							grep "trx/${user_to_verify}" ${user_path}/temp/${new_index_file} >${user_path}/new_index_filelist.tmp
							new_trx=`wc -l <${user_path}/new_index_filelist.tmp`
							new_trx_score_highest=0
							touch ${user_path}/old_index_filelist.tmp
							grep "trx/${user_to_verify}" ${script_path}/${new_index_file} >${user_path}/old_index_filelist.tmp
							old_trx=`wc -l <${user_path}/old_index_filelist.tmp`
							old_trx_score_highest=0
							no_matches=0
							if [ $old_trx -gt 0 -a $new_trx -gt 0 ]
							then
								if [ $old_trx -le $new_trx ]
								then
									while read line
									do
										is_file_there=`grep -c "${line}" ${user_path}/new_index_filelist.tmp`
										if [ $is_file_there = 1 ]
										then
											no_matches=$(( $no_matches + 1 ))
										else
											old_trx_receiver=`sed -n '7p' ${script_path}/${line}|cut -d ':' -f2`
											old_trx_confirmations=`grep -l "$line" proofs/*.*/*.txt|grep -v "${user_to_verify}\|${old_trx_receiver}"|wc -l`
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
											is_file_there=`grep -c "${line}" ${user_path}/old_index_filelist.tmp`
											if [ $is_file_there = 0 ]
											then
												new_trx_receiver=`sed -n '7p' ${user_path}/temp/${line}|cut -d ':' -f2`
												new_trx_confirmations=`grep -l "$line" ${user_path}/temp/proofs/*.*/*.txt|grep -v "${user_to_verify}\|${new_trx_receiver}"|wc -l`
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
										is_file_there=`grep -c "${line}" ${user_path}/old_index_filelist.tmp`
										if [ $is_file_there = 1 ]
										then
											no_matches=$(( $no_matches + 1 ))
										else
											new_trx_receiver=`sed -n '7p' ${user_path}/temp/${line}|cut -d ':' -f2`
											new_trx_confirmations=`grep -l "$line" ${user_path}/temp/proofs/*.*/*.txt|grep -v "${user_to_verify}\|${new_trx_receiver}"|wc -l`
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
											is_file_there=`grep -c "${line}" ${user_path}/new_index_filelist.tmp`
											if [ $is_file_there = 0 ]
											then
												old_trx_receiver=`sed -n '7p' ${script_path}/${line}|cut -d ':' -f2`
												old_trx_confirmations=`grep -l "$line" proofs/*.*/*.txt|grep -v "${user_to_verify}\|${old_trx_receiver}"|wc -l`
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
						user_new=`ls -1 ${user_path}/temp/keys|grep -c "${user_to_verify}"`
						if [ $user_new = 0 ]
						then
							echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
						fi
					fi
				done
				rm ${user_path}/new_index_filelist.tmp
				rm ${user_path}/old_index_filelist.tmp
				cat ${user_path}/remove_list.tmp|sort|uniq >${user_path}/temp_filelist.tmp
				cat ${user_path}/files_to_fetch.tmp >>${user_path}/temp_filelist.tmp
				cat ${user_path}/temp_filelist.tmp|sort|uniq -u >${user_path}/files_to_fetch.tmp
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
					rm ${script_path}/userdata/${handover_account}/all_keys.dat
					rm ${script_path}/userdata/${handover_account}/all_trx.dat
					rm ${script_path}/userdata/${handover_account}/all_accounts.dat
					rm ${script_path}/userdata/${handover_account}/*_ledger.dat
				fi
			fi
			while read line
			do
				if [ -h ${user_path}/temp/${line} -o -x ${user_path}/temp/${line} ]
				then
					rm ${user_path}/temp/${line}
				fi
			done <${user_path}/files_to_fetch.tmp
			files_to_copy=`find ${user_path}/temp/ -maxdepth 3 -type f|wc -l`
			if [ $files_to_copy -gt 0 ]
			then
				#############################################
				############  COPY FILES TO TARGET###########
				##################WITH FLOCK#################
				cd ${user_path}/
				flock ${script_path}/keys/ -c '
				user_path=`pwd`
				base_dir=`dirname $user_path`
				script_path=`dirname $base_dir`
				cp ${user_path}/temp/keys/* ${script_path}/keys/ 2>/dev/null
				cp -r ${user_path}/temp/proofs/* ${script_path}/proofs/ 2>/dev/null
				cp ${user_path}/temp/trx/* ${script_path}/trx/ 2>/dev/null
				'
				cd ${script_path}/
				#############################################

				###PURGE TEMP FILES##########################
				rm -r ${user_path}/temp/keys/* 2>/dev/null
				rm -r ${user_path}/temp/trx/* 2>/dev/null
				rm -r ${user_path}/temp/proofs/* 2>/dev/null
			fi
}
check_blacklist(){
			###CHECK IF USER HAS BEEN BLACKLISTED AND IF SO WARN HIM##
			am_i_blacklisted=`grep -c "${handover_account}" ${user_path}/blacklisted_accounts.dat`
			if [ $am_i_blacklisted -gt 0 ]
			then
				if [ $gui_mode = 1 ]
				then
					dialog_blacklisted_display=`echo $dialog_blacklisted|sed "s/<account_name>/${handover_account}/g"`
					dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name" --msgbox "$dialog_blacklisted_display" 0 0
				else
					echo "WARNING:USER_BLACKLISTED"
					exit 1
				fi
			fi
}

set_permissions(){
			###AVOID EXECUTABLES BY SETTING PERMISSIONS###############
			while read line
			do
				file_to_change="${script_path}/${line}"
				curr_permissions=`stat -c '%a' ${file_to_change}`
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
		for key_file in `gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys|grep "uid"|cut -d ':' -f10 2>/dev/null`
		do
			key_fp=`gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${key_file}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
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
		rm ${script_path}/keys/* 2>/dev/null
		rm ${script_path}/trx/* 2>/dev/null
		rm -r ${script_path}/proofs/* 2>/dev/null
		rm -r ${script_path}/userdata/* 2>/dev/null
}
import_keys(){
		cd ${script_path}/control/keys
		for key_file in `ls -1 ${script_path}/control/keys`
		do
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/control/keys/${key_file}
		done
		cd ${script_path}/
}
get_dependencies(){
			cd ${script_path}/trx
			new_ledger=1

			###CHECK IF ANYTHING HAS CHANGED##############################################
			depend_accounts_old_hash="X"
			depend_trx_old_hash="X"
			depend_confirmations_old_hash="X"
			if [ -e ${user_path}/depend_accounts.dat ]
			then
				if [ -e ${user_path}/depend_trx.dat ]
				then
					if [ -e ${user_path}/depend_confirmations.dat ]
					then
						depend_accounts_old_hash=`sha256sum ${user_path}/depend_accounts.dat|cut -d ' ' -f1`
						depend_trx_old_hash=`sha256sum ${user_path}/depend_trx.dat|cut -d ' ' -f1`
						depend_confirmations_old_hash=`sha256sum ${user_path}/depend_confirmations.dat|cut -d ' ' -f1`
					fi
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
					grep -l "RCVR:${user}" $(cat ${user_path}/all_trx.dat)|awk -F. '{print $1"."$2}'|sort|uniq >${user_path}/depend_user_list.tmp
					for user_trx in `grep "${user}" ${user_path}/all_trx.dat`
					do
						echo "${user_trx}" >>${user_path}/depend_trx.dat
						sed -n '7p' ${script_path}/trx/${user_trx}|cut -d ':' -f2 >>${user_path}/depend_user_list.tmp
					done
					sort -t . -k2 ${user_path}/depend_user_list.tmp|uniq >${user_path}/depend_user_list_sorted.tmp
					mv ${user_path}/depend_user_list_sorted.tmp ${user_path}/depend_user_list.tmp
					while read line
					do
						already_there=`grep -c "${line}" ${user_path}/depend_accounts.dat`
						if [ $already_there = 0 ]
						then
							echo $line >>${user_path}/depend_accounts.dat
						fi
					done <${user_path}/depend_user_list.tmp
			       		rm ${user_path}/depend_user_list.tmp 2>/dev/null
				done <${user_path}/depend_accounts.dat

				###SORT DEPENDENCIE LISTS#####################################################
				sort -t . -k2 ${user_path}/depend_accounts.dat >${user_path}/depend_accounts.tmp
				mv ${user_path}/depend_accounts.tmp ${user_path}/depend_accounts.dat
				sort -t . -k3 ${user_path}/depend_trx.dat|uniq >${user_path}/depend_trx.tmp
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
				trx_hash=`sha256sum ${script_path}/trx/${line}|cut -d ' ' -f1`
				trx_sender=`sed -n '6p' ${script_path}/trx/${user_trx}|cut -d ':' -f2`
				total_confirmations=`grep -l "trx/${line} ${trx_hash}" ${script_path}/proofs/*.*/*.txt|grep -v "${handover_account}\|${trx_sender}"|wc -l`
				if [ $total_confirmations -lt $confirmations_from_users ]
				then
					echo "$line" >>${user_path}/depend_confirmations.dat
				fi
			done <${user_path}/depend_trx.dat

			###GET HASH AND COMPARE#######################################################
			depend_accounts_new_hash=`sha256sum ${user_path}/depend_accounts.dat|cut -d ' ' -f1`
			depend_trx_new_hash=`sha256sum ${user_path}/depend_trx.dat|cut -d ' ' -f1`
			depend_confirmations_new_hash=`sha256sum ${user_path}/depend_confirmations.dat|cut -d ' ' -f1`
			if [ $depend_accounts_new_hash = $depend_accounts_old_hash -a $depend_trx_new_hash = $depend_trx_old_hash -a $depend_confirmations_new_hash = $depend_confirmations_old_hash ]
			then
				new_ledger=0
			fi
			cd ${script_path}/
			return $new_ledger
}
request_uca(){
		###STATUS BAR FOR GUI##############################
		if [ $gui_mode = 1 ]
		then
			number_ucas=`wc -l <${script_path}/control/uca.conf`
			percent_per_uca=`echo "scale=10; 100 / ${number_ucas}"|bc`
			current_percent=0
			percent_display=0
		fi

		###READ UCA.CONF LINE BY LINE######################
		while read line
		do
			###SET SESSION KEY################################
			session_key=`date -u +%Y%m%d`

			###GET VALUES FROM UCA.CONF#######################
			uca_connect_string=`echo $line|cut -d ',' -f1`
			uca_rcv_port=`echo $line|cut -d ',' -f2`
			uca_info=`echo $line|cut -d ',' -f4`

			###STATUS BAR FOR GUI##############################
			if [ $gui_mode = 1 ]
			then
				echo "$percent_display"|dialog --title "$dialog_uca_full" --backtitle "$core_system_name" --gauge "${dialog_uca_request} ${uca_info}" 0 0 0
			fi

			###GET RANDOM P AND RELATED G#####################
			numbers_total=`wc -l <${script_path}/control/dh.db`
			number_urandom=`head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 6`
			number_random=`expr ${number_urandom} % ${numbers_total}`
			number_random=$(( $number_random + 1 ))
			p_number=`sed -n "${number_random}p" ${script_path}/control/dh.db|cut -d ':' -f1`
			g_number=`sed -n "${number_random}p" ${script_path}/control/dh.db|cut -d ':' -f2`

			###CALCULATE VALUE FOR A##########################
			usera_random_integer_unformatted=`head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 5`
			usera_random_integer_formatted=`echo "${usera_random_integer_unformatted} / 1"|bc`
			usera_send_tmp=`echo "${g_number} ^ ${usera_random_integer_formatted}"|bc`
			usera_send=`echo "${usera_send_tmp} % ${p_number}"|bc`
			usera_session_id=`head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 20`
			usera_string="${p_number}:${g_number}:${usera_send}:${usera_session_id}:"
			##################################################

			###SET VALUES#####################################
			now_stamp=`date +%s`
			sync_file="${user_path}/uca_${now_stamp}.sync"
			out_file="${user_path}/uca_${now_stamp}.out"
			save_file="${user_path}/uca_save.dat"

			###WRITE HEADER AND ENCRYPT#######################
			printf "${usera_string}\n"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${user_path}/uca_header.tmp --passphrase ${session_key} - 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				###SEND KEY VIA DIFFIE-HELLMAN AND WRITE RESPONSE TO FILE####################
				cat ${user_path}/uca_header.tmp|netcat -q0 -w60 ${uca_connect_string} ${uca_rcv_port} >${out_file} 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###DECRYPT HEADER RECEIVED#########################
					header=`head -6 ${out_file}|gpg --batch --no-tty --output - --passphrase ${session_key} --decrypt - 2>/dev/null`

					###GET SIZE OF HEADER AND BODY######################
					total_bytes_received=`wc -c <${out_file}`
					total_bytes_header=`head -6 ${out_file}|wc -c`
					total_bytes_count=$(( $total_bytes_received - $total_bytes_header ))

					###CALCULATE SHARED-SECRET##########################
					userb_sent=`echo $header|cut -d ':' -f3`
					usera_ssecret_tmp=`echo "${userb_sent} ^ ${usera_random_integer_formatted}"|bc`
					usera_ssecret=`echo "${usera_ssecret_tmp} % ${p_number}"|bc`
					usera_hssecret=`echo "${usera_ssecret}_${session_key}"|sha256sum|cut -d ' ' -f1`

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
							echo "${uca_connect_string}:${usera_ssecret}:${usera_session_id}:" >${save_file}
						fi
						###WRITE SHARED SECRET TO DB########################
						ssecret_there=`grep "${uca_connect_string}" ${save_file}|wc -l`
						if [ $ssecret_there = 0 ]
						then
							echo "${uca_connect_string}:${usera_ssecret}:${usera_session_id}:" >>${save_file}
						else
							same_key=`grep "${uca_connect_string}" ${save_file}|cut -d ':' -f2`
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
				current_percent=`echo "scale=10; ${current_percent} + ${percent_per_uca}"|bc`
				percent_display=`echo "scale=0; ${current_percent} / 1"|bc`
				echo "$percent_display"|dialog --title "$dialog_uca_full" --backtitle "$core_system_name" --gauge "${dialog_uca_request} ${uca_info}" 0 0 0
			fi

			###PURGE TEMP FILES################################
			rm ${out_file} 2>/dev/null
			rm ${sync_file} 2>/dev/null
		done <${script_path}/control/uca.conf
}
send_uca(){
		now_stamp=`date +%s`

		###SET VARIABLES#############################
		sync_file="${user_path}/${handover_account}_${now_stamp}.sync"
		out_file="${user_path}/${handover_account}_${now_stamp}.out"
		save_file="${user_path}/uca_save.dat"

		###STATUS BAR FOR GUI########################
		if [ $gui_mode = 1 ]
		then
			number_ucas=`wc -l <${script_path}/control/uca.conf`
			percent_per_uca=`echo "scale=10; 100 / ${number_ucas}"|bc`
			current_percent=0
			percent_display=0
		fi

		###ONLY CONTINUE IF SAVEFILE IS THERE########
		if [ -s ${save_file} ]
		then
			###STEP INTO HOMEDIR AND CREATE TARBALL######
			cd ${script_path}/
			tar -czf ${out_file} keys/ proofs/ trx/ --dereference --hard-dereference
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				###READ UCA.CONF LINE BY LINE################
				while read line
				do
					###SET SESSION KEY################################
					session_key=`date -u +%Y%m%d`

					###GET VALUES FROM UCA.CONF##################
					uca_connect_string=`echo $line|cut -d ',' -f1`
					uca_snd_port=`echo $line|cut -d ',' -f3`
					uca_info=`echo $line|cut -d ',' -f4`

					###STATUS BAR FOR GUI########################
					if [ $gui_mode = 1 ]
					then
						echo "$percent_display"|dialog --title "$dialog_uca_full" --backtitle "$core_system_name" --gauge "${dialog_uca_send} ${uca_info}" 0 0 0
					fi

					###GET STAMP#################################
					now_stamp=`date +%s`

					###WRITE SHARED SECRET TO DB########################
					ssecret_there=`grep "${uca_connect_string}" ${save_file}|wc -l`
					if [ ! $ssecret_there = 0 ]
					then
						###GET KEY FROM SAVE-TABLE#########################
						usera_ssecret=`grep "${uca_connect_string}" ${save_file}|cut -d ':' -f2`
						usera_ssecret=$(( $usera_ssecret + $usera_ssecret ))
						usera_hssecret=`echo "${usera_ssecret}_${session_key}"|sha256sum|cut -d ' ' -f1`
						usera_session_id=`grep "${uca_connect_string}" ${save_file}|cut -d ':' -f3`

						###ENCRYPT HEADER CONTAINING SESSION ID############
						printf "${usera_session_id}\n"|gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${user_path}/uca_header.tmp --passphrase ${session_key} - 2>/dev/null
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###ENCRYPT SYNCFILE################################
							gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --armor --cipher-algo AES256 --output ${sync_file} --passphrase ${usera_hssecret} ${out_file}
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								###SEND KEY AND SYNCFILE VIA DIFFIE-HELLMAN########
								cat ${user_path}/uca_header.tmp ${sync_file}|netcat -q0 -w5 ${uca_connect_string} ${uca_snd_port} 2>/dev/null
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
					fi

					###STATUS BAR FOR GUI##############################
					if [ $gui_mode = 1 ]
					then
						current_percent=`echo "scale=10; ${current_percent} + ${percent_per_uca}"|bc`
						percent_display=`echo "scale=0; ${current_percent} / 1"|bc`
						echo "$percent_display"|dialog --title "$dialog_uca_full" --backtitle "$core_system_name" --gauge "${dialog_uca_send} ${uca_info}" 0 0 0
					fi
				done <${script_path}/control/uca.conf
			fi
		fi
		rm ${sync_file} 2>/dev/null
		rm ${save_file} 2>/dev/null
}
##################
#Main Menu Screen#
##################
###GET SCRIPT PATH##########
script_path=$(dirname $(readlink -f ${0}))

###GET PID##################
my_pid=$$

###SOURCE CONFIG FILE#######
. ${script_path}/control/config.conf

###SET THEME################
export DIALOGRC="${script_path}/theme/${theme_file}"
dialogrc_set="${theme_file}"

###SOURCE LANGUAGE FILE#####
. ${script_path}/lang/${lang_file}

###SET INITIAL VARIABLES####
now=`date -u +%Y%m%d`
no_ledger=0
user_logged_in=0
uca_trigger=0
action_done=1
make_ledger=1
end_program=0

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
	cmd_purpose=""
	cmd_type=""
	cmd_path=""

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
			"-pin")	 cmd_var=$1
					;;
			"-password")	cmd_var=$1
					;;
			"-sender")	cmd_var=$1
					;;
			"-receiver")	cmd_var=$1
					;;
			"-amount")	cmd_var=$1
					;;
			"-purpose")	cmd_var=$1
					;;
			"-type")	cmd_var=$1
					;;
			"-path")	cmd_var=$1
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
						"-pin")	 cmd_pin=$1
								;;
						"-password")	cmd_pw=$1
								;;
						"-sender")	cmd_sender=$1
								;;
						"-receiver")	cmd_receiver=$1
								;;
						"-amount")	cmd_amount=$1
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
			main_menu=`dialog --ok-label "$dialog_main_choose" --no-cancel --backtitle "$core_system_name ${core_system_version}" --output-fd 1 --colors --menu "\Z7XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXX                   XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX                   XXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXX \ZUUNIVERSAL CREDIT SYSTEM\ZU XXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 22 43 5 "$dialog_main_logon" "" "$dialog_main_create" "" "$dialog_main_settings" "" "$dialog_main_backup" "" "$dialog_main_end" ""`
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
									account_name_entered=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --output-fd 1 --max-input 30 --inputbox "$dialog_login_display_account" 0 0 ""`
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
												account_pin_entered=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --output-fd 1 --max-input 5 --insecure --passwordbox "$dialog_login_display_loginkey" 0 0 ""`
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
															account_password_entered=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_login_display_pw" 0 0 ""`
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
									account_name=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --title "$dialog_main_create" --backtitle "$core_system_name" --max-input 30 --output-fd 1 --inputbox "$dialog_keys_account" 0 0 "${account_name_inputbox}"`
									rt_query=$?
								else
									if [ "${cmd_user}" = "" ]
									then
										account_name=`tr -dc A-Za-z0-9 </dev/urandom|head -c 20`
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
												account_pin_first=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin1" 0 0 "$account_pin_inputbox"`
												rt_query=$?
											else
												if [ "${cmd_pin}" = "" ]
												then
													account_pin_first=`tr -dc 0-9 </dev/urandom|head -c 5`
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
														account_pin_second=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 5 --output-fd 1 --inputbox "$dialog_keys_pin2" 0 0 "$account_pin_inputbox"`
														rt_query=$?
													else
														rt_query=0
													fi
													if [ $rt_query = 0 ]
													then
				       										if [ ! "${account_pin_first}" = "${account_pin_second}" ]
														then
															clear
															dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_pinmatch" 0 0
															clear
														else
															account_password_entered_correct=0
	     														while [ $account_password_entered_correct = 0 ]
	       														do
																if [ $gui_mode = 1 ]
																then
																	account_password_first=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw1" 0 0`
																	rt_query=$?
																else
																	if [ "${cmd_pw}" = "" ]
																	then
																		account_password_first=`tr -dc A-Za-z0-9 </dev/urandom|head -c 10`
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
																			account_password_second=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw2" 0 0`
																			rt_query=$?
																		else
																			rt_query=0
																		fi
																		if [ $rt_query = 0 ]
																		then
				       															if [ ! "${account_password_first}" = "${account_password_second}" ]
																			then
																				clear
																				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_pwmatch" 0 0
																				clear
																			else
																				account_name_entered_correct=1
																				account_pin_entered_correct=1
																				account_password_entered_correct=1
																				create_keys "${account_name}" "${account_pin_second}" "${account_password_second}"
																				rt_query=$?
																				if [ $rt_query = 0 ]
																				then
																					dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_success" 0 0
																				else
																					dialog --title "$dialog_type_titel_error" --backtitle "$core_system_name" --msgbox "$dialog_keys_fail" 0 0
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
													account_pin_inputbox=`tr -dc 0-9 </dev/urandom|head -c 5`
												else
													account_pin_entered_correct=1
												fi
											fi
										done
									fi
								else
									if [ $rt_query = 3 ]
									then
										account_name_inputbox=`tr -dc A-Za-z0-9 </dev/urandom|head -c 20`
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
									settings_menu=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_main_back" --backtitle "$core_system_name" --output-fd 1 --colors --menu "$dialog_main_settings" 0 5 0 "$dialog_main_lang" "" "$dialog_main_theme" ""`
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										case $settings_menu in
											"$dialog_main_lang")	ls -1 ${script_path}/lang/ >${script_path}/languages.tmp
														while read line
														do
															lang_ex_short=`echo $line|cut -d '_' -f2`
															lang_ex_full=`echo $line|cut -d '_' -f3|cut -d '.' -f1`
															printf "$lang_ex_short $lang_ex_full " >>${script_path}/lang_list.tmp
														done <${script_path}/languages.tmp
														lang_selection=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_cancel" --title "$dialog_main_lang" --backtitle "$core_system_name" --output-fd 1 --menu "$dialog_lang" 0 0 0 --file ${script_path}/lang_list.tmp`
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															new_lang_file=`grep "lang_${lang_selection}_" ${script_path}/languages.tmp`
															if [ ! $lang_file = $new_lang_file ]
															then
																sed -i "s/lang_file=\"${lang_file}\"/lang_file=\"${new_lang_file}\"/g" ${script_path}/control/config.conf
																. ${script_path}/control/config.conf
																. ${script_path}/lang/${lang_file}
															fi
														fi
														rm ${script_path}/languages.tmp
														rm ${script_path}/lang_list.tmp
														;;
											"$dialog_main_theme")	ls -1 ${script_path}/theme/ >${script_path}/themes.tmp
														while read line
														do
															theme_name=`echo $line|cut -d '.' -f1`
															printf "$theme_name theme " >>${script_path}/theme_list.tmp
														done <${script_path}/themes.tmp
														theme_selection=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_cancel" --title "$dialog_main_theme" --backtitle "$core_system_name" --output-fd 1 --menu "$dialog_theme" 0 0 0 --file ${script_path}/theme_list.tmp`
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															new_theme_file=`grep "${theme_selection}" ${script_path}/themes.tmp`
															if [ ! $dialogrc_set = $new_theme_file ]
															then
																sed -i "s/theme_file=\"${dialogrc_set}\"/theme_file=\"${new_theme_file}\"/g" ${script_path}/control/config.conf
																. ${script_path}/control/config.conf
																export DIALOGRC="${script_path}/theme/${theme_file}"
																dialogrc_set="${theme_file}"
																clear
																sleep 1
															fi
														fi
														rm ${script_path}/themes.tmp
														rm ${script_path}/theme_list.tmp
														;;
										esac
									else
										quit_settings=1
									fi
								done
								;;
				"$dialog_main_backup")	if [ $gui_mode = 1 ]
							then
								dialog --yes-label "$dialog_backup_create" --no-label "$dialog_backup_restore" --title "$dialog_main_backup" --backtitle "$core_system_name" --yesno "$dialog_backup_text" 0 0
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
								now_stamp=`date +%s`
								tar -czf ${script_path}/backup/${now_stamp}.bcp control/ keys/ trx/ proofs/ userdata/ --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									cd ${script_path}/backup
									backup_file=`find . -maxdepth 1 -type f|sed "s#./##g"|sort -t . -k1|tail -1`
									if [ $gui_mode = 1 ]
									then
										dialog_backup_success_display=`echo $dialog_backup_create_success|sed "s/<backup_file>/${backup_file}/g"`
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_backup_success_display" 0 0
									else
										echo "BACKUP_FILE:${backup_file}"
										exit 0
									fi
								else
									rm ${script_path}/backup/${now_stamp}.bcp 2>/dev/null
									if [ $gui_mode = 1 ]
									then
										dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_backup_create_fail" 0 0
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
										no_backups=`wc -l <${script_path}/backups_list.tmp`
										if [ $no_backups -gt 0 ]
										then
											backup_display_text=""
											while read line
											do
												backup_stamp=`echo $line|cut -d '.' -f1`
												backup_date=`date +'%F|%H:%M:%S' --date=@${backup_stamp}`
												printf "${backup_date} BACKUP " >>${script_path}/backup_list.tmp
											done <${script_path}/backups_list.tmp
										else
											printf "${dialog_history_noresult}" >${script_path}/backup_list.tmp
										fi
										backup_decision=`dialog --ok-label "$dialog_backup_restore" --cancel-label "$dialog_main_back" --title "$dialog_main_backup" --backtitle "$core_system_name" --output-fd 1 --menu "$dialog_backup_menu" 0 0 0 --file ${script_path}/backup_list.tmp`
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											no_results=`echo $dialog_history_noresult|cut -d ' ' -f1`
											if [ ! $backup_decision = $no_results ]
											then
												bcp_date_extracted=`echo $backup_decision|cut -d '|' -f1`
												bcp_time_extracted=`echo $backup_decision|cut -d '|' -f2`
												bcp_stamp=`date +%s --date="${bcp_date_extracted} ${bcp_time_extracted}"`
												bcp_file=`cat ${script_path}/backups_list.tmp|grep "${bcp_stamp}"`
												file_path="${script_path}/backup/${bcp_file}"
												cd ${script_path}
												purge_files
												tar -xzf $file_path --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
												rt_query=$?
												if [ $rt_query -gt 0 ]
												then
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_backup_restore_fail" 0 0
												else
													import_keys
													dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_backup_restore_success" 0 0
												fi
											else
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_backup_fail" 0 0
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
		if [ $auto_uca_start = 1 ]
		then
			request_uca
		fi

		###ON EACH START AND AFTER EACH ACTION...
		if [ $action_done = 1 ]
		then
			check_tsa
			check_keys
			check_trx
			trx_new_ledger=$?
			get_dependencies
			dep_new_ledger=$?
			if [ $trx_new_ledger = 0 -a $dep_new_ledger = 0 ]
			then
				changes=0
			else
				changes=1
			fi
			action_done=0
		fi

		if [ $no_ledger = 0 ]
		then
			now_stamp=`date +%s`
			if [ $make_ledger = 1 ]
			then
				build_ledger $changes
				if [ $changes = 1 ]
				then
					make_signature "none" $now_stamp 1
				fi
				make_ledger=0
			fi
			check_blacklist
			account_my_balance=`grep "${handover_account}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
			account_my_score=`grep "${handover_account}" ${user_path}/scoretable.dat|cut -d '=' -f2`
			is_score_greater_balance=`echo "${account_my_score} > ${account_my_balance}"|bc`
			if [ $is_score_greater_balance = 1 ]
			then
				account_my_score=$account_my_balance
			fi
		fi

		###IF AUTO-UCA-SYNC########################
		if [ $auto_uca_start = 1 ]
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
			dialog_main_menu_text_display=`echo $dialog_main_menu_text|sed -e "s/<login_name>/${login_name}/g" -e "s/<handover_account>/${handover_account}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<account_my_score>/${account_my_score}/g" -e "s/<currency_symbol>/${currency_symbol}/g"`
			user_menu=`dialog --ok-label "$dialog_main_choose" --no-cancel --title "$dialog_main_menu" --backtitle "$core_system_name" --output-fd 1 --menu "$dialog_main_menu_text_display" 0 0 0 "$dialog_send" "" "$dialog_receive" "" "$dialog_sync" "" "$dialog_uca" "" "$dialog_history" "" "$dialog_stats" "" "$dialog_logout" ""`
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
				"$dialog_send")	recipient_found=0
						order_aborted=0
	      					while [ $recipient_found = 0 ]
			      			do
							if [ $gui_mode = 1 ]
							then
								order_receipient=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name" --max-input 75 --output-fd 1 --inputbox "$dialog_send_address" 0 0 ""`
								rt_query=$?
							else
								rt_query=0
								order_receipient=$cmd_receiver
							fi
							if [ $rt_query = 0 ]
							then
								touch ${user_path}/keylist.tmp
								cat ${user_path}/all_accounts.dat >${user_path}/keylist.tmp
								key_there=`grep -c -w "${order_receipient}" ${user_path}/keylist.tmp`
								if [ $key_there = 1 ]
								then
									receiver_file=`grep "${order_receipient}" ${user_path}/keylist.tmp|head -1`
									recipient_found=1
									amount_selected=0
								else
									if [ $gui_mode = 1 ]
									then
										dialog_login_nokey2_display=`echo $dialog_login_nokey2|sed "s/<account_name>/${order_receipient}/g"`
										dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_login_nokey2_display" 0 0
									else
										exit 1
									fi
								fi
								rm ${user_path}/keylist.tmp
								while [ $amount_selected = 0 ]
								do
									###SCORE############################################################
									sender_score_balance=`grep "${handover_account}" ${user_path}/scoretable.dat|cut -d '=' -f2`
									sender_score_balance_value=$account_my_score
									####################################################################
									if [ $gui_mode = 1 ]
									then
										dialog_send_amount_display=`echo $dialog_send_amount|sed -e "s/<score>/${sender_score_balance_value}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g"`
										order_amount=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name" --output-fd 1 --inputbox "$dialog_send_amount_display" 0 0 "1.000000000"`
										rt_query=$?
									else
										rt_query=0
										order_amount=$cmd_amount
									fi
	     								if [ $rt_query = 0 ]
									then
										order_amount_alnum=`echo $order_amount|grep -c '[[:alpha:]]'`
										if [ $order_amount_alnum = 0 ]
										then
											order_amount_formatted=`echo $order_amount|sed -e 's/,/./g' -e 's/ //g'`
											order_amount_formatted=`echo "scale=9; ${order_amount_formatted} / 1"|bc`
											is_greater_one=`echo "${order_amount_formatted} >= 1"|bc`
											if [ $is_greater_one = 0 ]
											then
												order_amount_formatted="0${order_amount_formatted}"
											fi
											is_amount_big_enough=`echo "${order_amount_formatted} >= 0.000000001"|bc`
											amount_mod=`echo "${order_amount_formatted} % 0.000000001"|bc`
											is_amount_mod=`echo "${amount_mod} == 0"|bc` 
											if [ $is_amount_big_enough = 1 -a $is_amount_mod = 1 ]
											then
												enough_balance=`echo "${account_my_balance} - ${order_amount_formatted} >= 0"|bc`
												###SCORE#############################################################
												is_score_ok=`echo "${sender_score_balance_value} >= ${order_amount_formatted}"|bc`
												#####################################################################
												if [ $enough_balance = 1 -a $is_score_ok = 1 ]
												then
													amount_selected=1
												else
													if [ $gui_mode = 1 ]
													then
														dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_send_fail_nobalance" 0 0
													else
														exit 1
													fi
												fi
											else
												if [ $gui_mode = 1 ]
												then
													dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_send_amount_not_big_enough" 0 0
												else
													exit 1
												fi
											fi
										else
											if [ $gui_mode = 1 ]
											then
												dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_send_fail_amount" 0 0
											else
												exit 1
											fi
										fi
									else
										amount_selected=1
										recipient_found=1
										order_aborted=1
									fi
								done
							else
								recipient_found=1
								order_aborted=1
							fi
						done
						if [ $order_aborted = 0 ]
						then
							if [ $gui_mode = 1 ]
							then
								order_purpose=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name" --max-input 75 --output-fd 1 --inputbox "$dialog_send_purpose" 0 0 ""`
								rt_query=$?
							else
								order_purpose=$cmd_purpose
								order_purpose_size=`printf "${cmd_purpose}"|wc -m`
								if [ $order_purpose_size -lt 75 ]
								then
									rt_query=0
								else
									exit 1
								fi
							fi
							if [ $rt_query = 0 ]
							then
								if [ $gui_mode = 1 ]
								then
									dialog_send_overview_display=`echo $dialog_send_overview|sed -e "s/<order_receipient>/${order_receipient}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<order_amount_formatted>/${order_amount_formatted}/g" -e "s/<order_purpose>/${order_purpose}/g"`
									dialog --yes-label "$dialog_yes" --no-label "$dialog_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name" --yesno "$dialog_send_overview_display" 0 0
									rt_query=$?
								else
									rt_query=0
								fi
								if [ $rt_query = 0 ]
								then
									trx_now=`date +%s`
									order_purpose_hash=`printf "${handover_account}_${trx_now}_${order_purpose}"|sha224sum|cut -d ' ' -f1`
									make_signature "TIME:${trx_now}\nAMNT:${order_amount_formatted}\nSNDR:${handover_account}\nRCVR:${order_receipient}\nPRPS:${order_purpose_hash}" ${trx_now} 0
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										last_trx="${script_path}/trx/${handover_account}.${trx_now}"
										verify_signature ${last_trx} ${handover_account}
										rt_query=$?
										if [ $rt_query = 0 ]
										then
											if [ $gui_mode = 1 ]
											then
												dialog --yes-label "$dialog_yes" --no-label "$dialog_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name" --yesno "$dialog_send_trx" 0 0
												small_trx=$?
											fi
											if [ ! $small_trx = 255 ]
											then
												receipient_index_file="${script_path}/proofs/${order_receipient}/${order_receipient}.txt"
												rm ${user_path}/files_list.tmp 2>/dev/null
												if [ $small_trx = 0 -a -s $receipient_index_file ]
												then
													###GET KEYS AND PROOFS##########################################
													while read line
													do
														key_there=0
														key_there=`grep -c "keys/${line}" $receipient_index_file`
														if [ $key_there = 0 ]
														then
															echo "keys/${line}" >>${user_path}/files_list.tmp
														fi

														for tsa_service in `ls -1 ${script_path}/certs`
														do
															tsa_req_there=0
															tsa_req_there=`grep -c "proofs/${line}/${tsa_service}.tsq" $receipient_index_file`
															if [ $tsa_req_there = 0 ]
															then
																echo "proofs/${line}/${tsa_service}.tsq" >>${user_path}/files_list.tmp
															fi
															tsa_res_there=0
															tsa_res_there=`grep -c "proofs/${line}/${tsa_service}.tsr" $receipient_index_file`
															if [ $tsa_res_there = 0 ]
															then
																echo "proofs/${line}/${tsa_service}.tsr" >>${user_path}/files_list.tmp
															fi
														done

														index_file="proofs/${line}/${line}.txt"
														if [ -s ${script_path}/${index_file} ]
														then
															echo "proofs/${line}/${line}.txt" >>${user_path}/files_list.tmp
														fi
													done <${user_path}/depend_accounts.dat

													###GET TRX###################################################################
													while read line
													do
														trx_there=`grep -c "trx/${line}" $receipient_index_file`
														if [ $trx_there = 0 ]
														then
															echo "trx/${line}" >>${user_path}/files_list.tmp
														fi
													done <${user_path}/depend_trx.dat
												else
													###GET KEYS AND PROOFS#######################################################
													while read line
													do
														echo "keys/${line}" >>${user_path}/files_list.tmp
														for tsa_service in `ls -1 ${script_path}/certs`
														do
															if [ -s "proofs/${line}/${tsa_service}.tsq" ]
															then
																echo "proofs/${line}/${tsa_service}.tsq" >>${user_path}/files_list.tmp
															fi
															if [ -s "proofs/${line}/${tsa_service}.tsr" ]
															then
																echo "proofs/${line}/${tsa_service}.tsr" >>${user_path}/files_list.tmp
															fi
														done
														if [ -s ${script_path}/proofs/${line}/${line}.txt ]
														then
															echo "proofs/${line}/${line}.txt" >>${user_path}/files_list.tmp
														fi
													done <${user_path}/depend_accounts.dat

													###GET TRX###################################################################
													while read line
													do
														echo "trx/${line}" >>${user_path}/files_list.tmp
													done <${user_path}/depend_trx.dat
												fi
												###COMMANDS TO REPLACE BUILD_LEDGER CALL#####################################
												trx_hash=`sha256sum ${script_path}/trx/${handover_account}.${trx_now}|cut -d ' ' -f1`
												echo "trx/${handover_account}.${trx_now} ${trx_hash}" >>${user_path}/index_trx.dat
												echo "trx/${handover_account}.${trx_now}" >>${user_path}/files_list.tmp
												###SCORE#####################################################################
												sender_new_score_balance=`echo "${sender_score_balance} - ${order_amount_formatted}"|bc`
												is_greater_one=`echo "${sender_new_score_balance} >= 1"|bc`
												if [ $is_greater_one = 0 ]
												then
													sender_new_score_balance="0${sender_new_score_balance}"
												fi
												sed -i "s/${handover_account}=${sender_score_balance}/${handover_account}=${sender_new_score_balance}/g" ${user_path}/scoretable.dat
												##############################################################################
												make_signature "none" ${trx_now} 1
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													cd ${script_path}/
													tar -czf ${handover_account}_${trx_now}.trx.tmp -T ${user_path}/files_list.tmp --dereference --hard-dereference
													rt_query=$?
													rm ${user_path}/files_list.tmp 2>/dev/null
													if [ $rt_query = 0 ]
													then
														###COMMANDS TO REPLACE BUILD_LEDGER CALL#####################################
														account_new_balance=`echo "${account_my_balance} - ${order_amount_formatted}"|bc`
														is_greater_one=`echo "${account_new_balance} >= 1"|bc`
														if [ $is_greater_one = 0 ]
														then
															account_new_balance="0${account_new_balance}"
														fi
														sed -i "s/${handover_account}=${account_my_balance}/${handover_account}=${account_new_balance}/g" ${user_path}/${now}_ledger.dat
														echo "${handover_account}.${trx_now}" >>${user_path}/all_trx.dat
														get_dependencies
														#############################################################################

														###ENCRYPT TRX FILE SO THAT ONLY THE RECEIVER CAN READ IT####################
														gpg --batch --no-tty --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output ${handover_account}_${trx_now}.trx --passphrase ${order_receipient} ${handover_account}_${trx_now}.trx.tmp
														rt_query=$?
														if [ $rt_query = 0 ]
														then
															###REMOVE GPG TMP FILE#######################################################
															rm ${trx_path_output}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null

															###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER##########################
															#cp ${script_path}/${handover_account}_${trx_now}.trx ${user_path}/${handover_account}_${trx_now}.trx
															#############################################################################
															if [ ! $trx_path_output = $script_path ]
															then
																mv ${script_path}/${handover_account}_${trx_now}.trx ${trx_path_output}/${handover_account}_${trx_now}.trx
															fi
															if [ $gui_mode = 1 ]
															then
																dialog_send_success_display=`echo $dialog_send_success|sed "s#<file>#${trx_path_output}/${handover_account}_${trx_now}.trx#g"`
																dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_send_success_display" 0 0
															else
																cmd_output=`grep "${handover_account}" ${user_path}/${now}_ledger.dat`
																echo "BALANCE_${trx_now}:${cmd_output}"
																cmd_output=`grep "${handover_account}" ${user_path}/scoretable.dat`
																echo "UNLOCKED_BALANCE_${trx_now}:${cmd_output}"
																if [ ! "${cmd_path}" = "" -a ! "${trx_path_output}" = "${cmd_path}" ]
																then
																	mv ${trx_path_output}/${handover_account}_${trx_now}.trx ${cmd_path}/${handover_account}_${trx_now}.trx
																	echo "FILE:${cmd_path}/${handover_account}_${trx_now}.trx"
																else
																	echo "FILE:${trx_path_output}/${handover_account}_${trx_now}.trx"
																fi
																exit 0
															fi
														else
															rm ${trx_path_output}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null
															rm ${trx_path_output}/${handover_account}_${trx_now}.trx 2>/dev/null
															rm ${last_trx} 2>/dev/null
															if [ $gui_mode = 1 ]
															then
																dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail" 0 0
															else
																exit 1
															fi
														fi
													else
														rm ${script_path}/${handover_account}_${trx_now}.trx.tmp 2>/dev/null
														rm ${last_trx} 2>/dev/null
														if [ $gui_mode = 1 ]
														then
															dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail" 0 0
														else
															exit 1
														fi
													fi
												else
													if [ $gui_mode = 1 ]
													then
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail" 0 0
													else
														exit 1
													fi
												fi
											fi
										else
											if [ $gui_mode = 1 ]
											then
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail" 0 0
											else
												exit 1
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail" 0 0
										else
											exit 1
										fi
									fi
								fi
							fi
						fi
						;;
				"$dialog_receive")	file_found=0
							path_to_search=$trx_path_input
							while [ $file_found = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									file_path=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name" --output-fd 1 --fselect "$path_to_search" 20 48`
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
															check_trx
															trx_new_ledger=$?
															get_dependencies
															dep_new_ledger=$?
															if [ $trx_new_ledger = 0 -a $dep_new_ledger = 0 ]
															then
																changes=0
															else
																changes=1
															fi
															now_stamp=`date +%s`
															build_ledger $changes
															if [ $changes = 1 ]
															then
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
														dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
													else
														exit 1
													fi
												fi
											else
												if [ $gui_mode = 1 ]
												then
													dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
												else
													exit 1
												fi
												rm ${file_path}.tmp 2>/dev/null
											fi
										else
											if [ $gui_mode = 1 ]
											then
												dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
											else
												exit 1
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
											dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
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
							dialog --yes-label "$dialog_sync_read" --no-label "$dialog_sync_create" --title "$dialog_sync" --backtitle "$core_system_name" --yesno "$dialog_sync_io" 0 0
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
									file_path=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name" --output-fd 1 --fselect "$path_to_search" 20 48`
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
					 			       				dialog --yes-label "$dialog_sync_add_yes" --no-label "$dialog_sync_add_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name" --yesno "$dialog_sync_add" 0 0
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
															check_trx
															trx_new_ledger=$?
															get_dependencies
															dep_new_ledger=$?
															if [ $trx_new_ledger = 0 -a $dep_new_ledger = 0 ]
															then
																changes=0
															else
																changes=1
															fi
															now_stamp=`date +%s`
															build_ledger $changes
															if [ $changes = 1 ]
															then
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
														dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
														dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
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
												dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
    												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
											else
												exit 1
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
			       								dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
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
								###GET CURRENT TIMESTAMP#################################
								now_stamp=`date +%s`

								###SWITCH TO SCRIPT PATH AND CREATE TAR-BALL#############
								cd ${script_path}/
								tar -czf ${handover_account}_${now_stamp}.sync keys/ proofs/ trx/ --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER################################
									#cp ${script_path}/${handover_account}_${now_stamp}.sync ${user_path}/${handover_account}_${now_stamp}.sync
									###################################################################################
									if [ ! $sync_path_output = $script_path ]
									then
										mv ${script_path}/${handover_account}_${now_stamp}.sync ${sync_path_output}/${handover_account}_${now_stamp}.sync
									fi
									if [ $gui_mode = 1 ]
									then
										dialog_sync_create_success_display=`echo $dialog_sync_create_success|sed "s#<file>#${sync_path_output}/${handover_account}_${now_stamp}.sync#g"`
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_sync_create_success_display" 0 0
									else
										if [ ! "${cmd_path}" = "" -a ! "${sync_path_output}" = "${cmd_path}" ]
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
									dialog_sync_create_fail_display=`echo $dialog_sync_create_fail|sed "s#<file>#${script_path}/${handover_account}_${now_stamp}.sync#g"`
									dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_create_fail_display" 0 0
								fi
							fi
						fi
						;;
				"$dialog_uca")	session_key=`date -u +%Y%m%d`
						if [ $gui_mode = 1 ]
						then
							if [ $auto_uca_start = 0 ]
							then
								uca_trigger=1
								auto_uca_start=1
							fi
							action_done=1
						else
							if [ $cmd_action = "sync_uca" ]
							then
								request_uca
								check_tsa
								check_keys
								check_trx
								trx_new_ledger=$?
								get_dependencies
								dep_new_ledger=$?
								if [ $trx_new_ledger = 0 -a $dep_new_ledger = 0 ]
								then
									changes=0
								else
									changes=1
								fi
								build_ledger $changes
								if [ $changes = 1 ]
								then
									make_signature "none" $now_stamp 1
								fi
								send_uca
								exit 0
							fi
						fi
						;;
				"$dialog_history")	cd ${script_path}/trx
							rm ${user_path}/my_trx.tmp 2>/dev/null
							rm ${user_path}/my_trx_sorted.tmp 2>/dev/null
							touch ${user_path}/my_trx.tmp
							touch ${user_path}/my_trx_sorted.tmp
							grep -l ":${handover_account}" *.* >${user_path}/my_trx.tmp 2>/dev/null
							sort -r -t . -k3 ${user_path}/my_trx.tmp >${user_path}/my_trx_sorted.tmp
							mv ${user_path}/my_trx_sorted.tmp ${user_path}/my_trx.tmp
							cd ${script_path}
							no_trx=`wc -l <${user_path}/my_trx.tmp`
							if [ $no_trx -gt 0 ]
							then
								while read line
								do
									line_extracted=$line
									sender=`sed -n '6p' ${script_path}/trx/${line_extracted}|cut -d ':' -f2`
									receiver=`sed -n '7p' ${script_path}/trx/${line_extracted}|cut -d ':' -f2`
									trx_date_tmp=`echo "${line_extracted}"|cut -d '.' -f3`
									trx_date=`date +'%F|%H:%M:%S' --date=@${trx_date_tmp}`
			      						trx_amount=`sed -n '5p' ${script_path}/trx/${line_extracted}|cut -d ':' -f2`
									trx_hash=`sha256sum ${script_path}/trx/${line_extracted}|cut -d ' ' -f1`
									trx_confirmations=`grep -l "trx/${line_extracted} ${trx_hash}" proofs/*.*/*.txt|grep -v "${handover_account}\|${sender}"|wc -l`
									if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
									then
										trx_signed=`grep -c "${line_extracted}" ${script_path}/proofs/${sender}/${sender}.txt`
									else
										trx_signed=0
									fi
									if [ $trx_signed -gt 0 ]
									then
										if [ $trx_confirmations -ge $confirmations_from_users ]
										then
											trx_blacklisted=`grep -c "${line_extracted}" ${user_path}/blacklisted_trx.dat`
											sender_blacklisted=`grep -c "${sender}" ${user_path}/blacklisted_accounts.dat`
											receiver_blacklisted=`grep -c "${receiver}" ${user_path}/blacklisted_accounts.dat`
											if [ $trx_blacklisted = 0 -a $sender_blacklisted = 0 -a $receiver_blacklisted = 0 ]
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
										printf "${trx_date}|-${trx_amount} \Zb${trx_color}$dialog_history_ack_snd\ZB " >>${user_path}/history_list.tmp
									fi
									if [ $receiver = $handover_account ]
									then
										printf "${trx_date}|+${trx_amount} \Zb${trx_color}$dialog_history_ack_rcv\ZB " >>${user_path}/history_list.tmp
									fi
								done <${user_path}/my_trx.tmp
							else
								printf "${dialog_history_noresult}" >${user_path}/history_list.tmp
							fi
							menu_item_selected=`head -1 ${user_path}/history_list.tmp|cut -d ' ' -f1`
							overview_quit=0
							while [ $overview_quit = 0 ]
							do
								decision=`dialog --colors --ok-label "$dialog_open" --cancel-label "$dialog_main_back" --title "$dialog_history" --backtitle "$core_system_name" --output-fd 1 --default-item "${menu_item_selected}" --menu "$dialog_history_menu" 0 0 0 --file ${user_path}/history_list.tmp`
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									menu_item_selected=$decision
									dialog_history_noresults=`echo $dialog_history_noresult|cut -d ' ' -f1`
									if [ ! $decision = $dialog_history_noresults ]
									then
										trx_date_extracted=`echo $decision|cut -d '|' -f1`
										trx_time_extracted=`echo $decision|cut -d '|' -f2`
										trx_date=`date +%s --date="${trx_date_extracted} ${trx_time_extracted}"`
										trx_file=`grep "${trx_date}" ${user_path}/my_trx.tmp`
										trx_amount=`echo $decision|cut -d '|' -f3|sed -e 's/+//g' -e 's/-//g'`
										trx_hash=`sha256sum ${script_path}/trx/${trx_file}|cut -d ' ' -f1`
										sender=`sed -n '6p' ${script_path}/trx/${trx_file}|cut -d ':' -f2`
										receiver=`sed -n '7p' ${script_path}/trx/${trx_file}|cut -d ':' -f2`
										purpose=`sed -n '8p' ${script_path}/trx/${trx_file}`
										purpose_size=`echo "${purpose}"|wc -c`
										if [ $purpose_size -gt 6 ]
										then
											purpose_extracted=`echo $purpose|cut -c 6-$purpose_size`
										else
											purpose_extracted=""
										fi
										trx_status=""
										if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
										then
											trx_signed=`grep -c "trx/${trx_file} ${trx_hash}" ${script_path}/proofs/${sender}/${sender}.txt`
										else
											trx_signed=0
										fi
										if [ $trx_signed = 0 ]
										then
											trx_status="TRX_IGNORED "
										fi
										trx_blacklisted=`grep -c "${trx_file}" ${user_path}/blacklisted_trx.dat`
										if [ $trx_blacklisted = 1 ]
										then
											trx_status="${trx_status}TRX_BLACKLISTED "
										fi
										sender_blacklisted=`grep -c "${sender}" ${user_path}/blacklisted_accounts.dat`
										if [ $sender_blacklisted = 1 ]
										then
										trx_status="${trx_status}SDR_BLACKLISTED "
										fi
										receiver_blacklisted=`grep -c "${receiver}" ${user_path}/blacklisted_accounts.dat`
										if [ $receiver_blacklisted = 1 ]
										then
											trx_status="${trx_status}RCV_BLACKLISTED "
										fi
										if [ $trx_signed = 1 -a $trx_blacklisted = 0 -a $sender_blacklisted = 0 -a $receiver_blacklisted ]
										then
											trx_status="OK"
										fi
										user_total=`wc -l ${user_path}/depend_accounts.dat|cut -d ' ' -f1`
										trx_confirmations_total=`grep -l "trx/${trx_file} ${trx_hash}" proofs/*.*/*.txt|grep -v "${handover_account}\|${sender}"|wc -l`
										trx_confirmations="${trx_confirmations_total} \/ ${user_total}"
										if [ $sender = $handover_account ]
										then
											dialog_history_show_trx_out_display=`echo $dialog_history_show_trx_out|sed -e "s/<receiver>/${receiver}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<order_purpose>/${purpose_extracted}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g"`
											dialog --title "$dialog_history_show" --backtitle "$core_system_name" --msgbox "$dialog_history_show_trx_out_display" 0 0
										else
											dialog_history_show_trx_in_display=`echo $dialog_history_show_trx_in|sed -e "s/<sender>/${sender}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<order_purpose>/${purpose_extracted}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g"`
											dialog --title "$dialog_history_show" --backtitle "$core_system_name" --msgbox "$dialog_history_show_trx_in_display" 0 0
										fi
									else
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_history_fail" 0 0
									fi
								else
									overview_quit=1
									rm ${user_path}/history_list.tmp 2>/dev/null
								fi
							done
							;;
				"$dialog_stats")	###EXTRACT STATISTICS FOR TOTAL################
							total_keys=`wc -l <${user_path}/all_accounts.dat`
							total_trx=`wc -l <${user_path}/all_trx.dat`
							total_user_blacklisted=`wc -l <${user_path}/blacklisted_accounts.dat`
							total_trx_blacklisted=`wc -l <${user_path}/blacklisted_trx.dat`
							###############################################

							if [ $gui_mode = 1 ]
							then
								###IF GUI MODE DISPLAY STATISTICS##############
								dialog_statistic_display=`echo $dialog_statistic|sed -e "s/<total_keys>/${total_keys}/g" -e "s/<total_trx>/${total_trx}/g" -e "s/<total_user_blacklisted>/${total_user_blacklisted}/g" -e "s/<total_trx_blacklisted>/${total_trx_blacklisted}/g"`
								dialog --title "$dialog_stats" --backtitle "$core_system_name" --msgbox "$dialog_statistic_display" 0 0
							else
								###IF CMD MODE DISPLAY STATISTICS##############
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
