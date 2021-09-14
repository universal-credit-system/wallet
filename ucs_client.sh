#!/bin/sh
login_account(){
		account_name_chosen=$1
		account_key_rn=$2
		account_password=$3
		account_found=0
		handover_account=""

		###SET TRIGGER THAT ACCOUND WAS FOUND TO 0###################
		ignore_rest=0

		###READ LIST OF KEYS LINE BY LINE############################
		for line in `ls -1 ${script_path}/keys/|sort -t. -k2`
		do
			if [ $ignore_rest = 0 ]
			then
				###EXTRACT KEY DATA##########################################
				keylist_name=`echo $line|cut -d '.' -f1`
		                keylist_stamp=`echo $line|cut -d '.' -f2`
                                if [ ! $cmd_sender = "" ]
				then
                                        keylist_hash=`echo $cmd_sender|cut -d '.' -f1`
				else
					keylist_hash=`echo "${account_name_chosen}_${keylist_stamp}_${account_key_rn}"|shasum -a 256|cut -d ' ' -f1`
				fi
				#############################################################

				###IF ACCOUNT MATCHES########################################
				if [ $keylist_name = $keylist_hash ]
				then
					account_found=1
					ignore_rest=1
					handover_account=$line
				fi
				##############################################################
			fi
		done
		#############################################################

		###CHECK IF ACCOUNT HAS BEEN FOUND###########################
		if [ $account_found = 1 ]
		then
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
			echo $account_name_chosen >${user_path}/account.acc
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always -r $handover_account --passphrase ${account_password} --pinentry-mode loopback --encrypt --sign ${user_path}/account.acc 1>/dev/null 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				###REMOVE ENCRYPTION SOURCE FILE#############################
				rm ${user_path}/account.acc

				####TEST KEY BY DECRYPTING THE MESSAGE#######################
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --passphrase ${account_password} --pinentry-mode loopback --output ${user_path}/account.acc --decrypt ${user_path}/account.acc.gpg 1>/dev/null 2>/dev/null
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					extracted_name=`cat ${user_path}/account.acc`
					if [ "${extracted_name}" = "${account_name_chosen}" ]
					then
						if [ $gui_mode = 1 ]
						then
							###IF SUCCESSFULL DISPLAY WELCOME MESSAGE AND SET LOGIN VARIABLE###########
							dialog_login_welcome_display=`echo $dialog_login_welcome|sed "s/<account_name_chosen>/${account_name_chosen}/g"`
							dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --infobox "$dialog_login_welcome_display" 0 0
							sleep 1
						fi
						user_logged_in=1
					fi
				else
					if [ $gui_mode = 1 ]
					then
						dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_login_wrongpw" 0 0
					else
						exit 1
					fi
				fi
			else
				if [ $gui_mode = 1 ]
				then
					###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND################
					dialog_login_nokey_display="${dialog_login_nokey} (-> ${account_name_chosen})!"
					dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_login_nokey_display" 0 0
				else
					exit 1
				fi
			fi
		else
			if [ $gui_mode = 1 ]
			then
				###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND###############
				dialog_login_nokey2_display=`echo $dialog_login_nokey2|sed "s/<account_name>/${account_name_chosen}/g"`
				dialog --title "$dialog_type_title_warning" --backtitle "$core_system_name" --msgbox "$dialog_login_nokey2_display" 0 0
				clear
			else
				exit 1
			fi
		fi
                rm ${user_path}/account.acc.gpg 2>/dev/null
	        rm ${user_path}/account.acc 2>/dev/null
		action_done=1
		make_ledger=1
}
create_keys(){
		name_chosen=$1
		name_passphrase=$2
		name_cleared=$name_chosen

		###SET REMOVE TRIGGER TO 0###################################
		key_remove=0

		###SET FILESTAMP TO NOW######################################
		file_stamp=`date +%s`

		###CREATE RANDOM 5 DIGIT NUMBER AS PIN#######################
                key_rn=`head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 5`

		###CREATE ADDRESS BY HASHING NAME,STAMP AND PIN##############
		name_hashed=`echo "${name_cleared}_${file_stamp}_${key_rn}"|shasum -a 256|cut -d ' ' -f1`

		if [ $gui_mode = 1 ]
		then
			###DISPLAY PROGRESS BAR######################################
			echo "0"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create1" 0 0 0
		fi

		###GENERATE KEY##############################################
		gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --no-default-keyring --keyring=${script_path}/control/keyring.file --passphrase ${name_passphrase} --pinentry-mode loopback --quick-gen-key ${name_hashed}.${file_stamp} rsa4096 sign,auth,encr none 1>/dev/null 2>/dev/null
		rt_query=$?
		if [ $rt_query = 0 ]
		then
			if [ $gui_mode = 1 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR############################
				echo "33"|dialog --title "$dialog_keys_title" --backtitle "$core_system_name" --gauge "$dialog_keys_create2" 0 0 0
			fi

			###CREATE USER DIRECTORY AND SET USER_PATH###########
			mkdir ${script_path}/userdata/${name_hashed}.${file_stamp}
			mkdir ${script_path}/userdata/${name_hashed}.${file_stamp}/temp
			mkdir ${script_path}/userdata/${name_hashed}.${file_stamp}/temp/keys
			mkdir ${script_path}/userdata/${name_hashed}.${file_stamp}/temp/proofs
			mkdir ${script_path}/userdata/${name_hashed}.${file_stamp}/temp/trx
			user_path="${script_path}/userdata/${name_hashed}.${file_stamp}"

			###EXPORT PUBLIC KEY#########################################
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${name_hashed}_${key_rn}_${file_stamp}_pub.asc --passphrase ${name_passphrase} --pinentry-mode loopback --export ${name_hashed}.${file_stamp}
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
				gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --output ${user_path}/${name_hashed}_${key_rn}_${file_stamp}_priv.asc --pinentry-mode loopback --passphrase ${name_passphrase} --export-secret-keys ${name_hashed}.${file_stamp}
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###STEP INTO USER DIRECTORY##################################
					cd ${user_path}

					###CREATE TSA QUIERY FILE####################################
					openssl ts -query -data ${user_path}/${name_hashed}_${key_rn}_${file_stamp}_pub.asc -no_nonce -sha512 -out ${user_path}/freetsa.tsq 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###SET QUIERY TO TSA#########################################
						curl --silent -H "Content-Type: application/timestamp-query" --data-binary '@freetsa.tsq' https://freetsa.org/tsr > ${user_path}/freetsa.tsr
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###STEP INTO CERTS DIRECTORY#################################
							cd ${script_path}/certs

							###DOWNLOAD LATEST TSA CERTIFICATES##########################
							wget -q https://freetsa.org/files/tsa.crt
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								wget -q https://freetsa.org/files/cacert.pem
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
									mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/cacert.pem
									openssl ts -verify -queryfile ${user_path}/freetsa.tsq -in ${user_path}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>/dev/null 2>/dev/null
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
										mkdir ${script_path}/proofs/${name_hashed}.${file_stamp}
										mv ${user_path}/freetsa.tsq ${script_path}/proofs/${name_hashed}.${file_stamp}/freetsa.tsq
										mv ${user_path}/freetsa.tsr ${script_path}/proofs/${name_hashed}.${file_stamp}/freetsa.tsr

										###COPY EXPORTED PUB-KEY INTO KEYS-FOLDER#######################
										cp ${user_path}/${name_hashed}_${key_rn}_${file_stamp}_pub.asc ${script_path}/keys/${name_hashed}.${file_stamp}

										###COPY EXPORTED PRIV-KEY INTO CONTROL-FOLDER#######################
										cp ${user_path}/${name_hashed}_${key_rn}_${file_stamp}_priv.asc ${script_path}/control/keys/${name_hashed}.${file_stamp}

										if [ $gui_mode = 1 ]
										then
											###DISPLAY NOTIFICATION THAT EVERYTHING WAS FINE#############
											dialog_keys_final_display=`echo $dialog_keys_final|sed -e "s/<name_chosen>/${name_chosen}/g" -e "s/<name_hashed>/${name_hashed}.${file_stamp}/g" -e "s/<key_rn>/${key_rn}/g" -e "s/<file_stamp>/${file_stamp}/g"`
				                                                	dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_final_display" 0 0
											clear
										else
											echo "USER:${name_cleared}"
											echo "PIN:${key_rn}"
											echo "PASSWORD:>${name_passphrase}<"
											echo "ADRESS:${name_hashed}.${file_stamp}"
											echo "KEY:${name_hashed}.${file_stamp}"
											echo "KEY_PUB:/keys/${name_hashed}.${file_stamp}"
											echo "KEY_PRV:/control/keys/${name_hashed}.${file_stamp}"
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
				rm -r ${script_path}/proofs/${name_hashed}.${file_stamp} 2>/dev/null

				###REMOVE USERDATA DIRECTORY OF USER#########################
				rm -r ${script_path}/userdata/${name_hashed}.${file_stamp} 2>/dev/null

				###REMOVE KEYS FROM KEYRING##################################
				key_fp=`gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${name_hashed}.${file_stamp}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
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
				echo $transaction_message >>${message_blank}
				#################################################################
			else
				###IF YES.....###################################################
				message=${script_path}/proofs/${handover_account}/${handover_account}.txt
                                message_blank=${user_path}/message_blank.dat
				touch ${message_blank}
				touch ${user_path}/index_keys.tmp
				cat ${user_path}/all_accounts.dat >${user_path}/index_keys.tmp
				while read line
				do
					###WRITE KEYFILE TO INDEX FILE###################################
					key_hash=`shasum -a 256 <${script_path}/keys/${line}|cut -d ' ' -f1`
                                        key_path="keys/${line}"
                                        echo "${key_path} ${key_hash}" >>${message_blank}
					#################################################################

					###IF TSA QUIERY FILE IS AVAILABLE ADD TO INDEX FILE#############
					freetsa_qfile="${script_path}/proofs/${line}/freetsa.tsq"
					if [ -s $freetsa_qfile ]
					then
						freetsa_qfile_path="proofs/$line/freetsa.tsq"
						freetsa_qfile_hash=`shasum -a 256 <${script_path}/proofs/$line/freetsa.tsq|cut -d ' ' -f1`
						echo "${freetsa_qfile_path} ${freetsa_qfile_hash}" >>${message_blank}
					fi
					#################################################################

					###IF TSA RESPONSE FILE IS AVAILABLE ADD TO INDEX FILE###########
					freetsa_rfile="${script_path}/proofs/${line}/freetsa.tsr"
					if [ -s $freetsa_rfile ]
					then
						freetsa_rfile_path="proofs/$line/freetsa.tsr"
						freetsa_rfile_hash=`shasum -a 256 <${script_path}/proofs/$line/freetsa.tsr|cut -d ' ' -f1`
						echo "${freetsa_rfile_path} ${freetsa_rfile_hash}" >>${message_blank}
					fi
					#################################################################
				done <${user_path}/index_keys.tmp

				###REMOVE KEYLIST################################################
				rm ${user_path}/index_keys.tmp

				####WRITE TRX LIST TO INDEX FILE#################################
                                cat ${user_path}/index_trx.dat >>${message_blank}
			fi
			#################################################################

			###CHECK SIZE OF FILE TO BE SIGNED###############################
			total_blank=`wc -l <${message_blank}`
			total_blank=$(( $total_blank + 16 ))

			###SIGN FILE AND REMOVE GPG WRAPPER##############################
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --digest-algo SHA512 --local-user $handover_account --clearsign ${message_blank} 2>/dev/null
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				rm ${message_blank} 2>/dev/null
				tail -$total_blank ${message_blank}.asc|sed -e 's/-----BEGIN PGP SIGNATURE-----//g' -e 's/-----END PGP SIGNATURE-----//g' >${message}
				rm ${message_blank}.asc 2>/dev/null
			fi
			#################################################################
			return $rt_query
}
verify_signature(){
			file_to_verify=$1
			user_signed=$2
			signed_correct=0
			build_message=${user_path}/verify_trx.tmp

			###CHECK NO OF LINES OF THE TRX TO VERIFY#####################
			no_lines_trx=`wc -l < ${file_to_verify}`

			###CALCULATE SIZE OF MESSAGE##################################
			till_sign=$(( $no_lines_trx - 16 ))	#-16

			###REBUILD GPG FILE###########################################
			echo "-----BEGIN PGP SIGNED MESSAGE-----" >${build_message}
			echo "Hash: SHA512" >>${build_message}
			echo "" >>${build_message}
			head -${till_sign} ${file_to_verify} >>${build_message}
			echo "-----BEGIN PGP SIGNATURE-----" >>${build_message}
			echo "" >>${build_message}
			tail -14 ${file_to_verify}|head -13 >>${build_message}
			echo "-----END PGP SIGNATURE-----" >>${build_message}
			##############################################################

			###CHECK GPG FILE#############################################
			gpg --status-fd 1 --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --verify ${build_message} >${user_path}/gpg_verify.tmp 2>/dev/null
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

			rm ${build_message} 2>/dev/null
			rm ${user_path}/gpg_verify.tmp 2>/dev/null
			return $rt_query
}
check_input(){ 
		input_string=$1
		check_mode=$2
		rt_query=0
		no_digit_check=0
		length_counter=0

		###CHECK LENGTH OF INPUT STRING########################################
		length_counter=`echo "${input_string}"|wc -m`

		if [ $check_mode = 1 ]
		then
			###CHECK IF ONLY CHARS ARE IN INPUT STRING###################
			nodigit_check=`echo "${input_string}"|grep -c '[^[:digit:]]'`

			###IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION##############
			if [ $nodigit_check = 1 ]
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
		fi

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

		###CHECK IF ONLY CHARS ARE IN INPUT STRING###################
		alnum_check=`echo "${input_string}"|grep -c '[^[:alnum:]]'`

		###IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION##############
		if [ $alnum_check = 1 ]
		then
			if [ $gui_mode = 1 ]
			then
				dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_check_msg3" 0 0
				rt_query=1
			else
				exit 1
			fi
		fi
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
		
		###GET TODAYS DATE##################################
		now=`date +%Y%m%d`

		###CHECK IF OLD LEDGER THERE########################
		start_date="20210216"
		old_ledger_there=`ls -1 ${user_path}/|grep -c "ledger.dat"`
		if [ $old_ledger_there -gt 0 -a $new = 0 ]
		then
			###GET LATEST LEDGER AND EXTRACT DATE###############
			last_ledger=`ls -1 ${user_path}/|grep "ledger.dat"|sort -t_ -k1|tail -1`
			last_ledger_date=`echo $last_ledger|cut -d '_' -f1`
			last_ledger_date_stamp=`date +%s --date="${last_ledger_date}"`

			###SET DATESTAMP TO NEXTDAY OF LAST LEDGER##########
			date_stamp=$(( $last_ledger_date_stamp + 86400 ))

			###MOVE LEDGER######################################
			mv ${user_path}/${last_ledger_date}_ledger.dat ${user_path}/${now}_ledger.dat 2>/dev/null

			###CALCULATE DAY COUNTER############################
			date_stamp_last=`date +%s --date="${start_date}"`
			no_seconds_last=$(( $date_stamp - $date_stamp_last ))
			day_counter=`expr $no_seconds_last / 86400`
		else
			###SET DATESTAMP####################################
			date_stamp=`date +%s --date="${start_date}"`

			###EMPTY LEDGER#####################################
			rm ${user_path}/*_ledger.dat 2>/dev/null
			touch ${user_path}/${now}_ledger.dat
			####################################################

			###EMPTY INDEX FILE#################################
			rm ${user_path}/index_trx.dat 2>/dev/null
			touch ${user_path}/index_trx.dat
			####################################################

			###EMPTY IGNORE TRX#################################
			rm ${user_path}/ignored_trx.dat 2>/dev/null
			####################################################

			###SET DAYCOUNTER FOR NORMAL LEDGER RUN#############
			day_counter=1
		fi
		####################################################

		###SET FOCUS########################################
		focus=`date +%Y%m%d --date=@${date_stamp}`
		now_stamp=`date +%s`
		months=0
		####################################################		

		###INIT STATUS BAR##################################
		now_date_status=`date +%s --date=${now}`
                now_date_status=$(( $now_date_status + 86400 ))
		no_seconds_total=$(( $now_date_status - $date_stamp ))
		no_days_total=`expr $no_seconds_total / 86400`
		percent_per_day=`echo "scale=10; 100 / ${no_days_total}"|bc`
		current_percent=0
		current_percent_display=0
		current_percent=`echo "scale=10;${current_percent} + ${percent_per_day}"|bc`
		current_percent_display=`echo "${current_percent} / 1"|bc`
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
			months=`echo "scale=0;${day_counter} / 30"|bc`
			coinload=`echo "scale=9;0.97^$months*$initial_coinload/30"|bc`
			is_greater_one=`echo "${coinload}>=1"|bc`
		        if [ $is_greater_one = 0 ]
	        	then
	                	coinload="0${coinload}"
	                fi
			#################################################

			###GRANT COINLOAD OF THAT DAY####################
			awk -F= -v coinload="${coinload}" '{printf($1"=");printf "%.9f\n",( $2 + coinload )}' ${user_path}/${now}_ledger.dat >${user_path}/${now}_ledger.tmp
			if [ -s ${user_path}/${now}_ledger.tmp ]
			then
				mv ${user_path}/${now}_ledger.tmp ${user_path}/${now}_ledger.dat 2>/dev/null
			fi

			###CREATE LIST OF ACCOUNTS CREATED THAT DAY######
			date_stamp_tomorrow=$(( $date_stamp + 86400 ))
			awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$2 > date_stamp && $2 < date_stamp_tomorrow' ${user_path}/all_accounts.dat >${user_path}/accounts.tmp

			###GO TROUGH ACCOUNTS FOR FIRST ENTRY############
			awk -F. '{print $1"."$2"=0"}' ${user_path}/accounts.tmp >>${user_path}/${now}_ledger.dat
			rm ${user_path}/accounts.tmp 2>/dev/null

			###GO TROUGH TRX OF THAT DAY LINE BY LINE#####################
			awk -F. -v date_stamp="${date_stamp}" -v date_stamp_tomorrow="${date_stamp_tomorrow}" '$3 > date_stamp && $3 < date_stamp_tomorrow' ${user_path}/all_trx.dat >${user_path}/trxlist_${focus}.tmp
			while read line
			do
				###EXRACT DATA FOR CHECK######################################
			        trx_filename=`echo $line|cut -d ' ' -f3`
				trx_sender=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f1|cut -d ':' -f2`
				trx_receiver=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f3|cut -d ':' -f2`
				trx_hash=`shasum -a 256 <${script_path}/trx/${trx_filename}|cut -d ' ' -f1`
				trx_path="trx/${trx_filename}"
				##############################################################

				###CHECK IF INDEX-FILE EXISTS#################################
				if [ -s ${script_path}/proofs/${trx_sender}/${trx_sender}.txt -o $trx_sender = ${handover_account} ]
				then
					###CHECK IF TRX IS SIGNED BY USER#############################
					is_signed=`grep "trx/${trx_filename}" ${script_path}/proofs/${trx_sender}/${trx_sender}.txt|grep -c "${trx_hash}"`
					if [ $is_signed -gt 0 -o $trx_sender = $handover_account ]
					then
						###CHECK IF FRIENDS KNOW OF THIS TRX##########################
						number_of_friends_trx=0
						number_of_friends_add=0
						while read line
						do
							if [ -s ${script_path}/proofs/${line}/${line}.txt ]
							then
								number_of_friends_add=`grep -c "${trx_filename}" ${script_path}/proofs/${line}/${line}.txt`
								if [ $number_of_friends_add -gt 0 ]
								then
									number_of_friends_trx=$(( $number_of_friends_trx + 1 ))
								fi
							fi
						done <${user_path}/friends.dat
						##############################################################

						###EXTRACT TRX DATA###########################################
						trx_amount=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f2`
						account_balance=`grep "${trx_sender}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
						##############################################################

						###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
						account_check_balance=`echo "${account_balance} - ${trx_amount}"|bc`
						enough_balance=`echo "${account_check_balance}>=0"|bc`
						if [ $enough_balance = 1 ]
						then
							####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)############
							echo "${trx_path} ${trx_hash}" >>${user_path}/index_trx.dat
							##############################################################

							###SET BALANCE FOR SENDER#####################################
							account_balance=$account_check_balance
							is_greater_one=`echo "${account_balance}>=1"|bc`
							if [ $is_greater_one = 0 ]
							then
								account_balance="0${account_balance}"
							fi
							account_prev_balance=`grep "${trx_sender}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
							sed -i "s/${trx_sender}=${account_prev_balance}/${trx_sender}=${account_balance}/g" ${user_path}/${now}_ledger.dat
							##############################################################

							###IF FRIEDS ACKNOWLEDGED TRX HIGHER BALANCE OF RECEIVER######
							if [ $number_of_friends_trx -gt $confirmations_from_friends ]
							then
								receiver_in_ledger=`grep -c "${trx_receiver}" ${user_path}/${now}_ledger.dat`
								if [  $receiver_in_ledger = 1 ]
								then
									receiver_old_balance=`grep "${trx_receiver}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
									is_greater_one=`echo "${receiver_old_balance}>=1"|bc`
									if [ $is_greater_one = 0 ]
									then
										receiver_old_balance="0${receiver_old_balance}"
									fi
									receiver_new_balance=`echo "${receiver_old_balance} + ${trx_amount}"|bc`
									is_greater_one=`echo "${receiver_new_balance}>=1"|bc`
									if [ $is_greater_one = 0 ]
									then
										receiver_new_balance="0${receiver_new_balance}"
									fi
									sed -i "s/${trx_receiver}=${receiver_old_balance}/${trx_receiver}=${receiver_new_balance}/g" ${user_path}/${now}_ledger.dat
								fi
							fi
							##############################################################
						else
							echo "${trx_filename}" >>${user_path}/ignored_trx.dat
						fi
						##############################################################
					fi
					##############################################################
				fi
				##############################################################
			done <${user_path}/trxlist_${focus}.tmp
			rm ${user_path}/trxlist_${focus}.tmp 2>/dev/null

			###RAISE VARIABLES FOR NEXT RUN###############################
			date_stamp=$(( $date_stamp + 86400 ))
			focus=`date +%Y%m%d --date=@${date_stamp}`
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
			touch ${user_path}/files_to_keep.tmp

			###CHECK TARFILE CONTENT######################################
			tar -tvf $path_to_tarfile >${user_path}/tar_check_temp.tmp
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
		                				"keys")		if [ ! -d $line ]
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
													if [ ! -s $line ]
													then
														echo "$line" >>${user_path}/files_to_fetch.tmp
													fi
												else
													echo "$line" >>${user_path}/files_to_fetch.tmp
												fi
											fi
										fi
		                        		      			;;
		               					"trx")		if [ ! -d $line ]
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
														if [ ! -s $line ]
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
								"proofs")	if [ ! -d $line ]
										then
											file_usr=`echo $line|cut -d '/' -f2`
											file_usr_correct=`echo $file_usr|cut -d '.' -f2|grep -c '[^[:digit:]]'`
											if [ $file_usr_correct = 0 ]
											then
												file_full=`echo $line|cut -d '/' -f3`
												case $file_full in
													"freetsa.tsq")		if [ $check_mode = 0 ]
																then
																	if [ ! -s $line ]
																	then
																		echo "$line" >>${user_path}/files_to_fetch.tmp
																	fi
																else
																	echo "$line" >>${user_path}/files_to_fetch.tmp
																fi
																;;
													"freetsa.tsr")		if [ $check_mode = 0 ]
																then
																	if [ ! -s $line ]
																	then
																		echo "$line" >>${user_path}/files_to_fetch.tmp
																	fi
																else
																	echo "$line" >>${user_path}/files_to_fetch.tmp
																fi
																;;
													"${file_usr}.txt")	echo "$line" >>${user_path}/files_to_fetch.tmp
																;;
													*)			rt_query=1
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

			###CREATE LIST OF FILES THAT ARE ALREADY THERE FOR RESTORE####
			if [ $rt_query = 0 ]
			then
				###NORMAL EXTRACT WHERE ONLY CERTAIN FILES WILL BE KEPT######
				while read line
				do
					if [ ! -d ${script_path}/${line} ]
					then
						if [ -s ${script_path}/${line} ]
						then
							echo $line >>${user_path}/files_to_keep.tmp
						fi
					fi
				done<${user_path}/tar_check.tmp

				any_files_there=`wc -l <${user_path}/files_to_keep.tmp`
				if [ $any_files_there -gt 0 ]
				then
					###PACK BACKUP FILE###########################################
					cd ${script_path}/
					tar -czf ${script_path}/userdata/${handover_account}/${handover_account}_temp.bcp -T ${user_path}/files_to_keep.tmp --dereference --hard-dereference
					rt_query=$?
				fi
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

			###VARIABLE FOR FREETSA CERTIFICATE DOWNLOAD CHECK###########
			freetsa_available=0
			freetsa_cert_available=0
			freetsa_rootcert_available=0
			retry_counter=0

			while [ $freetsa_available = 0 ]
			do
				###IF TSA.CRT NOT AVAILABLE...############
				if [ ! -s ${script_path}/certs/freetsa/tsa.crt ]
				then
					###DOWNLOAD TSA.CRT######################
					wget -q https://freetsa.org/files/tsa.crt
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###IF SUCCESSFUL MOVE TO CERTS-FOLDER######
						mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
						freetsa_cert_available=1
					else
						rm ${script_path}/certs/tsa.crt 2>/dev/null
					fi
				else
					freetsa_cert_available=1
				fi

				###IF CACERT.PEM NOT AVAILABLE...#########
				if [ ! -s ${script_path}/certs/freetsa/cacert.pem ]
				then
					###DOWNLOAD CACERT.PEM####################
					wget -q https://freetsa.org/files/cacert.pem
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###IF SUCCESSFUL MOVE TO CERTS-FOLDER######
						mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/cacert.pem
						freetsa_rootcert_available=1
					else
						rm ${script_path}/certs/cacert.pem 2>/dev/null
					fi
				else
					freetsa_rootcert_available=1
				fi
	
				###IF BOTH TSA.CRT AND CACERT.PEM ARE THERE SET FLAG####################
				if [ $freetsa_cert_available = 1 -a $freetsa_rootcert_available = 1 ]
				then
					freetsa_available=1
				else
					retry_counter=$(( $retry_counter + 1 ))
					if [ $retry_counter -le 5 ]
					then
						sleep $wait_seconds_until_retry
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
				######################################
			done
			cd ${script_path}

			###VERIFY USERS AND THEIR TSA STAMPS###
			rm ${user_path}/blacklisted_accounts.dat 2>/dev/null
			touch ${user_path}/blacklisted_accounts.dat
			touch ${user_path}/all_accounts.dat
			ls -1 ${script_path}/keys|sort -t. -k2 >${user_path}/all_accounts.dat
			while read line
			do
				accountname_key_name=`echo $line`
				accountname_key_content=`gpg --with-colons --show-keys ${script_path}/keys/$line|grep "uid"|cut -d ':' -f10`
				if [ $accountname_key_name = $accountname_key_content ]
				then			
					###CHECK TSA QUERYFILE#########################
					openssl ts -verify -queryfile ${script_path}/proofs/${accountname_key_name}/freetsa.tsq -in ${script_path}/proofs/${accountname_key_name}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>/dev/null 2>/dev/null
					rt_query=$?
					if [ $rt_query = 0 ]
					then
						###WRITE OUTPUT OF RESPONSE TO FILE############
						openssl ts -reply -in ${script_path}/proofs/${accountname_key_name}/freetsa.tsr -text >${user_path}/timestamp_check.tmp 2>/dev/null
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							###VERIFY TSA RESPONSE#########################
							openssl ts -verify -data ${script_path}/keys/${line} -in ${script_path}/proofs/${accountname_key_name}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>/dev/null 2>/dev/null
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								###CHECK IF TSA RESPONSE WAS CREATED WITHIN 120 SECONDS AFTER KEY CREATION###########
								date_to_verify=`grep "Time stamp:" ${user_path}/timestamp_check.tmp|cut -c 13-37`
								date_to_verify_converted=`date +%s --date="${date_to_verify}"`
								accountdate_to_verify=`echo $line|cut -d '.' -f2`
								creation_date_diff=$(( $date_to_verify_converted - $accountdate_to_verify ))
								if [ $creation_date_diff -ge 0 ]
								then
									if [ $creation_date_diff -gt 120 ]
									then
										echo $line >>${user_path}/blacklisted_accounts.dat
									fi
								else
									echo $line >>${user_path}/blacklisted_accounts.dat
								fi
							else
								echo $line >>${user_path}/blacklisted_accounts.dat
							fi
						else
							echo $line >>${user_path}/blacklisted_accounts.dat
						fi
						rm ${user_path}/timestamp_check.tmp 2>/dev/null
					else
						echo $line >>${user_path}/blacklisted_accounts.dat
					fi
				else
					echo $line >>${user_path}/blacklisted_accounts.dat
				fi
			done <${user_path}/all_accounts.dat

			###GO THROUGH BLACKLISTED ACCOUNTS LINE BY LINE AND REMOVE KEYS AND PROOFS###########
			while read line
			do
				if [ ! $line = $handover_account ]
				then
					rm ${script_path}/keys/${line} 2>/dev/null
					rm -R ${script_path}/proofs/${line}/ 2>/dev/null
					rm ${script_path}/trx/${line}.* 2>/dev/null
				fi
			done <${user_path}/blacklisted_accounts.dat
			#####################################################################################

			###REMOVE BLACKLISTED USER FROM LIST OF FILES########################################
			cat ${user_path}/all_accounts.dat >${user_path}/all_accounts.tmp
			cat ${user_path}/blacklisted_accounts.dat >>${user_path}/all_accounts.tmp
			cat ${user_path}/all_accounts.tmp|sort|uniq -u >${user_path}/all_accounts.dat
			rm ${user_path}/all_accounts.tmp 2>/dev/null
			cd ${script_path}/
}
check_keys(){
		###CHECK KEYS IF ALREADY IN KEYRING AND IMPORT THEM IF NOT#########
		rm ${user_path}/blacklisted_trx.dat 2>/dev/null
		touch ${user_path}/blacklisted_trx.dat
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
						rm ${script_path}/proofs/${line}/${line}.txt
					fi
				fi
                       	fi
               	done <${user_path}/all_accounts.dat
		rm ${user_path}/keylist_gpg.tmp
		
		###REMOVE FILES OF ACCOUNTS THAT HAVE BEEN BLACKLISTED#############
		while read line
		do
			if [ ! $line = $handover_account ]
			then
				rm ${script_path}/keys/${line} 2>/dev/null
				rm -R ${script_path}/proofs/${line}/ 2>/dev/null
				rm ${script_path}/trx/${line}.* 2>/dev/null
			fi
		done <${user_path}/blacklisted_accounts.dat
		###################################################################

		###REMOVE BLACKLISTED ACCOUNTS FROM ACCOUNT LIST###################
               	cat ${user_path}/all_accounts.dat >${user_path}/all_accounts.tmp
		cat ${user_path}/blacklisted_accounts.dat >>${user_path}/all_accounts.tmp
		cat ${user_path}/all_accounts.tmp|sort|uniq -u >${user_path}/all_accounts.dat
		rm ${user_path}/all_accounts.tmp 2>/dev/null
}
check_trx(){
		###REMOVE OLD FILES AND RECREATE THEM##############################
		rm ${user_path}/all_trx.dat 2>/dev/null
		rm ${user_path}/all_trx.tmp 2>/dev/null
		rm ${user_path}/trx_list_all.tmp 2>/dev/null
		touch ${user_path}/all_trx.dat
		touch ${user_path}/all_trx.tmp
		touch ${user_path}/trx_list_all.tmp

		###CHECK IF INDEX/IGNORE/LEDGER THERE IF NOT BUILD LEDGE###########
		index_there=0
		ignore_there=0
		ledger_needed=1
		if [ -s ${user_path}/${now}_ledger.dat ]
		then
			if [ -s ${script_path}/proofs/${handover_account}/${handover_account}.txt ]
			then
				ledger_needed=0
				index_there=1
				if [ -s ${user_path}/ignored_trx.dat ]
				then
					ignore_there=1
				fi
			else
				ledger_needed=1
			fi
		else
			ledger_needed=1
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
		cat ${user_path}/all_trx.dat|sort -t . -k3 >${user_path}/all_trx.tmp
		mv ${user_path}/all_trx.tmp ${user_path}/all_trx.dat

		###GO THROUGH TRANSACTIONS LINE PER LINE###########################
		while read line
		do
			###CHECK IF HEADER MATCHES OWNER###################################
			file_to_check=${script_path}/trx/${line}
			user_to_check=`echo $line|awk -F. '{print $1"."$2}'`
			trx_header=`head -1 $file_to_check`
			user_to_check_sender=`echo $trx_header|cut -d ' ' -f1|cut -d ':' -f2`
			if [ $user_to_check = $user_to_check_sender ]
			then
				###VERIFY SIGNATURE OF TRANSACTION#################################
				verify_signature $file_to_check $user_to_check
				rt_query=$?
				if [ $rt_query = 0 ]
				then
					###CHECK IF DATE IN HEADER MATCHES DATE OF FILENAME################
					trx_date_filename=`echo $line|cut -d '.' -f3`
					trx_date_inside=`echo $trx_header|cut -d ' ' -f4`
					if [ $trx_date_filename = $trx_date_inside ]
					then
						###CHECK IF TRANSACTION WAS CREATED BEFORE RECEIVER EXISTED##############
						user_to_check_receiver_date=`echo $trx_header|cut -d ' ' -f3|cut -d ':' -f2|cut -d '.' -f2`
						if [ $trx_date_inside -gt $user_to_check_receiver_date ]
						then
							###CHECK IF USER HAS CREATED A INDEX FILE################################
							if [ -s ${script_path}/proofs/${user_to_check}/${user_to_check}.txt ]
							then
								####CHECK IF USER HAS INDEXED THE TRANSACTION############################
								is_trx_signed=`grep -c "trx/${line}" ${script_path}/proofs/${user_to_check}/${user_to_check}.txt`

								###CHECK IF AMOUNT IS MINIMUM 0.000000001################################
								trx_amount=`echo $trx_header|cut -d ' ' -f2`
								is_amount_ok=`echo "${trx_amount} >= 0.000000001"|bc`

								if [ $is_trx_signed = 0 -a $delete_trx_not_indexed = 1 -o $is_amount_ok = 0 ]
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
													ledger_needed=1
													echo $line >>${user_path}/all_trx.tmp
												fi
											else
												ledger_needed=1
												echo $line >>${user_path}/all_trx.tmp
											fi
										else
											echo $line >>${user_path}/all_trx.tmp
										fi
									fi 
								fi
							else
								if [ $delete_trx_not_indexed = 1 ]
								then
									rm $file_to_check 2>/dev/null
								fi
							fi
						else
							echo $file_to_check >>${user_path}/blacklisted_trx.dat
						fi
					else
						echo $file_to_check >>${user_path}/blacklisted_trx.dat
					fi
				else
					echo $file_to_check >>${user_path}/blacklisted_trx.dat
				fi
			else
				echo $file_to_check >>${user_path}/blacklisted_trx.dat
			fi
		done <${user_path}/all_trx.dat
		
		if [ -s ${user_path}/all_trx.tmp ]
		then
			mv ${user_path}/all_trx.tmp ${user_path}/all_trx.dat
		fi

		###IF NO LEDGER IS NEEDED SET MAKE_LEDGER TO 0#####################
		if [ $ledger_needed = 0 ]
		then
			make_ledger=0
		fi

		###GO THROUGH BLACKLISTED TRX LINE BY LINE AND REMOVE THEM#########
		while read line
		do
			trx_account=`echo $line|awk -F. '{print $1"."$2}'`
			if [ ! $trx_account = $handover_account ]
			then
				rm ${script_path}/trx/${line} 2>/dev/null
			fi
		done <${user_path}/blacklisted_trx.dat
		###################################################################

		###REMOVE BLACKLISTED TRX FROM LIST OF TRANSACTIONS################
		touch ${user_path}/all_trx.tmp
		cat ${user_path}/all_trx.dat >${user_path}/all_trx.tmp
		cat ${user_path}/blacklisted_trx.dat >>${user_path}/all_trx.tmp
		cat ${user_path}/all_trx.tmp|sort|uniq -u >${user_path}/all_trx.dat
		rm ${user_path}/all_trx.tmp 2>/dev/null
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
				touch ${user_path}/new_indexes.tmp
				grep "proofs/" ${user_path}/files_to_fetch.tmp|grep ".txt" >${user_path}/new_indexes.tmp
				while read line
				do
					user_to_verify_name=`echo $line|cut -d '/' -f2|cut -d '.' -f1`
					user_to_verify_date=`echo $line|cut -d '/' -f2|cut -d '.' -f2`
					user_to_verify="${user_to_verify_name}.${user_to_verify_date}"
					user_already_there=`cat ${user_path}/all_accounts.dat|grep -c "${user_to_verify}"`
					if [ $user_already_there = 1 ]
					then
						verify_signature ${user_path}/temp/${line} $user_to_verify
						rt_query=$?
						if [ $rt_query = 0 ]
						then
							grep "trx/${user_to_verify}" ${user_path}/temp/${line} >${user_path}/new_index_filelist.tmp
							new_trx=`wc -l <${user_path}/new_index_filelist.tmp`
							grep "trx/${user_to_verify}" ${script_path}/${line} >${user_path}/old_index_filelist.tmp
							old_trx=`wc -l <${user_path}/old_index_filelist.tmp`
							if [ $old_trx -le $new_trx ]
							then
								while read line
								do
									is_file_there=`grep -c "${line}" ${user_path}/new_index_filelist.tmp`
									if [ $is_file_there = 0 ]
									then
										echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
									fi
								done <${user_path}/old_index_filelist.tmp
							else
								no_matches=0
								while read line
								do
									is_file_there=`grep -c "${line}" ${user_path}/old_index_filelist.tmp`
									if [ $is_file_there = 1 ]
									then
										no_matches=$(( $no_matches + 1 ))
									fi
								done <${user_path}/new_index_filelist.tmp
								if [ $no_matches -lt $old_trx ]
								then
									echo "proofs/${user_to_verify}/${user_to_verify}.txt" >>${user_path}/remove_list.tmp
								fi
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
				done <${user_path}/new_indexes.tmp
				rm ${user_path}/new_indexes.tmp
				rm ${user_path}/new_index_filelist.tmp
				rm ${user_path}/old_index_filelist.tmp
				cat ${user_path}/remove_list.tmp|sort|uniq >${user_path}/temp_filelist.tmp
				cat ${user_path}/files_to_fetch.tmp >>${user_path}/temp_filelist.tmp
				cat ${user_path}/temp_filelist.tmp|sort|uniq -u >${user_path}/files_to_fetch.tmp
                                rm ${user_path}/temp_filelist.tmp
                                rm ${user_path}/remove_list.tmp
			fi
			while read line
			do
				if [ -h ${user_path}/temp/${line} ]
				then
					rm ${user_path}/temp/${line}
				fi
			done <${user_path}/files_to_fetch.tmp
			cp ${user_path}/temp/keys/* ${script_path}/keys/
			cp -r ${user_path}/temp/proofs/* ${script_path}/proofs/
			cp ${user_path}/temp/trx/* ${script_path}/trx/
			rm -r ${user_path}/temp/keys/* 2>/dev/null
			rm -r ${user_path}/temp/trx/* 2>/dev/null
			rm -r ${user_path}/temp/proofs/* 2>/dev/null
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
restore_data(){
			###SET PERMISSIONS TO ENSURE ACCESS#######################
			chmod $permissions_directories ${script_path}/control/
			chmod $permissions_directories ${script_path}/keys/
			chmod $permissions_directories ${script_path}/trx/
			chmod $permissions_directories ${script_path}/proofs/

			###CREATE LIST WITH FILES THAT ARE NEW####################
			cat ${user_path}/files_to_fetch.tmp >${user_path}/file_list_unsorted.tmp
			cat ${user_path}/files_to_keep.tmp >>${user_path}/file_list_unsorted.tmp
			sort ${user_path}/file_list_unsorted.tmp|uniq >${user_path}/files_to_delete.tmp

			###REMOVE TMP FILE########################################
			rm ${user_path}/file_list_unsorted.tmp

			###GO THROUGH LIST AND DELETE NEW FILES###################
			while read line
			do
				is_proof=`echo $line|grep -c "proof/"`
				if [ is_proof = 1 ]
				then
					proof_user=`echo $line|cut -d '/' -f2`
					if [ -d ${script_path}/proofs/${proof_user}/ ]
					then
						rm -R ${script_path}/proofs/${proof_user} 2>/dev/null
					fi
				else
					rm ${script_path}/${line} 2>/dev/null
				fi
			done <${user_path}/files_to_delete.tmp

			###UNPACK BACKUP FILE#####################################
			cd ${script_path}/
			tar -xzf ${script_path}/userdata/${handover_account}/${handover_account}_temp.bcp --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
			
			###REMOVE TEMP BACKUP FILE################################
			rm ${script_path}/userdata/${handover_account}/${handover_account}_temp.bcp 2>/dev/null
			
			###REMOVE FILE LIST#######################################
			rm ${user_path}/files_to_delete.tmp
			rm ${user_path}/files_to_fetch.tmp 2>/dev/null
			rm ${user_path}/files_to_keep.tmp 2>/dev/null
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

			###REMOVE TEMP BACKUP FILE################################
			rm ${script_path}/userdata/${handover_account}/${handover_account}_temp.bcp 2>/dev/null

			###REMOVE FILE LIST#######################################
			rm ${user_path}/files_to_fetch.tmp 2>/dev/null
			rm ${user_path}/files_to_keep.tmp 2>/dev/null
}
purge_files(){
		###FIRST REMOVE ALL KEYS FROM KEYRING TO AVOID GPG ERRORS##########
		touch ${user_path}/keylist_gpg.tmp
		gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys|grep "uid"|cut -d ':' -f10 >${user_path}/keylist_gpg.tmp 2>/dev/null
		while read line
		do
			key_fp=`gpg --no-default-keyring --keyring=${script_path}/control/keyring.file --with-colons --list-keys ${line}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
			rt_query=$?
			if [ $rt_query = 0 ]
			then
				gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-secret-keys ${key_fp} 2>/dev/null
				gpg --batch --yes --no-default-keyring --keyring=${script_path}/control/keyring.file --delete-keys ${key_fp} 2>/dev/null
			fi
		done <${user_path}/keylist_gpg.tmp
		rm ${user_path}/keylist_gpg.tmp 2>/dev/null

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
		touch ${user_path}/keys_to_import.tmp
		ls -1 ${script_path}/control/keys >${user_path}/keys_to_import.tmp
		while read line
		do
			gpg --batch --no-default-keyring --keyring=${script_path}/control/keyring.file --trust-model always --import ${script_path}/control/keys/${line}
		done <${user_path}/keys_to_import.tmp
		rm ${user_path}/keys_to_import.tmp
		cd ${script_path}/
}
get_dependencies(){
			cd ${script_path}/trx
			changes=1
			depend_accounts_old_hash="X"
			depend_trx_old_hash="X"
			if [ -e ${user_path}/depend_accounts.dat ]
			then
				if [ -e ${user_path}/depend_trx.dat ]
				then
					depend_accounts_old_hash=`cat ${user_path}/depend_accounts.dat|shasum -a 256|cut -d ' ' -f1`
					depend_trx_old_hash=`cat ${user_path}/depend_trx.dat|shasum -a 256|cut -d ' ' -f1`
				fi
			fi
			echo "${handover_account}" >${user_path}/depend_accounts.dat
			grep "${handover_account}" ${user_path}/all_trx.dat >${user_path}/depend_trx.dat
			while read line
			do
				touch ${user_path}/depend_user_list.tmp
				user=$line
				grep -l "R:${line}" $(cat ${user_path}/all_trx.dat)|awk -F. '{print $1"."$2}'|sort|uniq >${user_path}/depend_user_list.tmp
				grep "S:${line}" $(cat ${user_path}/all_trx.dat)|cut -d ' ' -f3|cut -d ':' -f2|sort|uniq >>${user_path}/depend_user_list.tmp
				cat ${user_path}/depend_user_list.tmp|sort|uniq >${user_path}/depend_user_list_sorted.tmp
				mv ${user_path}/depend_user_list_sorted.tmp ${user_path}/depend_user_list.tmp
				while read line
				do
					already_there=`grep -c "${line}" ${user_path}/depend_accounts.dat`
					if [ $already_there = 0 ]
					then
						echo $line >>${user_path}/depend_accounts.dat
						grep $line ${user_path}/all_trx.dat >>${user_path}/depend_trx.dat
					fi
				done <${user_path}/depend_user_list.tmp
				rm ${user_path}/depend_user_list.tmp 2>/dev/null
			done <${user_path}/depend_accounts.dat

			###SORT DEPENDENCIE LISTS#####################################################
			sort -t . -k2 ${user_path}/depend_accounts.dat >${user_path}/depend_accounts.tmp
			mv ${user_path}/depend_accounts.tmp ${user_path}/depend_accounts.dat
			sort -t . -k3 ${user_path}/depend_trx.dat >${user_path}/depend_trx.tmp
			mv ${user_path}/depend_trx.tmp ${user_path}/depend_trx.dat

			###GET HASH AND COMPARE#############################
			depend_accounts_new_hash=`cat ${user_path}/depend_accounts.dat|shasum -a 256|cut -d ' ' -f1`
			depend_trx_new_hash=`cat ${user_path}/depend_trx.dat|shasum -a 256|cut -d ' ' -f1`
			if [ $depend_accounts_new_hash = $depend_accounts_old_hash -a $depend_trx_new_hash = $depend_trx_old_hash ]
			then
				changes=0
			fi

			###CREATE FRIENDS LIST##############################
			own_trx_there=`grep -c "${handover_account}" ${user_path}/depend_trx.dat`
			touch ${user_path}/friends.dat
			if [ $own_trx_there -gt 0 ]
			then
				grep -v "R:${handover_account}" ${handover_account}.*|grep "S:"|cut -d ':' -f4|cut -d ' ' -f1|sort|uniq >${user_path}/friends.dat
			fi
			####################################################
			cd ${script_path}/
			return $changes
}
##################
#Main Menu Screen#
##################
###GET SCRIPT PATH##########
script_path=$(dirname $(readlink -f ${0}))

###SOURCE CONFIG FILE#######
. ${script_path}/control/config.conf

###SOURCE LANGUAGE FILE#####
. ${script_path}/lang/${lang_file}

###SET INITIAL VARIABLES####
now=`date +%Y%m%d`
no_ledger=0
user_logged_in=0
action_done=1
make_ledger=1

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
			"-pin")         cmd_var=$1
					;;
			"-password")	cmd_var=$1
					;;
			"-sender")	cmd_var=$1
					;;
			"-receiver")	cmd_var=$1
					;;
			"-amount")	cmd_var=$1
					;;
			"-type")	cmd_var=$1
					;;
			"-path")	cmd_var=$1
					;;
			"-help")	more ${script_path}/HELP.txt
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
									"send_uca")		main_menu=$dialog_main_logon
												user_menu=$dialog_uca
												;;
									"request_uca")		main_menu=$dialog_main_logon
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
						"-pin")         cmd_pin=$1
								;;
						"-password")	cmd_pw=$1
								;;
						"-sender")	cmd_sender=$1
								;;
						"-receiver")	cmd_receiver=$1
								;;
						"-amount")	cmd_amount=$1
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
while [ ! 1 = 2 ]
do
	if [ $user_logged_in = 0 ]
	then
		if [ $gui_mode = 1 ]
		then
			main_menu=`dialog --ok-label "$dialog_main_choose" --no-cancel --backtitle "$core_system_name ${core_system_version}" --output-fd 1 --colors --menu "\Z7XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXX                   XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXX                   XXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXX \ZUUNIVERSAL CREDIT SYSTEM\ZU XXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 22 43 5 "$dialog_main_logon" "" "$dialog_main_create" "" "$dialog_main_lang" "" "$dialog_main_backup" "" "$dialog_main_end" ""`
			rt_query=$?
		else
			rt_query=0
		fi
		if [ ! $rt_query = 0 ]
        	then
                	exit
        	else
			if [ $gui_mode = 1 ]
			then
                		clear
			else
				if [ ! $cmd_action = "create_user" -a ! $cmd_action = "create_backup" -a ! $cmd_action = "restore_backup" ]
				then
					main_menu=$dialog_main_logon
				fi
			fi
                	case $main_menu in
                        	"$dialog_main_logon")   set -f
							account_chosen="blank"
							account_rn="blank"
							password_chosen="blank"
							account_entered_correct=0
							account_entered_aborted=0
							if [ $gui_mode = 0 ]
							then
								if [ ! $cmd_sender = "" ]
								then
									account_entered_correct=1
								fi
							fi
							while [ $account_entered_correct = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									account_chosen=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --output-fd 1 --max-input 30 --inputbox "$dialog_login_display_account" 0 0 ""`
									rt_query=$?
								else
									rt_query=0
									account_chosen="${cmd_user}"
								fi
								if [ $rt_query = 0 ]
								then
									check_input "${account_chosen}" 0
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										if [ $gui_mode = 1 ]
										then
											account_rn=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --output-fd 1 --max-input 5 --insecure --passwordbox "$dialog_login_display_loginkey" 0 0 ""`
                                                                                	rt_query=$?
										else
											rt_query=0
											account_rn=$cmd_pin
										fi
                                                                                if [ $rt_query = 0 ]
                                                                                then
                                                                                        check_input "${account_rn}" 1
                                                                                        rt_query=$?
                                                                                        if [ $rt_query = 0 ]
                                                                                        then
                                                                                                account_entered_correct=1
                                                                                        fi
                                                                                else
                                                                                        account_entered_correct=1
                                                                                        account_entered_aborted=1
                                                                                fi
									fi
								else
									account_entered_correct=1
									account_entered_aborted=1
								fi
							done
							if [ $account_entered_aborted = 0 ]
							then
								if [ $gui_mode = 1 ]
								then
									password_chosen=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_main_logon" --backtitle "$core_system_name" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_login_display_pw" 0 0 ""`
                                                                	rt_query=$?
								else
									rt_query=0
									password_chosen=$cmd_pw
								fi
                                                                if [ $rt_query = 0 ]
                                                                then
									login_account "${account_chosen}" "${account_rn}" "${password_chosen}"
								fi
							fi
							set +f
							;;
                        	"$dialog_main_create")  set -f
							account_entered_correct=0
							account_chosen_inputbox=""
							while [ $account_entered_correct = 0 ]
							do
								if [ $gui_mode = 1 ]
								then
									account_chosen=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --extra-button --extra-label "RANDOM" --title "$dialog_main_create" --backtitle "$core_system_name" --max-input 30 --output-fd 1 --inputbox "$dialog_keys_account" 0 0 "${account_chosen_inputbox}"`
									rt_query=$?
								else
									account_chosen=$cmd_user
								fi
								if [ $rt_query = 0 ]
								then
									check_input "${account_chosen}" 0
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										password_found=0
	     									while [ $password_found = 0 ]
               									do
											if [ $gui_mode = 1 ]
											then
                										password_first=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw1" 0 0`
												rt_query=$?
											else
												password_first=$cmd_pw
												rt_query=0
											fi
											if [ $rt_query = 0 ]
											then
               											check_input "${password_first}" 0
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													if [ $gui_mode = 1 ]
													then
														clear
														password_second=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --max-input 30 --output-fd 1 --insecure --passwordbox "$dialog_keys_pw2" 0 0`
														rt_query=$?
													else
														password_second=$cmd_pw
														rt_query=0
													fi
													if [ $rt_query = 0 ]
													then
                                       										if [ ! $password_first = $password_second ]
                        											then
															clear
															dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_pwmatch" 0 0
															clear
														else
															account_entered_correct=1
                                											password_found=1
															create_keys $account_chosen $password_second
															rt_query=$?
															if [ $rt_query = 0 ]
															then
																dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_keys_success" 0 0
															else
																dialog --title "$dialog_type_titel_error" --backtitle "$core_system_name" --msgbox "$dialog_keys_fail" 0 0
															fi
														fi
													else
														password_found=1
													fi
												fi
											else
												password_found=1
											fi
										done
									fi
								else
									if [ $rt_query = 3 ]
									then
										account_chosen_inputbox=`tr -dc A-Za-z0-9 </dev/urandom|head -c 20`
									else
										account_entered_correct=1
									fi
								fi
							done
							set +f
							;;
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
								new_lang_file=`grep "lang_${lang_selection}_"  ${script_path}/languages.tmp`
								if [ ! $lang_file = $new_lang_file ]
								then
									sed -i "s/lang_file=${lang_file}/lang_file=${new_lang_file}/g" ${script_path}/control/config.conf
									. ${script_path}/control/config.conf
									. ${script_path}/lang/${lang_file}
								fi
							fi
							rm ${script_path}/languages.tmp
							rm ${script_path}/lang_list.tmp
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
										if [ $cmd_path = "" ]
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
                        	"$dialog_main_end")     exit 0
							;;
                	esac
        	fi

	else
		###ON EACH START AND AFTER EACH ACTION...
		if [ $action_done = 1 ]
		then
			check_tsa
			check_keys
			check_trx
			get_dependencies
			changes=$?
			if [ $changes = 1 ]
			then
				make_ledger=1
			fi
			action_done=0
		fi
		if [ $no_ledger = 0 ]
		then
			now_stamp=`date +%s`
			if [ $make_ledger = 1 ]
			then
				build_ledger $changes
				make_signature "none" $now_stamp 1
				make_ledger=0
			fi
			check_blacklist
			account_my_balance=`grep "${handover_account}" ${user_path}/${now}_ledger.dat|cut -d '=' -f2`
		fi
		if [ $gui_mode = 1 ]
		then
			dialog_main_menu_text_display=`echo $dialog_main_menu_text|sed -e "s/<account_name_chosen>/${account_name_chosen}/g" -e "s/<handover_account>/${handover_account}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g"`
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
									if [ $gui_mode = 1 ]
									then
										order_amount=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_send" --backtitle "$core_system_name" --output-fd 1 --inputbox "$dialog_send_amount" 0 0 "1.000000000"`
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
											is_greater_one=`echo "${order_amount_formatted}>=1"|bc`
											if [ $is_greater_one = 0 ]
											then
												order_amount_formatted="0${order_amount_formatted}"
											fi
											is_amount_big_enough=`echo "${order_amount_formatted}>=0.000000001"|bc`
											amount_mod=`echo "${order_amount_formatted} % 0.000000001"|bc`
											is_amount_mod=`echo "${amount_mod} <=0"|bc` 
											if [ $is_amount_big_enough = 1 -a $is_amount_mod = 1 ]
											then
												enough_balance=`echo "${account_my_balance} - ${order_amount_formatted}>=0"|bc`
												if [ $enough_balance = 1 ]
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
								dialog_send_overview_display=`echo $dialog_send_overview|sed -e "s/<order_receipient>/${order_receipient}/g" -e "s/<account_my_balance>/${account_my_balance}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<order_amount_formatted>/${order_amount_formatted}/g"`
								dialog --yes-label "$dialog_yes" --no-label "$dialog_no" --title "$dialog_type_title_notification" --backtitle "$core_system_name" --yesno "$dialog_send_overview_display" 0 0
								rt_query=$?
							else
								rt_query=0
							fi
							if [ $rt_query = 0 ]
							then
								trx_now=`date +%s`
								make_signature "S:${handover_account} ${order_amount_formatted} R:${order_receipient} ${trx_now}" ${trx_now} 0
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
											touch ${user_path}/keys_for_trx.tmp
											cat ${user_path}/all_accounts.dat >${user_path}/keys_for_trx.tmp
											while read line
											do
												if [ $small_trx = 0 -a -s $receipient_index_file ]
												then
													key_there=0
													key_there=`grep -c "keys/${line}" $receipient_index_file`
													if [ $key_there = 0 ]
													then
														echo "keys/${line}" >>${user_path}/files_list.tmp
													fi
													tsa_req_there=0
													tsa_req_there=`grep -c "proofs/${line}/freetsa.tsq" $receipient_index_file`
													if [ $tsa_req_there = 0 ]
													then
														echo "proofs/${line}/freetsa.tsq" >>${user_path}/files_list.tmp
													fi
													tsa_res_there=0
													tsa_res_there=`grep -c "proofs/${line}/freetsa.tsr" $receipient_index_file`
													if [ $tsa_res_there = 0 ]
													then
														echo "proofs/${line}/freetsa.tsr" >>${user_path}/files_list.tmp
													fi
													index_file="proofs/${line}/${line}.txt"
													if [ -s ${script_path}/${index_file} ]
													then
														echo "proofs/${line}/${line}.txt" >>${user_path}/files_list.tmp
													fi
												else
													echo "keys/${line}" >>${user_path}/files_list.tmp
													tsa_req_check="${script_path}/proofs/${line}/freetsa.tsq"
													if [ -s $tsa_req_check ]
													then
														echo "proofs/${line}/freetsa.tsq" >>${user_path}/files_list.tmp
													fi
													tsa_res_check="${script_path}/proofs/${line}/freetsa.tsr"
													if [ -s $tsa_res_check ]
													then
														echo "proofs/${line}/freetsa.tsr" >>${user_path}/files_list.tmp
													fi
													index_file="proofs/${line}/${line}.txt"
													if [ -s ${script_path}/${index_file} ]
													then
														echo "proofs/${line}/${line}.txt" >>${user_path}/files_list.tmp
													fi
												fi
											done <${user_path}/keys_for_trx.tmp
											rm ${user_path}/keys_for_trx.tmp

											touch ${user_path}/trx_for_trx.tmp
											cat ${user_path}/all_trx.dat >${user_path}/trx_for_trx.tmp
											while read line
											do
												trx_there=0
												if [ -s $receipient_index_file ]
												then
													trx_there=`grep -c "trx/${line}" $receipient_index_file`
												fi
												if [ $trx_there = 0 ]
												then
													echo "trx/${line}" >>${user_path}/files_list.tmp
												fi
											done <${user_path}/trx_for_trx.tmp
											rm ${user_path}/trx_for_trx.tmp
											###COMMANDS TO REPLACE BUILD_LEDGER CALL#####################################
											trx_hash=`shasum -a 256 <${script_path}/trx/${handover_account}.${trx_now}|cut -d ' ' -f1`
											echo "trx/${handover_account}.${trx_now} ${trx_hash}" >>${user_path}/index_trx.dat
											#############################################################################
											make_signature "none" ${trx_now} 1
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												cd ${script_path}/
												tar -czf ${handover_account}_${trx_now}.trx -T ${user_path}/files_list.tmp --dereference --hard-dereference
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													###COMMANDS TO REPLACE BUILD_LEDGER CALL#####################################
													account_new_balance=`echo "${account_my_balance} - ${order_amount_formatted}"|bc`
													is_greater_one=`echo "${account_my_balance} - ${order_amount_formatted}<1"|bc`
													if [ $is_greater_one = 1 ]
													then
														account_new_balance="0${account_new_balance}"
													fi
													sed -i "s/${handover_account}=${account_my_balance}/${handover_account}=${account_new_balance}/g" ${user_path}/${now}_ledger.dat
													echo "${handover_account}.${trx_now}" >>${user_path}/all_trx.dat
													friend_already_there=`grep -c "${order_receipient}" ${user_path}/friends.dat`
													if [ $friend_already_there = 0 ]
													then
														echo "${order_receipient}" >>${user_path}/friends.dat
													fi
													#############################################################################
													rm ${user_path}/files_list.tmp
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
														if [ ! $cmd_path = "" -a ! $trx_path_output = $cmd_path ]
														then
															mv ${trx_path_output}/${handover_account}_${trx_now}.trx ${cmd_path}/${handover_account}_${trx_now}.trx
															echo "FILE:${cmd_path}/${handover_account}_${trx_now}.trx"
														else
															echo "FILE:${trx_path_output}/${handover_account}_${trx_now}.trx"
														fi
														exit 0
													fi
												else
													rm ${script_path}/${handover_account}_${trx_now}.trx 2>/dev/null
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
													dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail2" 0 0
												else
													exit 1
												fi
											fi
										fi
									else
										if [ $gui_mode = 1 ]
										then
											dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail2" 0 0
										else
											exit 1
										fi
									fi
								else
									if [ $gui_mode = 1 ]
									then
										dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_send_fail2" 0 0
									else
										exit 1
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
												rt_query=0
											else
												rt_query=$extract_all
											fi
											if [ $rt_query = 0 ]
											then
												check_archive $file_path 0
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
													tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --keep-directory-symlink --skip-old-files --dereference --hard-dereference
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														process_new_files 0
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
												check_archive $file_path 1
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
													tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														process_new_files 1
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
											fi
											if [ $rt_query -gt 0 ]
											then
												restore_data
												if [ $gui_mode = 0 ]
												then
													exit 1
												fi
											else
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
													get_dependencies
													if [ $no_ledger = 0 ]
													then
														now_stamp=`date +%s`
														build_ledger 1
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
                                        		        				rt_query=$?
											else
												case $cmd_type in
													"partial")	rt_query=0
															;;
													"full")		rt_query=1
															;;
													*)		exit 1
															;;
												esac
											fi
                     		                           				if [ $rt_query = 0 ]
                                	                				then
												check_archive $file_path 0
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
                                        	               			 			tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-same-owner --no-same-permissions --keep-directory-symlink --skip-old-files --dereference --hard-dereference
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														process_new_files 0
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
                		                                 				check_archive $file_path 1
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													cd ${user_path}/temp
													tar -xzf $file_path -T ${user_path}/files_to_fetch.tmp --no-overwrite-dir --no-same-owner --no-same-permissions --keep-directory-symlink --dereference --hard-dereference
                                		                					rt_query=$?
													if [ $rt_query = 0 ]
													then
														process_new_files 1
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
											fi
											if [ $rt_query -gt 0 ]
											then
												restore_data
												if [ $gui_mode = 0 ]
												then
													exit 1
												fi
											else
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
													get_dependencies
													if [ $no_ledger = 0 ]
													then
														now_stamp=`date +%s`
														build_ledger 1
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
								###GET LIST OF KEYS WITH PATH############################
								cat ${user_path}/all_accounts.dat >${user_path}/keys_sync.tmp
								while read line
								do
									echo "keys/$line" >>${user_path}/files_for_sync.tmp
									freetsa_qfile="${script_path}/proofs/${line}/freetsa.tsq"
									if [ -s $freetsa_qfile ]
									then
										echo "proofs/${line}/freetsa.tsq" >>${user_path}/files_for_sync.tmp
									fi
									freetsa_rfile="${script_path}/proofs/${line}/freetsa.tsr"
									if [ -s $freetsa_rfile ]
									then
										echo "proofs/${line}/freetsa.tsr" >>${user_path}/files_for_sync.tmp
									fi
									index_file="${script_path}/proofs/${line}/${line}.txt"
									if [ -s $index_file ]
									then
										echo "proofs/${line}/${line}.txt" >>${user_path}/files_for_sync.tmp
									fi
								done <${user_path}/keys_sync.tmp

								###GET LIST OF TRX#######################################
								cat ${user_path}/all_trx.dat >${user_path}/trx_sync.tmp
								while read line
								do
									echo "trx/$line" >>${user_path}/files_for_sync.tmp
								done <${user_path}/trx_sync.tmp
								#########################################################

								###GET CURRENT TIMESTAMP#################################
								synch_now=`date +%s`

								###SWITCH TO SCRIPT PATH AND CREATE TAR-BALL#############
								cd ${script_path}/
								tar -czf ${handover_account}_${synch_now}.sync -T ${user_path}/files_for_sync.tmp --dereference --hard-dereference
								rt_query=$?
								if [ $rt_query = 0 ]
								then
									###UNCOMMENT TO ENABLE SAVESTORE IN USERDATA FOLDER################################
									#cp ${script_path}/${handover_account}_${synch_now}.sync ${user_path}/${handover_account}_${synch_now}.sync
									###################################################################################
									if [ ! $sync_path_output = $script_path ]
									then
										mv ${script_path}/${handover_account}_${synch_now}.sync ${sync_path_output}/${handover_account}_${synch_now}.sync
									fi
									if [ $gui_mode = 1 ]
									then
										dialog_sync_create_success_display=`echo $dialog_sync_create_success|sed "s#<file>#${sync_path_output}/${handover_account}_${synch_now}.sync#g"`
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_sync_create_success_display" 0 0
									else
										if [ ! $cmd_path = "" -a ! $sync_path_output = $cmd_path ]
										then
											mv ${sync_path_output}/${handover_account}_${synch_now}.sync ${cmd_path}/${handover_account}_${synch_now}.sync
											echo "FILE:${cmd_path}/${handover_account}_${synch_now}.sync"
										else
											echo "FILE:${sync_path_output}/${handover_account}_${synch_now}.sync"
										fi
										exit 0
									fi
                       						else
									rm ${handover_account}_${synch_now}.sync 2>/dev/null
									dialog_sync_create_fail_display=`echo $dialog_sync_create_fail|sed "s#<file>#${script_path}/${handover_account}_${synch_now}.sync#g"`
									dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_create_fail_display" 0 0
								fi
							fi
							rm ${user_path}/keys_sync.tmp 2>/dev/null
							rm ${user_path}/files_for_sync.tmp 2>/dev/null
						fi
						;;
				"$dialog_uca")	session_key=`date -u +%Y%m%d`
						if [ $gui_mode = 1 ]
						then
							dialog --yes-label "$dialog_uca_send" --no-label "$dialog_uca_request" --title "$dialog_uca" --backtitle "$core_system_name" --yesno "$dialog_uca_overview" 0 0
							rt_query=$?
							if [ $rt_query = 0 ]
							then
								file_path=`dialog --ok-label "$dialog_next" --cancel-label "$dialog_cancel" --title "$dialog_read" --backtitle "$core_system_name" --output-fd 1 --fselect "$path_to_search" 20 48`
 			                               		rt_query=$?
								if [ $rt_query = 0 ]
								then
									if [ ! -d ${file_path} ]
									then
										if [ -s ${file_path} ]
										then
											cat ${file_path}|gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output - --passphrase ${session_key} -|netcat -q0 127.0.0.1 15000
											rt_query=$?
											if [ $rt_query = 0 ]
											then
												dialog_uca_success=`echo $dialog_uca_success|sed "s#<file>#${file_path}#g"`
												dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_uca_success" 0 0
											else
												dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_uca_fail" 0 0
											fi
										else
											dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
                               								dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
										fi
									else
										dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
                               							dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_sync_import_fail_display" 0 0
									fi
								fi
							else
								if [ ! $rt_query = 255 ]
								then
									now_stamp=`date +%s`
									netcat -q0 127.0.0.1 15001|gpg --batch --pinentry-mode loopback --output ${user_path}/uca_${now_stamp}.sync --passphrase ${session_key} --decrypt -
									rt_query=$?
									if [ $rt_query = 0 ]
									then
										dialog_uca_success=`echo $dialog_uca_success|sed "s#<file>#${user_path}/uca_${now_stamp}.sync#g"`
										dialog --title "$dialog_type_title_notification" --backtitle "$core_system_name" --msgbox "$dialog_uca_success" 0 0
									else
										dialog --title "$dialog_type_title_error" --backtitle "$core_system_name" --msgbox "$dialog_uca_fail" 0 0
									fi
								fi
							fi
						else
							case $cmd_action in
								"send_uca")	if [ ! $cmd_path = "" ]
										then
											if [ ! -d $cmd_path ]
											then
												if [ -s $cmd_path ]
												then
													session_key=`date -u +%Y%m%d`
													cat ${cmd_path}|gpg --batch --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --pinentry-mode loopback --symmetric --cipher-algo AES256 --output - --passphrase ${session_key} -|netcat -q0 127.0.0.1 15000
													rt_query=$?
													if [ $rt_query = 0 ]
													then
														exit 0
													else
														exit 1
													fi
												else
													exit 1
												fi
											else
												exit 1
											fi
										else
											exit 1
										fi
										;;
								"request_uca")	if [ $cmd_path = "" ]
										then
											cmd_path=${script_path}
										else
											if [ -d $cmd_path ]
											then
												now=`date +%s`
												netcat -q0 127.0.0.1 15001|gpg --batch --pinentry-mode loopback --output ${user_path}/uca_${now}.sync --passphrase ${session_key} --decrypt -
												rt_query=$?
												if [ $rt_query = 0 ]
												then
													exit 0
												else
													exit 1
												fi
											else
												exit 1
											fi
										fi
										;;
							esac
						fi
						;;
				"$dialog_history")	cd ${script_path}/trx
							rm ${user_path}/my_trx.tmp 2>/dev/null
							touch ${user_path}/my_trx.tmp
							while read line
							do
								grep -l ":${handover_account}" ${line} >>${user_path}/my_trx.tmp
							done <${user_path}/all_trx.dat
							cat ${user_path}/my_trx.tmp|sort -r -t . -k3 >${user_path}/my_trx_sorted.tmp
							mv ${user_path}/my_trx_sorted.tmp ${user_path}/my_trx.tmp
							cd ${script_path}
							no_trx=`wc -l <${user_path}/my_trx.tmp`
							if [ $no_trx -gt 0 ]
							then
								while read line
								do
									trx_confirmations=0
									trx_confirmations_user=0
									line_extracted=$line
									sender=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f1|cut -d ':' -f2`
									receiver=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f3|cut -d ':' -f2|cut -d ' ' -f1`
									trx_date_tmp=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f4`
									trx_date=`date +'%F|%H:%M:%S' --date=@${trx_date_tmp}`
                              	                	        	trx_amount=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f2`
									while read line
									do
										if [ -s ${script_path}/proofs/${line}/${line}.txt ]
										then
											trx_confirmations_user=`grep -c "${line_extracted}" ${script_path}/proofs/${line}/${line}.txt`
											if [ $trx_confirmations_user -gt 0 -a ! $receiver = $line ]
											then
												trx_confirmations=$(( $trx_confirmations + 1 ))
											fi
										fi
									done <${user_path}/friends.dat
									if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
									then
										trx_signed=`grep -c "${line_extracted}" ${script_path}/proofs/${sender}/${sender}.txt`
									else
										trx_signed=0
									fi
									if [ $trx_signed -gt 0 ]
									then
										if [ $trx_confirmations -gt 0 ]
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
										sender=`head -1 ${script_path}/trx/${trx_file}|cut -d ' ' -f1|cut -d ':' -f2`
										receiver=`head -1 ${script_path}/trx/${trx_file}|cut -d ' ' -f3|cut -d ':' -f2|cut -d ' ' -f1`
										trx_status=""
										trx_confirmations=0
										trx_confirmations_user=0
										if [ -s ${script_path}/proofs/${sender}/${sender}.txt ]
										then
											trx_signed=`grep -c "${trx_file}" ${script_path}/proofs/${sender}/${sender}.txt`
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
										while read line
										do
											if [ -s ${script_path}/proofs/${line}/${line}.txt ]
											then
												trx_confirmations_user=`grep -c "${trx_file}" ${script_path}/proofs/${line}/${line}.txt`
												if [ $trx_confirmations_user -gt 0 -a ! $receiver = $line ]
												then
													trx_confirmations=$(( $trx_confirmations + 1 ))
												fi
											fi
										done <${user_path}/friends.dat
										if [ $sender = $handover_account ]
										then
											dialog_history_show_trx_out_display=`echo $dialog_history_show_trx_out|sed -e "s/<receiver>/${receiver}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g"`
											dialog --title "$dialog_history_show" --backtitle "$core_system_name" --msgbox "$dialog_history_show_trx_out_display" 0 0
										else
											dialog_history_show_trx_in_display=`echo $dialog_history_show_trx_in|sed -e "s/<sender>/${sender}/g" -e "s/<trx_amount>/${trx_amount}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g" -e "s/<trx_file>/${trx_file}/g" -e "s/<trx_status>/${trx_status}/g" -e "s/<trx_confirmations>/${trx_confirmations}/g"`
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
							rm ${user_path}/my_trx.tmp
							;;
				"$dialog_stats")	if [ $make_ledger = 0 -o $no_ledger = 1 ]
							then
								###SET VARIABLES TO CALCULATE COINLOAD##############
								start_date="20210216"
								date_stamp=`date +%s --date="${start_date}"`
								now=`date +%Y%m%d`
								now_date_status=`date +%s --date=${now}`
                						now_date_status=$(( $now_date_status + 86400 ))
								no_seconds_total=$(( $now_date_status - $date_stamp ))
								no_days_total=`expr $no_seconds_total / 86400`
								no_days_total=$(( $no_days_total + 1 ))
							fi
							
							###CALCULATE COINLOAD AND NEXT COINLOAD########
							months=`echo "scale=0;${no_days_total} / 30"|bc`
							coinload=`echo "scale=9;0.97^$months*$initial_coinload/30"|bc`
							is_greater_one=`echo "${coinload}>=1"|bc`
		        				if [ $is_greater_one = 0 ]
	        					then
	                					coinload="0${coinload}"
	                				fi
                                                        next_month=$(( $months + 1 ))
							next_coinload=`echo "scale=9;0.97^$next_month*$initial_coinload/30"|bc`
							is_greater_one=`echo "${next_coinload}>=1"|bc`
		        				if [ $is_greater_one = 0 ]
	        					then
	                					next_coinload="0${next_coinload}"
	                				fi
							days_in_month=`expr $no_days_total % 30`
							in_days=$(( 30 - $days_in_month ))
							###############################################

							###EXTRACT STATISTICS FOR TOTAL################
							total_keys=`cat ${user_path}/all_accounts.dat|wc -l`
							total_trx=`cat ${user_path}/all_trx.dat|wc -l`
							total_user_blacklisted=`wc -l <${user_path}/blacklisted_accounts.dat`
							total_trx_blacklisted=`wc -l <${user_path}/blacklisted_trx.dat`
							total_friends=`wc -l <${user_path}/friends.dat`
							###############################################

							if [ $gui_mode = 1 ]
							then
								###IF GUI MODE DISPLAY STATISTICS##############
								dialog_statistic_display=`echo $dialog_statistic|sed -e "s/<total_keys>/${total_keys}/g" -e "s/<total_trx>/${total_trx}/g" -e "s/<total_user_blacklisted>/${total_user_blacklisted}/g" -e "s/<total_trx_blacklisted>/${total_trx_blacklisted}/g" -e "s/<total_friends>/${total_friends}/g" -e "s/<coinload>/${coinload}/g" -e "s/<currency_symbol>/${currency_symbol}/g" -e "s/<next_coinload>/${next_coinload}/g" -e "s/<in_days>/${in_days}/g"`
								dialog --title "$dialog_stats" --backtitle "$core_system_name" --msgbox "$dialog_statistic_display" 0 0
							else
								###IF CMD MODE DISPLAY STATISTICS##############
								echo "KEYS_TOTAL:${total_keys}"
								echo "TRX_TOTAL:${total_trx}"
								echo "BLACKLISTED_USERS_TOTAL:${total_user_blacklisted}"
								echo "BLACKLISTED_TRX_TOTAL:${total_trx_blacklisted}"
								echo "FRIENDS_TOTAL:${total_friends}"
								echo "CURRENT_COINLOAD:${coinload}"
								echo "NEXT_COINLOAD:${next_coinload}"
								echo "IN_DAYS:${in_days}"
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
