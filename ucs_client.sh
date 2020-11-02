#!/bin/sh
login_account(){
		account_name_chosen=$1
		account_key_rn=$2
		account_password=$3
		account_found=0
		handover_user=""
		account_file=""
		touch ${script_path}/keylist.tmp

		###WRITE LIST OF KEYS TO FILE################################
		ls -1 ${script_path}/keys/ >${script_path}/keylist.tmp

		###SET TRIGGER THAT ACCOUND WAS FOUND TO 0###################
		ignore_rest=0

		###READ LIST OF KEYS LINE BY LINE############################
		while read line
		do
			if [ $ignore_rest = 0 ]
			then
				###EXTRACT KEY DATA##########################################
				keylist_name=`echo $line|cut -d '.' -f1`
				keylist_stamp=`echo $line|cut -d '.' -f2`
				keylist_hash=`echo "${account_name_chosen}_${keylist_stamp}_${account_key_rn}"|shasum -a 256|cut -d ' ' -f1`
				#############################################################

				###IF ACCOUNT MATCHES########################################
				if [ $keylist_name = $keylist_hash ]
				then
					account_found=1
					ignore_rest=1

					###SET VARIABLES#############################################
					handover_account=$keylist_hash
					handover_account_stamp=$keylist_stamp
					account_file=$line
					handover_account_hash=`shasum -a 256 <${script_path}/keys/${account_file}|cut -d ' ' -f1`
					#############################################################
				fi
				##############################################################
			fi
		done <${script_path}/keylist.tmp
		#############################################################

		###REMOVE CREATED KEY LIST###################################
		rm ${script_path}/keylist.tmp

		
		###CHECK IF ACCOUNT HAS BEEN FOUND###########################
		if [ $account_found = 1 ]
		then
			###TEST KEY BY ENCRYPTING A MESSAGE##########################
			echo $account_name_chosen >${script_path}/${account_name_chosen}_account.dat
			gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file -r $handover_account --passphrase ${account_password} --pinentry-mode loopback --encrypt --sign ${script_path}/${account_name_chosen}_account.dat 1>/dev/null 2>/dev/null
			if [ $? = 0 ]
			then
				###REMOVE ENCRYPTION SOURCE FILE#############################
				rm ${script_path}/${account_name_chosen}_account.dat

				####TEST KEY BY DECRYPTING THE MESSAGE#######################
				gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${account_password} --output ${script_path}/${account_name_chosen}_account.dat --decrypt ${script_path}/${account_name_chosen}_account.dat.gpg 1>/dev/null 2>/dev/null
				encrypt_rt=$?
				if [ $encrypt_rt = 0 ]
				then
					extracted_name=`cat ${script_path}/${account_name_chosen}_account.dat|sed 's/ //g'`
					if [ $extracted_name = $account_name_chosen ]
					then
						###IF SUCCESSFULL DISPLAY WELCOME MESSAGE AND SET LOGIN VARIABLE###########
						dialog_login_welcome_display=`echo $dialog_login_welcome|sed "s/<account_name_chosen>/${account_name_chosen}/g"`
						dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_login_welcome_display" 0 0
						user_logged_in=1
					fi
				else
					dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_login_wrongpw" 0 0
				fi
				##############################################################
			else
				###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND################
				dialog_login_nokey_display="${dialog_login_nokey} (-> ${account_name_chosen})!"
				dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_login_nokey_display" 0 0
			fi
		else
			###DISPLAY MESSAGE THAT KEY HAS NOT BEEN FOUND###############
			dialog_login_nokey2_display=`echo $dialog_login_nokey2|sed "s/<account_name>/${account_name_chosen}/g"`
			dialog --title "$dialog_type_title_warning" --backtitle "Universal Credit System" --msgbox "$dialog_login_nokey2_display" 0 0
			clear
		fi
		#############################################################

		###REMOVE TEMPORARY FILES####################################
                rm ${script_path}/${account_name_chosen}_account.dat.gpg 2>/dev/null
	        rm ${script_path}/${account_name_chosen}_account.dat 2>/dev/null
}
create_keys(){
		name_chosen=$1
		name_passphrase=$2
		name_cleared=$name_chosen
		
		###SET FILESTAMP TO NOW######################################
		file_stamp=`date +%s`

		###CREATE RANDOM 5 DIGIT NUMBER AS PIN#######################
                key_rn=`head -10 /dev/urandom|tr -dc "[:digit:]"|head -c 5`

		###CREATE ADDRESS BY HASHING NAME,STAMP AND PIN##############
		name_hashed=`echo "${name_cleared}_${file_stamp}_${key_rn}"|shasum -a 256|cut -d ' ' -f1`

		###DISPLAY PROGRESS BAR######################################
		echo "0"|dialog --title "$dialog_keys_title" --backtitle "Universal Credit System" --gauge "$dialog_keys_create1" 0 0 0
		
		###GENERATE KEY##############################################
		gpg --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${name_passphrase} --quick-gen-key ${name_hashed} rsa4096 sign,auth,encr none
		rt_quiery=$?
		if [ $rt_quiery = 0 ]
		then
			###DISPLAY PROGRESS ON STATUS BAR############################
			echo "33"|dialog --title "$dialog_keys_title" --backtitle "Universal Credit System" --gauge "$dialog_keys_create2" 0 0 0
			
			###EXPORT PUBLIC KEY#########################################
			gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${name_passphrase} --output ${script_path}/${name_cleared}_${key_rn}_${file_stamp}_pub.asc --export $name_hashed
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				###DISPLAY PROGRESS ON STATUS BAR############################
				echo "66"|dialog --title "$dialog_keys_title" --backtitle "Universal Credit System" --gauge "$dialog_keys_create3" 0 0 0

				###DISPLAY NOTIFICATION FOR KEY-EXPORT#######################
				dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_keys_export" 0 0

				###CLEAR SCREEN
				clear
		
				###EXPORT PRIVATE KEY########################################
				gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${name_passphrase} --output ${script_path}/${name_cleared}_${key_rn}_${file_stamp}_priv.asc --export-secret-keys $name_hashed
				rt_quiery=$?
				if [ $rt_quiery = 0 ]
				then
					###CREATE PROOFS DIRECTORY###################################
					mkdir ${script_path}/proofs/${name_hashed}

					###STEP INTO THIS DIRECTORY##################################
					cd ${script_path}

					###CREATE TSA QUIERY FILE####################################
					openssl ts -query -data ${script_path}/${name_cleared}_${key_rn}_${file_stamp}_pub.asc -no_nonce -sha512 -out ${script_path}/freetsa.tsq 1>&2
					rt_quiery=$?
					if [ $rt_quiery = 0 ]
					then
						###STEP BACK INTO UCS HOME DIR###############################
						cd ${script_path}

						###SET QUIERY TO TSA#########################################
						curl --silent -H "Content-Type: application/timestamp-query" --data-binary '@freetsa.tsq' https://freetsa.org/tsr > ${script_path}/freetsa.tsr
						rt_quiery=$?
						if [ $rt_quiery = 0 ]
						then
							###STEP INTO CERTS DIRECTORY#################################
							cd ${script_path}/certs
		
							###DOWNLOAD LATEST TSA CERTIFICATES##########################
							wget -q https://freetsa.org/files/tsa.crt
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								wget -q https://freetsa.org/files/cacert.pem
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
									mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/cacert.pem
									openssl ts -verify -queryfile ${script_path}/freetsa.tsq -in ${script_path}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>&2
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										mv ${script_path}/freetsa.tsq ${script_path}/proofs/${name_hashed}/freetsa.tsq
										mv ${script_path}/freetsa.tsr ${script_path}/proofs/${name_hashed}/freetsa.tsr
									else
										rm ${script_path}/freetsa.tsq 2>/dev/null
										rm ${script_path}/freetsa.tsr 2>/dev/null
									fi
								else
									rm ${script_path}/certs/tsa.crt 2>/dev/null
									rm ${script_path}/certs/cacert.pem 2>/dev/null
								fi
							else
								rm ${script_path}/certs/tsa.crt 2>/dev/null
							fi
							#############################################################
						else
							###REMOVE QUIERY AND RESPONSE################################
							rm ${script_path}/freetsa.tsq 2>/dev/null
							rm ${script_path}/freetsa.tsr 2>/dev/null
						fi
					else
						###REMOVE TSA QUIERY FILE####################################
						rm ${script_path}/freetsa.tsq 2>/dev/null
					fi
				
					###CHECK IF EVERYTHING WAS SUCCESSFUL########################
					if [ $rt_quiery = 0 ]
					then
						###DISPLAY PROGRESS ON STATUS BAR############################
						echo "100"|dialog --title "$dialog_keys_title" --backtitle "Universal Credit System" --gauge "$dialog_keys_create4" 0 0 0
						clear

						###COPY EXPORTED KEYS INTO KEYS-FOLDER#######################
						cp ${script_path}/${name_cleared}_${key_rn}_${file_stamp}_pub.asc ${script_path}/keys/${name_hashed}.${file_stamp}
                                                
						###DISPLAY NOTIFICATION THAT EVERYTHING WAS FINE#############
						dialog_keys_final_display=`echo $dialog_keys_final|sed "s/<name_chosen>/${name_chosen}/g"|sed "s/<name_hashed>/${name_hashed}/g"|sed "s/<key_rn>/${key_rn}/g"|sed "s/<file_stamp>/${file_stamp}/g"`
                                                dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_keys_final_display" 0 0
						clear
					else
						###Remove Proofs-folder of Account that could not be created#
						rmdir ${script_path}/proofs/${name_hashed} 2>/dev/null

						###Remove created keys out of keyring########################
						key_fp=`gpg --no-default-keyring --keyring=${script_path}/keyring.file --with-colons --list-keys ${name_cleared}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
						gpg --batch --yes --no-default-keyring --keyring=${script_path}/keyring.file --delete-secret-keys ${key_fp}
						gpg --batch --yes --no-default-keyring --keyring=${script_path}/keyring.file --delete-keys ${key_fp}
					fi
				fi
			fi
		fi
		return $rt_quiery
}
make_signature(){
			transaction_message=$1
			trx_now=$2
			create_index_file=$3
			
			###CHECK IF INDEX FILE NEEDS TO BE CREATED#######################
			if [ $create_index_file = 0 ]
                        then
				###IF NOT WRITE TRX MESSAGE TO FILE##############################
				message=${script_path}/trx/${trx_now}.${handover_account}
				message_blank=${script_path}/message_blank.dat
				touch ${message_blank}
				echo $transaction_message >>${message_blank}
				#################################################################
			else
				###IF YES.....###################################################
				message=${script_path}/proofs/${handover_account}/${handover_account}.txt
                                message_blank=${script_path}/message_blank.dat
				touch ${message_blank}
				touch ${script_path}/index_keys.tmp
				ls -1 ${script_path}/keys >${script_path}/index_keys.tmp
				while read line
				do
					###WRITE KEYFILE TO INDEX FILE###################################
					key_hash=`shasum -a 512 <${script_path}/keys/${line}|cut -d ' ' -f1`
                                        key_path="keys/${line}"
                                        echo "${key_path} ${key_hash} ${trx_now}" >>${message_blank}
					#################################################################

					###IF TSA QUIERY FILE IS AVAILABLE ADD TO INDEX FILE#############
					freetsa_qfile="${script_path}/proofs/${line}/freetsa.tsq"
					if [ -s $freetsa_qfile ]
					then
						freetsa_qfile_path="proofs/$line/freetsa.tsq"
						freetsa_qfile_hash=`shasum -a 512 <${script_path}/proofs/$line/freetsa.tsq|cut -d ' ' -f1`
						echo "${freetsa_qfile_path} ${freetsa_qfile_hash} ${trx_now}" >>${message_blank}
					fi
					#################################################################

					###IF TSA RESPONSE FILE IS AVAILABLE ADD TO INDEX FILE###########
					freetsa_rfile="${script_path}/proofs/${line}/freetsa.tsr"
					if [ -s $freetsa_rfile ]
					then
						freetsa_rfile_path="proofs/$line/freetsa.tsr"
						freetsa_rfile_hash=`shasum -a 512 <${script_path}/proofs/$line/freetsa.tsr|cut -d ' ' -f1`
						echo "${freetsa_rfile_path} ${freetsa_rfile_hash} ${trx_now}" >>${message_blank}
					fi
					#################################################################
				done <${script_path}/index_keys.tmp
				
				###REMOVE KEYLIST################################################
				rm ${script_path}/index_keys.tmp

				####WRITE TRX LIST TO INDEX FILE#################################
                                cat ${script_path}/index_trx.tmp >>${message_blank}

				###REMOVE TRXLIST################################################
				rm ${script_path}/index_trx.tmp
			fi
			#################################################################
			
			###CHECK SIZE OF FILE TO BE SIGNED###############################
			total_blank=`wc -l <${message_blank}` 
			total_blank=$(( $total_blank + 16 ))

			###SIGN FILE AND REMOVE GPG WRAPPER##############################
			gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --digest-algo SHA512 --local-user $handover_account --clearsign ${message_blank} 2>/dev/null
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				rm ${message_blank} 2>/dev/null
				tail -$total_blank ${message_blank}.asc|sed 's/-----BEGIN PGP SIGNATURE-----//g'|sed 's/-----END PGP SIGNATURE-----//g' >${message}
				rm ${message_blank}.asc 2>/dev/null
			fi
			#################################################################
}
verify_signature(){
			trx_to_verify=$1
			user_signed=$2
			signed_correct=0
			build_message=${script_path}/verify_trx.tmp

			###CHECK NO OF LINES OF THE TRX TO VERIFY#####################
			no_lines_trx=`wc -l < ${trx_to_verify}`

			###CALCULATE SIZE OF MESSAGE##################################
			till_sign=$(( $no_lines_trx - 16 ))	#-16

			###REBUILD GPG FILE###########################################
			echo "-----BEGIN PGP SIGNED MESSAGE-----" >${build_message}
			echo "Hash: SHA512" >>${build_message}
			echo "" >>${build_message}
			head -${till_sign} ${trx_to_verify} >>${build_message}
			echo "-----BEGIN PGP SIGNATURE-----" >>${build_message}
			echo "" >>${build_message}
			tail -14 ${trx_to_verify}|head -13 >>${build_message}
			echo "-----END PGP SIGNATURE-----" >>${build_message}
			##############################################################

			###CHECK GPG FILE#############################################
			gpg --status-fd 1 --no-default-keyring --keyring=${script_path}/keyring.file --verify ${build_message} >${script_path}/gpg_verify.tmp 2>/dev/null
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				signed_correct=`cat ${script_path}/gpg_verify.tmp|grep "GOODSIG"|grep "${user_signed}"|wc -l`
			else
				rm ${trx_to_verify} 2>/dev/null
			fi
			###############################################################

			rm ${build_message} 2>/dev/null
			rm ${script_path}/gpg_verify.tmp 2>/dev/null
			return $rt_quiery
}
check_input(){
		input_string=$1
		rt_quiery=0
		alnum_there=0
		length_counter=0

		###CHECK LENGTH OF INPUT STRING########################################
		length_counter=`echo $input_string|wc -m|sed 's/ //g'`

		###CHECK IF ALPHANUMERICAL CHARS ARE IN INPUT STRING###################
		alnum_there=`echo $input_string|grep -c '[^[:alnum:]]'`

		###IF ALPHANUMERICAL CHARS ARE THERE DISPLAY NOTIFICATION##############
		if [ $alnum_there -gt 0 ]
		then
			dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_check_msg1" 0 0
			rt_quiery=1
		fi
		#######################################################################

		###IF INPUT LESS OR EQUAL 1 DISPLAY NOTIFICATION#######################
		if [ $length_counter -le 1 ]
                then
                        dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_check_msg2" 0 0
                	rt_quiery=1
		fi
		#######################################################################

		###IF INPUT GREATER 30 CHARS DISPLAY NOTIFICATION######################
		if [ $length_counter -gt 31 ]
		then
			dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_check_msg3" 0 0
			rt_quiery=1
		fi
		#######################################################################

		return $rt_quiery
}
build_ledger(){
		date_stamp=1590962400

		###LOAD ALL ACCOUNTS AND IGNORE BLACKLISTED#########
		ls -1 ${script_path}/keys >${script_path}/accounts.tmp
		cat ${script_path}/blacklisted_accounts.dat >>${script_path}/accounts.tmp
		cat ${script_path}/accounts.tmp|sort -t . -k2 >${script_path}/accounts_sorted.tmp
		cat ${script_path}/accounts_sorted.tmp|uniq >${script_path}/accounts_list.tmp

		###CREATE FRIENDS LIST##############################
		touch ${script_path}/friends_trx.tmp
		touch ${script_path}/friends.tmp
		cd ${script_path}/trx
		grep -l "S:${handover_account}" *.* >${script_path}/friends_trx.tmp 2>/dev/null
		cd ${script_path}
		while read line
		do
			head -1 ${script_path}/trx/${line}|cut -d ' ' -f3|cut -d ':' -f2 >${script_path}/friends.tmp
		done <${script_path}/friends_trx.tmp
		cat ${script_path}/friends.tmp|uniq >${script_path}/friends.dat
		rm ${script_path}/friends.tmp 2>/dev/null
		####################################################

		###EMPTY LEDGER#####################################
		rm ${script_path}/ledger.tmp 2>/dev/null
		touch ${script_path}/ledger.tmp
		####################################################

		###SET FOCUS########################################
		focus=`date +%Y%m%d --date=@${date_stamp}`
		now_stamp=`date +%s`
		now=`date +%Y%m%d --date=@${now_stamp}`
		multi=1
		multi_next=$(( $multi * 2 ))
		day_counter=1
		####################################################

		###INIT STATUS BAR##################################
		now_date_status=`date +%s --date=${now}`
		no_seconds_total=$(( $now_date_status - $date_stamp ))
		no_days_total=`expr $no_seconds_total / 86400`
		percent_per_day=`echo "scale=2; 100 / ${no_days_total}"|bc`
		is_greater_one=`echo "${percent_per_day}>=1"|bc`
		if [ $is_greater_one = 0 ]
	        then
	               	percent_per_day="0${percent_per_day}"
	        fi
		current_percent=0
		current_percent_display=0
		####################################################

		###LOAD ALL PREVIOUS TRANSACTIONS###################
		cd ${script_path}/trx
		touch ${script_path}/trxlist_full.tmp
		touch ${script_path}/trxlist.tmp
		touch ${script_path}/trxlist_full_sorted.tmp
		touch ${script_path}/trxlist_formatted.tmp
		grep -l "S:" *.* >${script_path}/trxlist_full.tmp 2>/dev/null
		cat ${script_path}/trxlist_full.tmp >${script_path}/trxlist.tmp 2>/dev/null
		cat ${script_path}/blacklisted_trx.dat >>${script_path}/trxlist.tmp 2>/dev/null
		cat ${script_path}/trxlist.tmp|sort -t . -k1 >${script_path}/trxlist_full_sorted.tmp
		rm ${script_path}/trxlist.tmp
		rm ${script_path}/trxlist_full.tmp
		while read line
		do
		     	stamp_to_convert=`echo $line|cut -d '.' -f1`
		       	stamp_converted=`date +%Y%m%d --date=@${stamp_to_convert}`
		       	trx_sender=`echo $line|cut -d '.' -f2`
		       	echo "${stamp_to_convert} ${stamp_converted} ${stamp_to_convert}.${trx_sender}" >>${script_path}/trxlist_formatted.tmp
		done <${script_path}/trxlist_full_sorted.tmp
		rm {script_path}/trxlist_full_sorted.tmp 2>/dev/null
		####################################################

		###AS LONG AS FOCUS LESS OR EQUAL YET..#############
		while [ $focus -le $now ]
		do
			###STATUS BAR####################################
			#clear
			dialog_for_ledger_display=`echo $dialog_ledger|sed "s/<focus>/${focus}/g"`
			echo "$current_percent_display"|dialog --title "$dialog_ledger_title" --backtitle "Universal Credit System" --gauge "$dialog_for_ledger_display" 0 0 0
			current_percent=`echo "${current_percent} + ${percent_per_day}"|bc`
			current_percent_display=`echo "${current_percent} / 1"|bc`
			#################################################

			###CALCULATE CURRENT AND NEXT COINLOAD###########
       			if [ $day_counter -eq $multi_next ]
			then
				multi=$(( $multi * 2 ))
				multi_next=$(( $multi * 2 ))
			fi
			coinload=`echo "${initial_coinload} / ${multi}"|bc`
			is_greater_one=`echo "${coinload}>=1"|bc`
		        if [ $is_greater_one = 0 ]
	        	then
	                	coinload="0${coinload}"
	                fi
			next_coinload=`echo "${initial_coinload} / ${multi_next}"|bc`
			is_greater_one=`echo "${next_coinload}>=1"|bc`
		        if [ $is_greater_one = 0 ]
	        	then
	                	next_coinload="0${next_coinload}"
	                fi
			###################################################


			###GO TROUGH ACCOUNTS LINE BY LINE#####################
			while read line
			do
				###EXTRACT ACCOUNT DATA FOR CHECK############################
				account_name=`echo $line|cut -d '.' -f1`
				account_hash=`shasum -a 256 <${script_path}/keys/${line}|cut -d ' ' -f1`
				account_date_unformatted=`echo $line|cut -d '.' -f2`
				account_date=`date +%Y%m%d --date=@${account_date_unformatted}`
				#############################################################
				
				###IF FOCUS EQUAL TO DATE OF ACCOUNT CREATION GO AHEAD#######
				if [ $focus -ge $account_date ]
				then
					###SET INITAL VALUES FOR ACCOUNT###############
					account_balance=0
					###############################################

					###CHECK IF ACCOUNT ALREADY IN AND ADD ACCOUNT IF NOT###########
					if [ $focus -eq $account_date ]
					then
						account_there=`grep -c "${account_name}.${account_hash}" ${script_path}/ledger.tmp`
						if [ $account_there = 0 ]
						then
							echo "${account_name}.${account_hash}=0" >>${script_path}/ledger.tmp
						fi
					fi
					########################################################################

					###GRANT COINLOAD#######################################################
					account_prev_balance=`cat ${script_path}/ledger.tmp|grep "${account_name}.${account_hash}"|cut -d '=' -f2`
					account_balance=`echo "${account_prev_balance} + ${coinload}"|bc`
					is_greater_one=`echo "${account_balance}>=1"|bc`
					if [ $is_greater_one = 0 ]
					then
						account_balance="0${account_balance}"
					fi
					sed -i "s/${account_name}.${account_hash}=${account_prev_balance}/${account_name}.${account_hash}=${account_balance}/g" ${script_path}/ledger.tmp
					########################################################################
				fi
			done <${script_path}/accounts_list.tmp

			cat ${script_path}/trxlist_formatted.tmp|grep " ${focus} " >${script_path}/trxlist_${focus}.tmp
			###############################################

			###GO TROUGH TRX OF THAT DAY LINE BY LINE#####################
			while read line
			do
				###EXRACT DATA FOR CHECK######################################
			        trx_filename=`echo $line|cut -d ' ' -f3`
				trx_date_filename=`echo $trx_filename|cut -d '.' -f2`
				trx_date_inside=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f4`
				trx_sender=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f1|cut -d ':' -f2`
				trx_sender_file=`ls -1 ${script_path}/keys|grep "${trx_sender}"|head -1`
				trx_sender_hash=`shasum -a 256 <${script_path}/keys/${trx_sender_file}|cut -d ' ' -f1`
				trx_receiver=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f3|cut -d ':' -f2`
				trx_receiver_hash=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f5`
				##############################################################

				###CHECK IF FRIENDS KNOW OF THIS TRX##########################
				number_of_friends_trx=0
				number_of_friends_add=0
				while read line
				do
					###IGNORE CONFIRMATIONS OF TRX PARTICIPANTS
					if [ $trx_sender != $line -a $trx_receiver != $line ]
					then
						number_of_friends_add=`grep -c "${trx_filename}" ${script_path}/proofs/${line}/${line}.txt`
						number_of_friends_trx=$(( $number_of_friends_trx + $number_of_friends_add ))
					fi
				done <${script_path}/friends.dat
				##############################################################

				###EXTRACT TRX DATA###########################################
				trx_amount=`head -1 ${script_path}/trx/${trx_filename}|cut -d ' ' -f2`
				trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
				is_greater_one=`echo "${trx_fee}>=1"|bc`
                               	if [ $is_greater_one = 0 ]
				then
               	                	trx_fee="0${trx_fee}"
                       	        fi
              	                trx_total=`echo "${trx_amount} + ${trx_fee}"|bc`
				account_balance=`cat ${script_path}/ledger.tmp|grep "${trx_sender}.${trx_sender_hash}"|cut -d '=' -f2`
				##############################################################

				###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
                      	        account_check_balance=`echo "${account_balance} - ${trx_total}"|bc`
                              	enough_balance=`echo "${account_check_balance}>=0"|bc`
        	                if [ $enough_balance = 1 ]
                                then
					####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)############
					trx_hash=`shasum -a 512 <${script_path}/trx/${trx_filename}|cut -d ' ' -f1`
                        		trx_path="trx/${trx_filename}"
                              		echo "${trx_path} ${trx_hash} ${trx_now}" >>${script_path}/index_trx.tmp
					##############################################################

					###SET BALANCE FOR SENDER#####################################
                                      	account_balance=$account_check_balance
					is_greater_one=`echo "${account_balance}>=1"|bc`
				        if [ $is_greater_one = 0 ]
        	                      	then
                	              		account_balance="0${account_balance}"
                        	      	fi
					account_prev_balance=`cat ${script_path}/ledger.tmp|grep "${trx_sender}.${trx_sender_hash}"|cut -d '=' -f2`
					sed -i "s/${trx_sender}.${trx_sender_hash}=${account_prev_balance}/${trx_sender}.${trx_sender_hash}=${account_balance}/g" ${script_path}/ledger.tmp
					##############################################################

					###IF FRIEDS ACKNOWLEDGED TRX HIGHER BALANCE OF RECEIVER######
					if [ $number_of_friends_trx -gt 0 ]
					then
						receiver_in_ledger=`grep -c "${trx_receiver}.${trx_receiver_hash}" ${script_path}/ledger.tmp`
						if [ $receiver_in_ledger = 0 ]
						then
							echo "${trx_receiver}.${trx_receiver_hash}=${trx_amount}" >>${script_path}/ledger.tmp
						else
							receiver_old_balance=`cat ${script_path}/ledger.tmp|grep "${trx_receiver}.${trx_receiver_hash}"|cut -d '=' -f2`
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
							sed -i "s/${trx_receiver}.${trx_receiver_hash}=${receiver_old_balance}/${trx_receiver}.${trx_receiver_hash}=${receiver_new_balance}/g" ${script_path}/ledger.tmp
						fi
					fi
					##############################################################
        	                fi
				##############################################################
			done <${script_path}/trxlist_${focus}.tmp
			##############################################################

			###DELETE TRX LIST FOR THIS DAY###############################
			rm ${script_path}/trxlist_${focus}.tmp 2>/dev/null

			###RAISE VARIABLES FOR NEXT RUN###############################
			in_days=$(( $multi_next - $day_counter ))
			date_stamp=$(( $date_stamp + 86400 ))
			focus=`date +%Y%m%d --date=@${date_stamp}`
			day_counter=$(( $day_counter + 1 ))
			##############################################################
		done
		cd ${script_path}/
}
check_archive(){
			path_to_tarfile=$1
			touch ${script_path}/tar_check.tmp

			###CHECK TARFILE CONTENT######################################
			tar -tf $path_to_tarfile >${script_path}/tar_check.tmp
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				script_there=0
				files_not_homedir=0
				files_to_fetch=""
				files_to_fetch_display="${dialog_content}\n"

				###GO THROUGH CONTENT LIST LINE BY LINE#######################
				while read line
				do
					###CHECK IF ANY *.sh FILES ARE INCLUDED#######################
					script_there=`echo $line|grep -c ".sh"`
					if [ $script_there = 0 ]
					then
						###CHECK IF FILES MATCH TARGET-DIRECTORIES AND IGNORE OTHERS##
						files_not_homedir=`echo $line|cut -d '/' -f1`
             		   			case $files_not_homedir in
                        				"keys")		files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
									files_to_fetch_display="${files_to_fetch_display}${line}\n"
                                	        			;;
                   		     			"proofs")	files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
									files_to_fetch_display="${files_to_fetch_display}${line}\n"
                                        				;;
                        				"trx")		files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
									files_to_fetch_display="${files_to_fetch_display}${line}\n"
                                		        		;;
							*)		rt_quiery=1
									;;
                				esac
						##############################################################
					else
						rt_quiery=1
					fi
					##############################################################
				done <${script_path}/tar_check.tmp
				##############################################################
			fi
			##############################################################

			###REMOVE THE LIST THAT CONTAINS THE CONTENT##################
			rm ${script_path}/tar_check.tmp

			return $rt_quiery
}

##################
#Main Menu Screen#
##################
script_name=${0}
script_path=$(dirname $(readlink -f ${0}))
core_system_version="v0.0.1"
current_fee="0.001"
currency_symbol="UCC"
initial_coinload=10000
user_logged_in=0
action_done=1
make_ledger=1
files_to_fetch=""

###MAKE CLEAN START#########
rm ${script_path}/*.tmp 2>/dev/null
rm ${script_path}/*.dat 2>/dev/null

###SOURCE LANGUAGE-SELECTION
. ${script_path}/lang.conf
. ${script_path}/lang/${lang_file}
############################

while [ 1 != 2 ]
do
	if [ $user_logged_in = 0 ]
	then
		main_menu=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_main_end" --title "UNIVERSAL CREDIT SYSTEM" --backtitle "Universal Credit System ${core_system_version}" --menu "MMMWMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMWMWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMWK0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMW0ONMMMMMMMMMMMMMMMMMWWX0xdllcloxOKWMMMMMMMMMMM\nMMW0xXMMMMMMMMMMMMMMMMXx:'..   .......,lONMMMMMMMM\nMMKokWMMMMMMMMMMMMMMXo.    .:xOKKXK0kdl,.,xNMMWMMM\nMMx:0MMMMMMMMMMMMMM0,      :0NMMMMMMMWWN0o,;OWMMMM\nMMo;KMMMMMMMMMMMMMX;        .,dXMMMMMMMMMWKl'dNMMM\nMMo'OMMMMMMMMMMMMMx.           ;KMMMMMMMMWWWx'oWMM\nMMk'lWMMMMMMMMMMMMd             oWMMMMMMMMMMWo'kMM\nMMWo.dWMMMMMMMMMMMO.            lWMMMMMMMMMMMX;cWM\nMMWXo'lXMMMMMMMMMMWk.          .OMMMMMMMMMMMMWlcXM\nMMMMNx;;xXWWMMWMMMMWKd;.      .xWMMMMMMMMMMMMWooWM\nMMMMMWXd,'cx0NWWMMMWWXx'    .;OWMMMMMMMMMMMMMXokMM\nMMMMMMMMXx:'.';clllc;.   .'cONMMMMMMMMMMMMMMWkxNMM\nMMMMMMMMMMWXOdl:;,,,,:ldOKNMMMMMMMMMMMMMMMMMKkXMMM\nMMMMMMMMMMMMMMMMMWWWMMMMMMMMMMMMMMMMMMMMMMWK0XMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKKWWWMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWWMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n" 0 0 0 "$dialog_main_logon" "" "$dialog_main_create" "" "$dialog_main_lang" "" "$dialog_main_end" "" 3>&1 1>&2 2>&3`
		if [ $? != 0 ]
        	then
                	clear
                	exit
        	else
                	clear
                	case "$main_menu" in
                        	"$dialog_main_logon")   account_entered_correct=0
							account_entered_aborted=0
							while [ $account_entered_correct = 0 ]
							do
								account_chosen=`dialog --title "$dialog_main_logon" --backtitle "Universal Credit System" --inputbox "$dialog_login_display_account" 0 0 "" 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									check_input $account_chosen
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										account_rn=`dialog --title "$dialog_main_logon" --backtitle "Universal Credit System" --insecure --passwordbox "$dialog_login_display_loginkey" 0 0 "" 3>&1 1>&2 2>&3`
                                                                                rt_quiery=$?
                                                                                if [ $rt_quiery = 0 ]
                                                                                then
                                                                                        check_input $account_rn
                                                                                        rt_quiery=$?
                                                                                        if [ $rt_quiery = 0 ]
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
								password_chosen=`dialog --title "$dialog_main_logon" --backtitle "Universal Credit System" --insecure --passwordbox "$dialog_login_display_pw" 0 0 "" 3>&1 1>&2 2>&3`
                                                                rt_quiery=$?
                                                                if [ $rt_quiery = 0 ]
                                                                then
									login_account $account_chosen $account_rn $password_chosen
								fi
							fi
							;;
                        	"$dialog_main_create")  account_entered_correct=0
							while [ $account_entered_correct = 0 ]
							do
								account_chosen=`dialog --title "$dialog_main_create" --backtitle "Universal Credit System" --inputbox "$dialog_login_display_account" 0 0 "" 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									check_input $account_chosen
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										password_found=0
	     									while [ $password_found = 0 ]
               									do
                									password_first=`dialog --insecure --passwordbox "$dialog_keys_pw1" 0 0 3>&1 1>&2 2>&3`
											rt_quiery=$?
											if [ $rt_quiery = 0 ]
											then
               											check_input $password_first
												rt_quiery=$?
												if [ $rt_quiery = 0 ]
												then
													clear
													password_second=`dialog --insecure --passwordbox "$dialog_keys_pw2" 0 0 3>&1 1>&2 2>&3`
													rt_quiery=$?
													if [ $rt_quiery = 0 ]
													then
														clear
                                       										if [ $password_first != $password_second ]
                        											then
															dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_keys_pwmatch" 0 0
															clear
														else
															account_entered_correct=1
                                											password_found=1
															create_keys $account_chosen $password_second
															rt_quiery=$?
															if [ $rt_quiery = 0 ]
															then
																dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_keys_success" 0 0
															else
																dialog --title "$dialog_type_titel_error" --backtitle "Universal Credit System" --msgbox "$dialog_keys_fail" 0 0
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
									account_entered_correct=1
								fi
							done
							;;
				"$dialog_main_lang")	ls -1 ${script_path}/lang/ >${script_path}/languages.tmp
							lang_to_display=""
							while read line
							do
								lang_ex_short=`echo $line|cut -d '_' -f2`
								lang_ex_full=`echo $line|cut -d '_' -f3|cut -d '.' -f1`
								lang_to_display="${lang_to_display}$lang_ex_short $lang_ex_full "
							done <${script_path}/languages.tmp
							lang_selection=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_cancel" --title "$dialog_main_lang" --backtitle "Universal Credit System" --menu "$dialog_lang" 0 0 0 ${lang_to_display} 3>&1 1>&2 2>&3`
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								new_lang_file=`cat ${script_path}/languages.tmp|grep "lang_${lang_selection}_"`
								if [ $lang_file != $new_lang_file ]
								then
									sed -i "s/lang_file=${lang_file}/lang_file=${new_lang_file}/g" >${script_path}/lang.conf
									. ${script_path}/lang.conf
									. ${script_path}/lang/${lang_file}
								fi
							fi
							rm ${script_path}/languages.tmp
							;;
                        	"$dialog_main_end")     unset user_logged_in
							rm ${script_path}/*.tmp 2>/dev/null
							rm ${script_path}/*.dat 2>/dev/null
							exit
							;;
                	esac
        	fi

	else
		if [ $action_done = 1 ]
		then
			###FREETSA CERTIFICATE DOWNLOAD###
			freetsa_available=0
			freetsa_cert_available=0
			freetsa_rootcert_available=0
			cd ${script_path}/certs
			if [ ! -s ${script_path}/certs/freetsa/tsa.crt ]
			then
				wget -q https://freetsa.org/files/tsa.crt
				rt_quiery=$?
				if [ $rt_quiery = 0 ]
				then
					mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
					freetsa_cert_available=1
				else
					rm ${script_path}/certs/tsa.crt 2>/dev/null
				fi
			else
				freetsa_cert_available=1
			fi
			if [ ! -s ${script_path}/certs/freetsa/cacert.pem ]
			then
				wget -q https://freetsa.org/files/cacert.pem
				rt_quiery=$?
				if [ $rt_quiery = 0 ]
				then
					mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/cacert.pem
					freetsa_rootcert_available=1
				else
					rm ${script_path}/certs/cacert.pem 2>/dev/null
				fi
			else
				freetsa_rootcert_available=1
			fi
			cd ${script_path}
			if [ $freetsa_cert_available = 1 -a $freetsa_rootcert_available = 1 ]
			then
				freetsa_available=1
			fi
			######################################

			###VERIFY USERS AND THEIR TSA STAMPS###
			touch ${script_path}/blacklisted_accounts.dat
			touch ${script_path}/blacklisted_trx.dat
			touch ${script_path}/all_accounts.tmp
			ls -1 ${script_path}/keys >${script_path}/all_accounts.tmp
			while read line
			do
				accountname_to_check=`echo $line|cut -d '.' -f1`
				###FREETSA CHECK###############################
				if [ $freetsa_available = 1 ]
				then
					openssl ts -verify -queryfile ${script_path}/proofs/${accountname_to_check}/freetsa.tsq -in ${script_path}/proofs/${accountname_to_check}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>/dev/null 2>/dev/null
					rt_quiery=$?
					if [ $rt_quiery = 0 ]
					then
						openssl ts -reply -in ${script_path}/proofs/${accountname_to_check}/freetsa.tsr -text >${script_path}/timestamp_check.tmp 2>/dev/null
						rt_quiery=$?
						if [ $rt_quiery = 0 ]
						then
							openssl ts -verify -data ${script_path}/keys/${line} -in ${script_path}/proofs/${accountname_to_check}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt 1>/dev/null 2>/dev/null
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								date_to_verify=`cat ${script_path}/timestamp_check.tmp|grep "Time stamp:"|cut -c 13-37`
								date_to_verify_converted=`date --date="${date_to_verify}" +%s`
								accountdate_to_verify=`echo $line|cut -d '.' -f2`
								creation_date_diff=$(( $date_to_verify_converted - $accountdate_to_verify ))
								if [ $creation_date_diff -gt 0 ]
								then
									if [ $creation_date_diff -gt 120 ]
									then
										echo $line >>${script_path}/blacklisted_accounts.dat
									fi
								else
									echo $line >>${script_path}/blacklisted_accounts.dat
								fi
							else
								echo $line >>${script_path}/blacklisted_accounts.dat
							fi
						else
							echo $line >>${script_path}/blacklisted_accounts.dat
						fi
						rm ${script_path}/timestamp_check.tmp 2>/dev/null
					else
						echo $line >>${script_path}/blacklisted_accounts.dat
					fi
				fi
				###############################################
			done <${script_path}/all_accounts.tmp

			###CHECK KEYS IF ALREADY IN KEYRING AND IMPORT THEM IF NOT
			touch ${script_path}/keys_import.tmp
			touch ${script_path}/keylist_gpg.tmp
 	              	ls -1 ${script_path}/keys >${script_path}/keys_import.tmp
			gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --with-colons --list-keys >${script_path}/keylist_gpg.tmp 2>/dev/null
  	              	while read line
  	              	do
                        	key_uname=`echo $line|cut -d '.' -f1`
 	                        key_imported=`grep -c "${key_uname}" ${script_path}/keylist_gpg.tmp`
        	                if [ $key_imported = 0 ]
                 		then
                                	gpg --batch --no-default-keyring --keyring=${script_path}/keyring.file --import ${script_path}/keys/${line} 2>/dev/null
                      		        rt_quiery=$?
                                	if [ $rt_quiery -gt 0 ]
                                	then
						dialog_import_fail_display=`echo $dialog_import_fail|sed "s/<key_uname>/${key_uname}/g"|sed "s/<file>/${line}/g"`
                        			dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_import_fail_display" 0 0
                                        	key_already_blacklisted=`grep -c "${key_uname}" ${script_path}/blacklisted_accounts.dat`
                                        	if [ $key_already_blacklisted = 0 ]
                                        	then
                                                	echo "${line}" >>${script_path}/blacklisted_accounts.dat
                                        	fi
                                	fi
                        	fi
                	done <${script_path}/keys_import.tmp
			rm ${script_path}/keys_import.tmp
			rm ${script_path}/keylist_gpg.tmp
                	##########################################################

			###VERIFY TRX AT THE BEGINNING AND MOVE TRX THAT HAVE NOT BEEN SIGNED BY THE OWNER TO BLACKLISTED
			touch ${script_path}/all_trx.tmp
			ls -1 ${script_path}/trx >${script_path}/all_trx.tmp
			while read line
			do
				file_to_check=${script_path}/trx/${line}
				user_to_check=`echo $line|cut -d '.' -f2`
				usr_blacklisted=`grep -c "${user_to_check}" ${script_path}/blacklisted_accounts.dat`
				if [ $usr_blacklisted = 0 ]
				then
					user_file=`ls -1 ${script_path}/keys/|grep "${user_to_check}"`
					verify_signature $file_to_check $user_file
					rt_quiery=$?
					if [ $rt_quiery -gt 0 ]
					then
						echo $file_to_check >>${script_path}/blacklisted_trx.dat
					else
						trx_date_filename=`echo $line|cut -d '.' -f1`
						trx_date_inside=`head -1 ${script_path}/trx/${line}|cut -d ' ' -f4`
						if [ $trx_date_filename != $trx_date_inside ]
						then
							echo $file_to_check >>${script_path}/blacklisted_trx.dat
						fi
					fi
				fi
			done <${script_path}/all_trx.tmp
			####################################################################################
			action_done=0
		fi

		now=`date +%s`
		if [ $make_ledger = 1 ]
		then
			####GET COINS FOR ACCOUNT LOGGED IN
			build_ledger
			no_ack_trx=`wc -l <${script_path}/index.tmp`
			if [ $no_ack_trx -gt 0 ]
			then
				###CREATE INDEX FILE CONTAINING ALL KNOWN TRX
				make_signature "none" $now 1
			fi
			make_ledger=0
		fi
		am_i_blacklisted=`grep -c "${handover_account}" ${script_path}/blacklisted.dat`
		if [ $am_i_blacklisted -gt 0 ]
		then
			dialog_blacklisted_display=`echo $dialog_blacklisted|sed "s/<account_name>/${handover_account}/g"`
			dialog --title "$dialog_type_title_warning" --backtitle "Universal Credit System" --msgbox "$dialog_blacklisted_display" 0 0
		fi
		account_my_balance=`cat ${script_path}/ledger.tmp|grep "${handover_account}.${handover_account_hash}"|cut -d '=' -f2`
		dialog_main_menu_text_display=`echo $dialog_main_menu_text|sed "s/<account_name_chosen>/${account_name_chosen}/g"|sed "s/<handover_account>/${handover_account}/g"|sed "s/<account_my_balance>/${account_my_balance}/g"|sed "s/<currency_symbol>/${currency_symbol}/g"`
		user_menu=`dialog --ok-label "$dialog_main_choose" --cancel-label "$dialog_main_back" --title "$dialog_main_menu" --backtitle "Universal Credit System" --menu "$dialog_main_menu_text_display" 0 0 0 "$dialog_send" "" "$dialog_receive" "" "$dialog_sync" "" "$dialog_history" "" "$dialog_stats" "" "$dialog_logout" "" 3>&1 1>&2 2>&3`
        	if [ $? != 0 ]
		then
			user_logged_in=0
			clear
		else
			clear
			case "$user_menu" in
				"$dialog_send")	recipient_found=0
						order_aborted=0
              			        	while [ $recipient_found = 0 ]
                              		        do
							order_receipient=`dialog --title "$dialog_send" --backtitle "Universal Credit System" --inputbox "$dialog_send_address" 0 0 "" 3>&1 1>&2 2>&3`
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								ls -1 ${script_path}/keys >${script_path}/keylist.tmp
								key_there=`grep -c "${order_receipient}" ${script_path}/keylist.tmp`
								receiver_file=`grep "${order_receipient}" ${script_path}/keylist.tmp|head -1`
								if [ $key_there = 1 ]
								then
									receiver_hash=`shasum -a 256 <${script_path}/keys/${receiver_file}|cut -d ' ' -f1`
									recipient_found=1
									amount_selected=0
								else
									dialog_login_nokey2_display=`echo $dialog_login_nokey2|sed "s/<account_name>/${order_receipient}/g"`
									dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_login_nokey2_display" 0 0
								fi
								while [ $amount_selected = 0 ]
								do
									order_amount=`dialog --title "$dialog_send" --backtitle "Universal Credit System" --inputbox "$dialog_send_amount" 0 0 "1.000000" 3>&1 1>&2 2>&3`
								        rt_quiery=$?
             								if [ $rt_quiery = 0 ]
                							then
										order_amount_alnum=`echo $order_amount|grep -c '[[:alpha:]]'`
										if [ $order_amount_alnum = 0 ]
										then
											order_amount_formatted=`echo $order_amount|sed 's/,/./g'|sed 's/ //g'`
											is_greater_one=`echo "${order_amount_formatted}>=1"|bc`
											if [ $is_greater_one = 0 ]
											then
												order_amount_formatted="0${order_amount_formatted}"
											fi
											trx_fee=`echo "${order_amount_formatted} * ${current_fee}"|bc`
											is_greater_one=`echo "${trx_fee}>=1"|bc`
											if [ $is_greater_one = 0 ]
											then
												trx_fee="0${trx_fee}"
											fi
											order_amount_with_trx_fee=`echo "${order_amount_formatted} + ${trx_fee}"|bc`
											enough_balance=`echo "${account_my_balance} - ${order_amount_with_trx_fee}>0"|bc`
											if [ $enough_balance = 1 ]
											then
												amount_selected=1
											else
												dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_send_fail_nobalance" 0 0
											fi
										else
											dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_send_fail_amount" 0 0
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
							dialog_send_overview_display=`echo $dialog_send_overview|sed "s/<order_receipient>/${order_receipient}/g"|sed "s/<account_my_balance>/${account_my_balance}/g"|sed "s/<currency_symbol>/${currency_symbol}/g"|sed "s/<order_amount_formatted>/${order_amount_formatted}/g"|sed "s/<trx_fee>/${trx_fee}/g"|sed "s/<order_amount_with_trx_fee>/${order_amount_with_trx_fee}/g"`
							dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --yesno "$dialog_send_overview_display" 30 120
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								trx_now=`date +%s`
								make_signature "S:${handover_account} ${order_amount_formatted} R:${order_receipient} ${trx_now} ${receiver_hash}" ${trx_now} 0
								last_trx=`ls -1 ${script_path}/trx/*.${handover_account}|tail -1`
								verify_signature ${last_trx} ${handover_account}
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									cd ${script_path}/trx/
									last_trx=`ls -1 *.${handover_account}|tail -1`
									cd ${script_path}
									trx_to_append="trx/${last_trx} "
									cd ${script_path}/trx/
									touch ${script_path}/dependent_trx.tmp
									grep "R:${handover_account}" *.* >${script_path}/dependent_trx.tmp 2>/dev/null
									rm ${script_path}/dependencies.tmp 2>/dev/null
									touch ${script_path}/dependencies.tmp
									while read line
									do
										user_to_append_till_date=`echo $line|cut -d ':' -f1|cut -d '.' -f1`
										user_to_append=`echo $line|cut -d ':' -f1|cut -d '.' -f2`
										already_in_tree=`grep -c "${user_to_append}=" ${script_path}/dependencies.tmp`
										if [ $already_in_tree = 0 ]
										then
											echo "${user_to_append}=${user_to_append_till_date}" >>${script_path}/dependencies.tmp
										else
											user_to_append_old_date=`cat ${script_path}/dependencies.tmp|grep "${user_to_append}="|cut -d '=' -f2`
											sed -i "s/${user_to_append}=${user_to_append_old_date}/${user_to_append}=${user_to_append_till_date}/g" >${script_path}/dependencies.tmp
										fi
									done <${script_path}/dependent_trx.tmp
									dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --yesno "$dialog_send_trx" 0 0
									small_trx=$?
									if [ $small_trx = 1 ]
									then
										me_key_there=`grep -c "keys/${handover_account}.${handover_account_stamp}" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $me_key_there = 0 ]
										then
											keys_to_append="keys/${handover_account}.${handover_account_stamp} "
										else
											keys_to_append=""
										fi
									else
										keys_to_append="keys/${handover_account}.${handover_account_stamp} "
									fi
									proof_to_append=""
									if [ $small_trx = 1 ]
									then
										me_proofq_there=`grep -c "proofs/${handover_account}/freetsa.tsq" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $me_proofq_there = 0 ]
										then
											proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsq "
										fi
									else
										proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsq "
									fi
									if [ $small_trx = 1 ]
									then
										me_proofr_there=`grep -c "proofs/${handover_account}/freetsa.tsr" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $me_proofr_there = 0 ]
										then
											proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsr "
										fi
									else
										proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsr "
									fi

									while read line
									do
										user_to_append=`echo $line|cut -d '=' -f1`
										user_to_append_key=`ls -1 ${script_path}/keys|grep "${user_to_append}"`
										user_key_there=`grep -c "keys/${user_to_append_key}" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $small_trx = 1 ]
										then
											if [ $user_key_there = 0 ]
											then
												keys_to_append="${keys_to_append}keys/${user_to_append_key} "
											fi
										else
											keys_to_append="${keys_to_append}keys/${user_to_append_key} "
										fi
										user_proofq_there=`grep -c "proofs/${user_to_append}/freetsa.tsq" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $small_trx = 1 ]
										then
											if [ $user_proofq_there = 0 ]
											then
												proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsq "
											fi
										else
											proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsq "
										fi
										user_proofr_there=`grep -c "proofs/${user_to_append}/freetsa.tsr" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null
										if [ $small_trx = 1 ]
										then
											if [ $user_proofr_there = 0 ]
											then
												proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsr "
											fi
										else
											proof_to_append="${proof_to_append}proofs/${handover_account}/freetsa.tsr "
										fi
										user_to_append_till_date=`echo $line|cut -d '=' -f2`
										ls -1 ${script_path}/trx|grep "${user_to_append}" >${script_path}/dep_user_trx.tmp
										trx_till_line=`grep -n ${user_to_append_till_date} ${script_path}/dep_user_trx.tmp`
										append_line_counter=1
										while read line
										do
											if [ $append_line_counter -le $trx_till_line ]
											then
												if [ $small_trx = 1 ]											#
												then													#
													trx_there=`grep -c "trx/${line}" ${script_path}/proofs/${order_receipient}.txt` 2>/dev/null	#
													if [ $trx_there = 0 ]										#
													then												#
														trx_to_append="${trx_to_append}trx/${line} "
													fi												#
												else													#
													trx_to_append="${trx_to_append}trx/${line} "							#
												fi													#
											fi
										done <${script_path}/dep_user_trx.tmp
									done <${script_path}/dependencies.tmp
									build_ledger
									make_signature "none" ${trx_now} 1
									cd ${script_path}
									tar -cvf ${trx_now}.tar ${keys_to_append} ${proof_to_append} ${trx_to_append} proofs/${handover_account}/${handover_account}.txt
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										dialog_send_success_display=`echo $dialog_send_success|sed "s#<file>#${script_path}/${trx_now}.tar#g"`
										dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_send_success_display" 0 0
									else
										dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_send_fail" 0 0
									fi
									rm ${script_path}/manifest.txt 2>/dev/null
								else
									dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_send_fail2" 0 0
								fi
							fi
						fi
						;;
				"$dialog_receive")	file_found=0
							path_to_search=$HOME
							while [ $file_found = 0 ]
							do
								file_path=`dialog --title "$dialog_read" --backtitle "Universal Credit System" --fselect $path_to_search 20 48 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									if [ -s $file_path ]
									then
										if [ ! -d $file_path ]
										then
											check_archive $file_path
											rt_quiery=$?
											if [ $rt_quiery = 0 ]
											then
												dialog --title "$dialog_read" --backtitle "Universal Credit System" --yes-label "$dialog_yes" --no-label "$dialog_no" --yesno "$dialog_file_check" 0 0
												rt_quiery=$?
												if [ $rt_quiery = 0 ]
												then
													dialog --title "$dialog_read" --backtitle "Universal Credit System" --ok-label "$dialog_next" --extra-button --extra-label "$dialog_cancel" --msgbox "$files_to_fetch_display" 0 0
													#dialog --ok-label "$dialog_next" --extra-button --extra-label "$dialog_cancel" --title "$dialog_content" --backtitle "Universal Credit System" --prgbox "cat ${script_path}/files_to_fetch.tmp" 15 100
													rt_quiery=$?
												else
													rt_quiery=0
												fi
												if [ $rt_quiery = 0 ]
												then
													cd ${script_path}
													dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --yesno "$dialog_sync_add" 0 0
													rt_quiery=$?
													if [ $rt_quiery = 0 ]
													then
														tar -xkf $file_path 2>/dev/null
													else
														tar -xf $file_path $files_to_fetch
													fi
													file_found=1
													action_done=1
													make_ledger=1
												else
													file_found=1
												fi
											else
												dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
												dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
											fi
											rm ${script_path}/files_to_fetch.tmp
										else
											dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
                                							dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
										fi
									else
										dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
                        							dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
									fi
								else
									file_found=1
								fi
							done
							;;
				"$dialog_sync")	dialog --title "$dialog_sync" --backtitle "Universal Credit System" --yes-label "$dialog_sync_read" --no-label "$dialog_sync_create" --yesno "$dialog_sync_io" 0 0
						rt_quiery=$?
						case $rt_quiery in
							"0")	file_found=0
                        					path_to_search=$HOME
              			          			while [ $file_found = 0 ]
                        					do
                                					file_path=`dialog --title "$dialog_read" --backtitle "Universal Credit System" --fselect $path_to_search 20 48 3>&1 1>&2 2>&3`
 			                               			rt_quiery=$?
                        		        			if [ $rt_quiery = 0 ]
                                					then
										if [ -s $file_path ]
                  		                                                then
                                	                                                if [ ! -d $file_path ]
                                        	                                        then
												check_archive $file_path
                              	  								rt_quiery=$?
								                                if [ $rt_quiery = 0 ]
												then
													dialog --title "$dialog_read" --backtitle "Universal Credit System" --yes-label "$dialog_yes" --no-label "$dialog_no" --yesno "$dialog_file_check" 0 0
   													rt_quiery=$?
													if [ $rt_quiery = 0 ]
													then
														#dialog --ok-label "$dialog_next" --extra-button --extra-label "$dialog_cancel" --title "$dialog_content" --backtitle "Universal Credit System" --prgbox "cat ${script_path}/files_to_fetch.tmp" 15 100
   														dialog --title "$dialog_read" --backtitle "Universal Credit System" --ok-label "$dialog_next" --extra-button --extra-label "$dialog_cancel" --msgbox "$files_to_fetch_display" 0 0
	                              						       				rt_quiery=$?
													else
														rt_quiery=0
													fi
                                        								if [ $rt_quiery = 0 ]
                               			        	 					then
                                                								cd ${script_path}
                                         			       						dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --yesno "$dialog_sync_add" 0 0
                                        		        						rt_quiery=$?
                     		                           							if [ $rt_quiery = 0 ]
                                	                							then
                                        	               			 					tar -xkf $file_path 2>/dev/null
		                                                						else
                		                                 				       			tar -xf $file_path $files_to_fetch
                                		                						fi
														action_done=1
														make_ledger=1
                                        								else
                                                								file_found=1
                                  			      						fi
												else
													dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
													dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
												fi
												rm ${script_path}/files_to_fetch.tmp 2>/dev/null
											else
												dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
    									                        dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
											fi
										else
											dialog_sync_import_fail_display=`echo $dialog_sync_import_fail|sed "s#<file>#${file_path}#g"`
                                							dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_import_fail_display" 0 0
										fi
                                					else
                                       			 			file_found=1
                                					fi
                        					done
								;;
							"1")	###Get list of keys and related proofs with path
								ls -1 ${script_path}/keys >${script_path}/keys_sync.tmp
								while read line
								do
									echo "keys/$line" >>${script_path}/files_for_sync.tmp
									user_extracted=`echo $line|cut -d '.' -f1`
									freetsa_qfile="${script_path}/proofs/${user_extracted}/freetsa.tsq"
									if [ -s $freetsa_qfile ]
									then
										echo "proofs/${user_extracted}/freetsa.tsq" >>${script_path}/files_for_sync.tmp
									fi
									freetsa_rfile="${script_path}/proofs/${user_extracted}/freetsa.tsr"
									if [ -s $freetsa_rfile ]
									then
										echo "proofs/${user_extracted}/freetsa.tsr" >>${script_path}/files_for_sync.tmp
									fi
									index_file="${script_path}/proofs/${user_extracted}/${user_extracted}.txt"
									if [ -s $index_file ]
									then
										echo "proofs/${user_extracted}/${user_extracted}.txt" >>${script_path}/files_for_sync.tmp
									fi
								done <${script_path}/keys_sync.tmp

								###Get list of trx with path
								ls -1 ${script_path}/trx >${script_path}/trx_sync.tmp
								while read line
								do
									echo "trx/$line" >>${script_path}/files_for_sync.tmp
								done <${script_path}/trx_sync.tmp

								###Build string for tar-operation
								tar_string=""
								while read line
								do
									tar_string="${tar_string}$line "
								done <${script_path}/files_for_sync.tmp
								synch_now=`date +%s`
								cd ${script_path}
								tar -cf ${synch_now}.tar ${tar_string}
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									dialog_sync_create_success_display=`echo $dialog_sync_create_success|sed "s#<file>#${script_path}/${synch_now}.tar#g"`
									dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_sync_create_success_display" 0 0
                        					else
									dialog_sync_create_fail_display=`echo $dialog_sync_create_fail|sed "s#<file>#${script_path}/${synch_now}.tar#g"`
									dialog --title "$dialog_type_title_error" --backtitle "Universal Credit System" --msgbox "$dialog_sync_create_fail_display" 0 0
								fi
								rm ${script_path}/keys_sync.tmp 2>/dev/null
								rm ${script_path}/files_for_sync.tmp 2>/dev/null
								;;
						esac
						;;
				"$dialog_history")	cd ${script_path}/trx
							touch ${script_path}/my_trx.tmp
							grep -l "S:${handover_account}" *.* >${script_path}/my_trx.tmp 2>/dev/null
							grep -l " R:${handover_account}" *.*|grep "${handover_hash}" >>${script_path}/my_trx.tmp 2>/dev/null
							cd ${script_path}
							no_trx=`wc -l <${script_path}/my_trx.tmp`
							menu_display_text=""
							if [ $no_trx -gt 0 ]
							then
								while read line
								do
									line_extracted=`echo $line`
									sender=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f1|cut -d ':' -f2`
									receiver=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f3|cut -d ':' -f2`
									trx_date_tmp=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f4`
									trx_date=`date +'%F|%H:%M:%S' --date=@${trx_date_tmp}`
                              	                	        	trx_amount=`head -1 ${script_path}/trx/${line_extracted}|cut -d ' ' -f2`
									trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
									is_greater_one=`echo "${trx_fee}>1"|bc`
	                                                                if [ $is_greater_one = 0 ]
        	                                                        then
                	                                                        trx_fee="0${trx_fee}"
                        	                                        fi
                                	                               	trx_amount_with_fee=`echo "${trx_amount} + ${trx_fee}"|bc`
									if [ $sender = $handover_account ]
									then
										menu_display_text="${menu_display_text}${trx_date}|-${trx_amount_with_fee} $dialog_history_ack_snd "
									fi
									if [ $receiver = $handover_account ]
									then
										menu_display_text="${menu_display_text}${trx_date}|+${trx_amount} $dialog_history_ack_rcv "
									fi


								done <${script_path}/my_trx.tmp
							else
								menu_display_text="$dialog_history_noresult"
							fi
							overview_quit=0
							while [ $overview_quit = 0 ]
							do
								decision=`dialog --ok-label "$dialog_open" --cancel-label "$dialog_main_back" --title "$dialog_history" --backtitle "Universal Credit System" --menu "$dialog_history_text" 0 0 0 ${menu_display_text} 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									dialog_history_noresults=`echo $dialog_history_noresult|cut -d ' ' -f1`
									if [ $decision != $dialog_history_noresults ]
									then
										trx_date_extracted=`echo $decision|cut -d '|' -f1`
										trx_time_extracted=`echo $decision|cut -d '|' -f2`
										trx_date=`date +%s --date="${trx_date_extracted} ${trx_time_extracted}"`
										trx_file=`cat ${script_path}/my_trx.tmp|grep "${trx_date}"`
										sender=`head -1 ${script_path}/trx/${trx_file}|cut -d ' ' -f1|cut -d ':' -f2`
										receiver=`head -1 ${script_path}/trx/${trx_file}|cut -d ' ' -f3|cut -d ':' -f2`
										trx_status=""
										trx_confirmations=0
										trx_blacklisted=`grep -c "${trx_file}" ${script_path}/blacklisted_trx.dat`
										if [ $trx_blacklisted = 1 ]
										then
											trx_status="TRX_BLACKLISTED "
										fi
										sender_blacklisted=`grep -c "${sender}" ${script_path}/blacklisted_accounts.dat`
										if [ $sender_blacklisted = 1 ]
										then
										trx_status="${trx_status}SDR_BLACKLISTED "
										fi
										receiver_blacklisted=`grep -c "${sender}" ${script_path}/blacklisted_accounts.dat`
										if [ $receiver_blacklisted = 1 ]
										then
											trx_status="${trx_status}RCV_BLACKLISTED "
										fi
										if [ $trx_blacklisted = 0 -a $sender_blacklisted = 0 -a $receiver_blacklisted ]
										then
											trx_status="OK"
										fi
										while read line
										do
											trx_confirmations_user=`grep -c "${trx_file}" ${script_path}/proofs/$line/$line.txt`
											if [ $trx_confirmations_user = 1 ]
											then
												trx_confirmations=$(( $trx_confirmations + 1 ))
											fi
										done <${script_path}/friends.dat
										if [ $sender = $handover_account ]
										then
											trx_amount_with_fee=`echo $decision|cut -d '|' -f3|sed 's/+//g'|sed 's/-//g'`
											trx_amount=`echo "${trx_amount_with_fee} / 1.001"|bc`
											trx_fee=`echo "${trx_amount_with_fee} - ${trx_amount}"|bc`
											is_greater_one=`echo "${trx_fee}>1"|bc`
                                                        	                        if [ $is_greater_one = 0 ]
                                                                	                then
                                                                        	                trx_fee="0${trx_fee}"
                                                                                	fi
											dialog_history_show_trx_out_display=`echo $dialog_history_show_trx_out|sed "s/<receiver>/${receiver}/g"|sed "s/<trx_amount>/${trx_amount}/g"|sed "s/<currency_symbol>/${currency_symbol}/g"|sed "s/<trx_fee>/${trx_fee}/g"|sed "s/<trx_amount_with_fee>/${trx_amount_with_fee}/g"|sed "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g"|sed "s/<trx_file>/${trx_file}/g"|sed "s/<trx_status>/${trx_status}/g"|sed "s/<trx_confirmations>/${trx_confirmations}/g"`
											dialog --title "$dialog_history_show" --backtitle "Universal Credit System" --msgbox "$dialog_history_show_trx_out_display" 0 0
										else
											trx_amount=`echo $decision|cut -d '|' -f3|sed 's/+//g'|sed 's/-//g'`
                                	                                        	trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
                                        	                                	is_greater_one=`echo "${trx_fee}>1"|bc`
                                                	                                if [ $is_greater_one = 0 ]
                                                        	                        then
                                                                	                        trx_fee="0${trx_fee}"
                                                                        	        fi
											trx_amount_with_fee=`echo "${trx_amount} + ${trx_fee}"|bc`
											dialog_history_show_trx_in_display=`echo $dialog_history_show_trx_in|sed "s/<trx_amount>/${trx_amount}/g"|sed "s/<currency_symbol>/${currency_symbol}/g"|sed "s/<trx_date>/${trx_date_extracted} ${trx_time_extracted}/g"|sed "s/<trx_file>/${trx_file}/g"|sed "s/<trx_status>/${trx_status}/g"|sed "s/<trx_confirmations>/${trx_confirmations}/g"`
											dialog --title "$dialog_history_show" --backtitle "Universal Credit System" --msgbox "$dialog_history_show_trx_in_display" 0 0
										fi
									else
										dialog --title "$dialog_type_title_notification" --backtitle "Universal Credit System" --msgbox "$dialog_history_fail" 0 0
									fi
								else
									overview_quit=1
								fi
							done
							rm ${script_path}/my_trx.tmp
							;;
				"$dialog_stats")	dialog_statistic_display=`echo $dialog_statistic|sed "s/<coinload>/${coinload}/g"|sed "s/<currency_symbol>/${currency_symbol}/g"|sed "s/<in_days>/${in_days}/g"|sed "s/<next_coinload>/${next_coinload}/g"`
							dialog --title "$dialog_stats" --backtitle "Universal Credit System" --msgbox "$dialog_statistic_display" 0 0
							;;
				"Log out")		user_logged_in=0
							;;
			esac
		fi
	fi
done
