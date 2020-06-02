#!/bin/sh
login_account(){
		account_name_chosen=$1
		ls -1 ${script_path}/keys/ >${script_path}/keylist.tmp
		account_found=0
		handover_user=""
		account_file=""
		while read line
		do
			keylist_name=`echo $line|cut -d'.' -f1`
			keylist_stamp=`echo $line|cut -d'.' -f2`
			keylist_hash=`echo "${account_name_chosen}_${keylist_stamp}_Account"|shasum -a 256|cut -d' ' -f1`
			if [ $keylist_name = $keylist_hash ]
			then
				account_found=1
				handover_account=$keylist_hash
				account_file=$line
			fi
		done <${script_path}/keylist.tmp
		rm ${script_path}/keylist.tmp
		if [ $account_found = 1 ]
		then
			echo $account_name_chosen >${script_path}/${account_name_chosen}_account.dat
			gpg2 --no-default-keyring --keyring=${script_path}/keyring.file --local-user $handover_account -r $handover_account --encrypt --sign ${script_path}/${account_name_chosen}_account.dat
			if [ $? = 0 ]
			then
				rm ${script_path}/${account_name_chosen}_account.dat
				gpg2 --no-default-keyring --keyring=${script_path}/keys/${account_file} --output ${script_path}/${account_name_chosen}_account.dat --decrypt ${script_path}/${account_name_chosen}_account.dat.gpg
				encrypt_rt=$?
				extracted_name=`cat ${script_path}/${account_name_chosen}_account.dat|sed 's/ //g'`
				if [ $encrypt_rt = 0 ]
				then
					rm ${script_path}/${account_name_chosen}_account.dat.gpg
					rm ${script_path}/${account_name_chosen}_account.dat
					if [ $extracted_name = $account_name_chosen ]
					then
						dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Willkommen, ${account_name_chosen}!" 0 0
						user_logged_in=1
					fi
				else
					dialog --title "WARNUNG" --backtitle "Universal Credit System" --msgbox "Das Passwort ist nicht korrekt!" 0 0
				fi
			else
				dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Key für User ${account_name_chosen} nicht in GnuPG Keyring importiert!" 0 0
			fi
		else
			dialog --title "WARNUNG" --backtitle "Universal Credit System" --msgbox "Unter ${script_path}/keys/ befinden sich leider keine Profildateien für Account ${account_name_chosen}." 0 0
			clear
		fi
}
create_keys(){
		name_chosen=$1
		name_found=0
		name_cleared=$name_chosen
		with_pw=1
                password_found=0
 	        password_aborted=0
	     	while [ $password_found = 0 ]
               	do
                	password_first=`dialog --insecure --passwordbox "Bitte Passwort eingeben" 0 0 3>&1 1>&2 2>&3`
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
               			clear
				password_second=`dialog --insecure --passwordbox "Bitte Passwort ein zweites mal eingeben" 0 0 3>&1 1>&2 2>&3`
				rt_quiery=$?
				if [ $rt_quiery = 0 ]
				then
					clear
                                       	if [ $password_first != $password_second ]
                        		then
						dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Die eingegeben Passwörter stimmen nicht überein!" 0 0
						clear
					else
                                		password_found=1
					fi
				else
					password_found=1
					passwort_aborted=1
				fi
			else
				password_found=1
				password_aborted=1
			fi
		done
		if [ $password_aborted = 0 ]
		then
			file_stamp=`date +%Y%m%d`
			name_hashed=`echo "${name_cleared}_${file_stamp}_Account"|shasum -a 256|cut -d' ' -f1`
			echo "0"|dialog --title "Schlüssel erstellen" --backtitle "Universal Credit System" --gauge "Generiere Public und Private Keys..." 0 0 0
			gpg2 --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA512 --s2k-cipher-algo AES256 --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${password_second} --quick-gen-key ${name_hashed} rsa4096 sign,auth,encr none
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				echo "33"|dialog --title "Schlüssel erstellen" --backtitle "Universal Credit System" --gauge "Public Key exportieren..." 0 0 0
				gpg2 --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${password_second} --output ${script_path}/${name_cleared}_${file_stamp}_pub.asc --export $name_hashed
				rt_quiery=$?
				if [ $rt_quiery = 0 ]
				then
					echo "66"|dialog --title "Schlüssel erstellen" --backtitle "Universal Credit System" --gauge "Private Key exportieren..." 0 0 0
					dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Sie werden eventuell gleich aufgefordert für den Export des Privaten-Keys das Passwort einzugeben." 0 0
					clear
					gpg2 --batch --no-default-keyring --keyring=${script_path}/keyring.file --passphrase ${password_second} --output ${script_path}/${name_cleared}_${file_stamp}_priv.asc --export-secret-keys $name_hashed
					rt_quiery=$?
					if [ $rt_quiery = 0 ]
					then
						###TSA SECTION####
						mkdir ${script_path}/proofs/${name_hashed}

						###FreeTSA
						echo "Creating quiery file..." >${script_path}/tsa_debug.log
						cd ${script_path}
						openssl ts -query -data ${script_path}/${name_cleared}_${file_stamp}_pub.asc -no_nonce -sha512 -out ${script_path}/freetsa.tsq
						rt_quiery=$?
						if [ $rt_quiery = 0 ]
						then
							echo "Successfully created quiery file..." >>${script_path}/tsa_debug.log
							echo "Sending quiery file to TSA..." >>${script_path}/tsa_debug.log
							cd ${script_path}
							curl -H "Content-Type: application/timestamp-query" --data-binary '@freetsa.tsq' https://freetsa.org/tsr > ${script_path}/freetsa.tsr
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								echo "Successfully sent quiery file to TSA..." >>${script_path}/tsa_debug.log
								echo "Requesting latest certificate file..." >>${script_path}/tsa_debug.log
								cd ${script_path}/certs
								wget https://freetsa.org/files/tsa.crt
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									echo "Successfully requested latest certificate file..." >>${script_path}/tsa_debug.log
									echo "Requesting root certificate file..." >>${script_path}/tsa_debug.log
									wget https://freetsa.org/files/cacert.pem
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										echo "Successfully requested root certificate file..." >>${script_path}/tsa_debug.log
										mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
										mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/cacert.pem
										echo "Verifiying request..." >>${script_path}/tsa_debug.log
										openssl ts -verify -queryfile ${script_path}/freetsa.tsq -in ${script_path}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt
										rt_quiery=$?
										if [ $rt_quiery = 0 ]
										then
											echo "Request successfully verified..." >>${script_path}/tsa_debug.log
											mv ${script_path}/freetsa.tsq ${script_path}/proofs/${name_hashed}/freetsa.tsq
											mv ${script_path}/freetsa.tsr ${script_path}/proofs/${name_hashed}/freetsa.tsr
										else
											echo "Request could not be verified..." >>${script_path}/tsa_debug.log
											rm ${script_path}/freetsa.tsq
											rm ${script_path}/freetsa.tsr
										fi
									else
										rm ${script_path}/certs/tsa.crt
										rm ${script_path}/certs/cacert.pem
									fi
								else
									rm ${script_path}/certs/tsa.crt
								fi
							else
								rm ${script_path}/freetsa.tsq
								rm ${script_path}/freetsa.tsr
							fi
						else
							rm ${script_path}/freetsa.tsq
						fi
						if [ $rt_quiery = 0 ]
						then
							echo "100"|dialog --title "Schlüssel erstellen" --backtitle "Universal Credit System" --gauge "Fertig..." 0 0 0
							sleep 3s
							clear
							dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "RSA-Schlüssel erfolgreich erstellt. Bitte notieren Sie sich diese Daten. Die Adresse benötigen Sie z.B. um zahlungen entgegenzunehmen.\n\nName :\n${name_chosen}\n\nAdresse :\n${name_hashed}\n\nDatum :\n${file_stamp}\n\n" 0 0
							clear
							cp ${script_path}/${name_cleared}_${file_stamp}_pub.asc ${script_path}/keys/${name_hashed}.${file_stamp}
						else
							###Remove Proofs-folder of Account that could not be created
							rmdir ${script_path}/proofs/${name_hashed}

							###Remove created keys out of keyring
							key_fp=`gpg2 --no-default-keyring --keyring=${script_path}/keyring.file --with-colons --list-keys ${name_cleared}|sed -n 's/^fpr:::::::::\([[:alnum:]]\+\):/\1/p'`
							gpg2 --batch --yes --no-default-keyring --keyring=${script_path}/keyring.file --delete-secret-keys ${key_fp}
							gpg2 --batch --yes --no-default-keyring --keyring=${script_path}/keyring.file --delete-keys ${key_fp}
						fi
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
			if [ $create_index_file = 0 ]
                        then
				message=${script_path}/trx/${trx_now}.${handover_account}
				message_blank=${script_path}/message_blank.dat
				touch ${message_blank}
				echo $transaction_message >>${message_blank}
			else
				message=${script_path}/proofs/${handover_account}/${handover_account}.txt
                                message_blank=${script_path}/message_blank.dat
			#	#ls -1 ${script_path}/keys/ >${script_path}/signed_keys.tmp
				ls -1 ${script_path}/trx/ >${script_path}/signed_trx.tmp
			#	#ls -1 ${script_path}/proofs >${script_path}/signed_index.tmp
			#	#while read line
			#	#do
			#	#	key_hash=`cat ${script_path}/keys/${line}|shasum -a 512|cut -d' ' -f1`
			#	#	key_full_path="keys/${line}"
			#	#	echo "${key_full_path} ${key_hash} ${trx_now}" >>${message_blank}
			#	#done <${script_path}/signed_keys.tmp
				while read line
                                do
                                        trx_hash=`cat ${script_path}/trx/${line}|shasum -a 512|cut -d' ' -f1`
                                        trx_full_path="trx/${line}"
                                        echo "${trx_full_path} ${trx_hash} ${trx_now}" >>${message_blank}
                                done <${script_path}/signed_trx.tmp
			#	#while read line
			#	#do
			#	#	tsa_query_hash=`cat ${script_path}/proofs/${line}/freetsa.tsq|shasum -a 512|cut -d' ' -f1`
			#	#	tsa_query_full_path="proofs/${line}"
			#	#	echo "${tsa_query_full_path} ${tsa_query_hash} ${trx_now}" >>${message_blank}
			#	#	tsa_response_hash=`cat ${script_path}/proofs/${line}/freetsa.tsr|shasum -a 512|cut -d' ' -f1`
                        #       #        tsa_response_full_path="proofs/${line}"
                        #       #        echo "${tsa_response_full_path} ${tsa_response_hash} ${trx_now}" >>${message_blank}
			#	#done <${script_path}/signed_index.tmp
			fi
			#echo $script_hash >>${message_blank}
			total_blank=`cat ${message_blank}|wc -l`
			total_blank=$(( $total_blank + 16 ))
			gpg2 --no-default-keyring --keyring=${script_path}/keys/${account_file} --local-user $handover_account --clearsign ${message_blank}
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				rm ${message_blank}
				tail -$total_blank ${message_blank}.asc|sed 's/-----BEGIN PGP SIGNATURE-----//g'|sed 's/-----END PGP SIGNATURE-----//g' >${message}
				rm ${message_blank}.asc
			fi
}
verify_signature(){
			trx_to_verify=$1
			user_signed=$2
			signed_correct=0
			build_message=${script_path}/verify_trx.tmp
			no_lines_trx=`cat ${trx_to_verify}|wc -l|sed 's/ //g'`
			till_sign=$(( $no_lines_trx - 16 ))	#-16
			echo "-----BEGIN PGP SIGNED MESSAGE-----" >${build_message}
			echo "Hash: SHA512" >>${build_message}
			echo "" >>${build_message}
			head -${till_sign} ${trx_to_verify} >>${build_message}
			echo "-----BEGIN PGP SIGNATURE-----" >>${build_message}
			echo "" >>${build_message}
			tail -14 ${trx_to_verify}|head -13 >>${build_message}
			echo "-----END PGP SIGNATURE-----" >>${build_message}
			gpg2 --status-fd 1 --no-default-keyring --keyring=${script_path}/keys/${user_signed} --verify ${build_message} >${script_path}/gpg_verify.tmp
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				signed_correct=`cat ${script_path}/gpg_verify.tmp|grep "GOODSIG"|grep "${user_signed}"|wc -l`
			else
				rm ${trx_to_verify}
			fi
			rm ${build_message}
			rm ${script_path}/gpg_verify.tmp
			return $rt_quiery
}
check_input(){
		input_string=$1
		rt_quiery=0
		alnum_there=0
		length_counter=0
		length_counter=`echo $input_string|wc -m|sed 's/ //g'`
		alnum_there=`echo $input_string|grep '[^[:alnum:]]'|wc -l`
		if [ $alnum_there -gt 0 ]
		then
			dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Es sind nur Buchstaben (Aa-Zz) und Zahlen (0-9) ohne Leerzeichen erlaubt!" 0 0
			rt_quiery=1
		fi
		if [ $length_counter -le 1 ]
                then
                        dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Sie müssen mindestens 1 Zeichen eingeben!" 0 0
                	rt_quiery=1
		fi
		if [ $length_counter -gt 21 ]
		then
			dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Es sind nur maximal 20 Zeichen erlaubt!" 0 0
			rt_quiery=1
		fi
		return $rt_quiery
}
build_ledger(){
		date_stamp=1577142000

		###LOAD ALL ACCOUNTS AND IGNORE BLACKLISTED
		ls -1 ${script_path}/keys >${script_path}/accounts.tmp
		cat ${script_path}/blacklisted_accounts.dat >>${script_path}/accounts.tmp
		cat ${script_path}/accounts.tmp|sort >${script_path}/accounts_sorted.tmp
		cat ${script_path}/accounts_sorted.tmp|uniq >${script_path}/accounts_list.tmp

		###CREATE FRIENDS LIST
		cd ${script_path}/trx
		grep -l "S:${handover_account}" *.* >${script_path}/friends_trx.tmp
		while read line
		do
			head -1 ${script_path}/trx/${line}|cut -d' ' -f3|cut -d':' -f2 >${script_path}/friends.tmp
		done <${script_path}/friends_trx.tmp
		cat ${script_path}/friends.tmp|uniq >${script_path}/friends.dat
		rm ${script_path}/friends.tmp
		cd ${script_path}/

		#EMPTY LEDGER
		rm ${script_path}/ledger.tmp

		while read line
		do
			date_stamp=1577142000
			account_name=`echo $line|cut -d'.' -f1`
			account_date=`echo $line|cut -d'.' -f2`
			focus=`date +%Y%m%d --date=@${date_stamp}`
			now_stamp=`date +%s`
			now=`date +%Y%m%d --date=@${now_stamp}`
			day_counter=1
			account_balance=0
			enough_balance=0
			multi=1
			multi_next=$(( $multi * 2 ))

			###LOAD ALL PREVIOUS TRANSACTIONS
			cd ${script_path}/trx
			grep -l "S:${account_name}" *.* >${script_path}/trx_${account_name}.tmp
            		while read line
            	    	do
        	        	stamp_to_convert=`echo $line|cut -d'.' -f1`
            	    		stamp_converted=`date +%Y%m%d --date=@${stamp_to_convert}`
                		trx_sender=`echo $line|cut -d'.' -f2`
                		echo "${stamp_to_convert} ${stamp_converted} ${stamp_to_convert}.${trx_sender}" >>${script_path}/trxl_${account_name}.tmp
                	done <${script_path}/trx_${account_name}.tmp
			rm ${script_path}/trx_${account_name}.tmp
			cat ${script_path}/trxl_${account_name}.tmp|sort -k1 >${script_path}/trxs_${account_name}.tmp
			rm ${script_path}/trxl_${account_name}.tmp

			###AS LONG AS FOCUS LESS OR EQUAL YET..
			while [ $focus -le $now ]
			do
				###CHECK IF DATE IS DATE OF BEGINNING OF NEXT STAGE
				if [ $day_counter -eq $multi_next ]
				then
					multi=$(( $multi * 2 ))
					multi_next=$(( $multi * 2 ))
				fi
				if [ $focus -ge $account_date ]
				then
					if [ $focus -eq $account_date ]
					then
						account_there=`cat ${script_path}/ledger.tmp|grep "${account_name}"|wc -l`
						if [ $account_there = 0 ]
						then
							echo "${account_name}=0" >>${script_path}/ledger.tmp
						fi
					fi
					###GRANT COINLOAD OF THAT DAY
					coinload=`echo "${initial_coinload} / ${multi}"|bc`
					is_greater_one=`echo "${coinload}>1"|bc`
	                                if [ $is_greater_one = 0 ]
        	                        then
                	                	coinload="0${coinload}"
                        	        fi
					next_coinload=`echo "${initial_coinload} / ${multi_next}"|bc`
					is_greater_one=`echo "${next_coinload}>1"|bc`
	                                if [ $is_greater_one = 0 ]
        	                        then
                	                	next_coinload="0${next_coinload}"
                        	        fi
					account_prev_balance=`cat ${script_path}/ledger.tmp|grep "${account_name}"|cut -d'=' -f2`
					account_balance=`echo "${account_prev_balance} + ${coinload}"|bc`
					is_greater_one=`echo "${account_balance}>1"|bc`
					if [ $is_greater_one = 0 ]
					then
						account_balance="0${account_balance}"
					fi
					cat ${script_path}/ledger.tmp|sed "s/${account_name}=${account_prev_balance}/${account_name}=${account_balance}/g" >${script_path}/ledger_mod.tmp
					mv ${script_path}/ledger_mod.tmp ${script_path}/ledger.tmp
					grep -n "$focus" ${script_path}/trxs_${account_name}.tmp >${script_path}/trx_day_${focus}.tmp
					no_hits_that_day=`cat ${script_path}/trx_day_${focus}.tmp|wc -l`
					if [ $no_hits_that_day -gt 0 ]
					then
						while read line
						do
							line_trx_list=`echo $line|cut -d':' -f1`
							trx_filename=`head -${line_trx_list} ${script_path}/trxs_${account_name}.tmp|tail -1|cut -d' ' -f3`
							trx_date_filename=`echo $trx_filename|cut -d'.' -f1`
							trx_date_inside=`head -1 ${script_path}/trx/${trx_filename}|cut -d' ' -f4`
							trx_sender=`head -1 ${script_path}/trx/${trx_filename}|cut -d' ' -f1|cut -d':' -f2`
							trx_receiver=`head -1 ${script_path}/trx/${trx_filename}|cut -d' ' -f3|cut -d':' -f2`
							
							###CHECK IF FRIENDS KNOW OF THIS TRX
							number_of_friends_trx=0
							number_of_friends_add=0
							while read line
							do
								###IGNORE CONFIRMATIONS OF TRX PARTICIPANTS
								if [ $trx_sender != $line -a $trx_receiver != $line ]
								then
									number_of_friends_add=`grep "${trx_filename}" ${script_path}/proofs/${line}/${line}.txt|wc -l|sed 's/ //g'`
									number_of_friends_trx=$(( $number_of_friends_trx + $number_of_friends_add ))
								fi
							done <${script_path}/friends.dat
							
							#trx_receiver=`head -1 ${script_path}/trx/${trx_filename}|cut -d' ' -f3|cut -d':' -f2`
							trx_amount=`head -1 ${script_path}/trx/${trx_filename}|cut -d' ' -f2`
							trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
							is_greater_one=`echo "${trx_fee}>1"|bc`
                                			if [ $is_greater_one = 0 ]
					                       then
                	                               		trx_fee="0${trx_fee}"
                        	                	fi
               	                	        	trx_total=`echo "${trx_amount} + ${trx_fee}"|bc`
                       	                	        account_check_balance=`echo "${account_balance} - ${trx_total}"|bc`
                               	                        enough_balance=`echo "${account_check_balance}>0"|bc`
        	                       	        	if [ $enough_balance = 1 ]
                                               	        then
                                                       	       	account_balance=$account_check_balance
								is_greater_one=`echo "${account_balance}>1"|bc`
						                if [ $is_greater_one = 0 ]
        	                                		then
                	                                		account_balance="0${account_balance}"
                        	                		fi
								account_prev_balance=`cat ${script_path}/ledger.tmp|grep "${account_name}"|cut -d'=' -f2`
								cat ${script_path}/ledger.tmp|sed "s/${account_name}=${account_prev_balance}/${account_name}=${account_balance}/g" >${script_path}/ledger_mod.tmp
								mv ${script_path}/ledger_mod.tmp ${script_path}/ledger.tmp
								if [ $number_of_friends_trx -gt 0 ]
								then
									receiver_in_ledger=`cat ${script_path}/ledger.tmp|grep "${trx_receiver}"|wc -l`
									if [ $receiver_in_ledger = 0 ]
									then
										echo "${trx_receiver}=${trx_amount}" >>${script_path}/ledger.tmp
									else
										receiver_old_balance=`cat ${script_path}/ledger.tmp|grep "${trx_receiver}"|cut -d'=' -f2`
										is_greater_one=`echo "${receiver_old_balance}>1"|bc`
										if [ $is_greater_one = 0 ]
										then
											receiver_old_balance="0${receiver_old_balance}"
										fi
										receiver_new_balance=`echo "${receiver_old_balance} + ${trx_amount}"|bc`
										is_greater_one=`echo "${receiver_new_balance}>1"|bc`
										if [ $is_greater_one = 0 ]
										then
											receiver_new_balance="0${receiver_new_balance}"
										fi
									 	cat ${script_path}/ledger.tmp|sed "s/${trx_receiver}=${receiver_old_balance}/${trx_receiver}=${receiver_new_balance}/g" >${script_path}/ledger_mod.tmp
										mv ${script_path}/ledger_mod.tmp ${script_path}/ledger.tmp
									fi
								fi
        	                	        	fi
						done <${script_path}/trx_day_${focus}.tmp
					else
						rm ${script_path}/trx_day_${focus}.tmp
					fi
				fi
				in_days=$(( $multi_next - $day_counter ))
				date_stamp=$(( $date_stamp + 86400 ))
				focus=`date +%Y%m%d --date=@${date_stamp}`
				day_counter=$(( $day_counter + 1 ))
			done
			rm ${script_path}/trxs_${account_name}.tmp
		done <${script_path}/accounts_list.tmp
		cd ${script_path}/
}
check_archive(){
			path_to_tarfile=$1
			tar -tf $path_to_tarfile >${script_path}/tar_check.tmp
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				script_there=0
				files_not_homedir=0
				files_to_fetch=""
				while read line
				do
					script_there=`echo $line|grep ".sh"|wc -l|sed 's/ //g'`
					if [ $script_there = 0 ]
					then
						files_not_homedir=`echo $line|cut -d'/' -f1`
             		   			case $files_not_homedir in
                        				"keys")		files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
                                	        			;;
                   		     			"proofs")	files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
                                        				;;
                        				"trx")		files_to_fetch="${files_to_fetch}$line "
									echo "$line" >>${script_path}/files_to_fetch.tmp
                                		        		;;
                				esac
					fi
				done <${script_path}/tar_check.tmp
				rm ${script_path}/tar_check.tmp
			fi
			return $rt_quiery
}

##################
#Main Menu Screen#
##################
script_name=${0}
script_path=$(dirname $(readlink -f ${0}))
script_name_extr=`echo $script_name|cut -d'/' -f2`
script_hash=`cat ${script_path}/${script_name_extr}|shasum -a 512|cut -d' ' -f1`
user_logged_in=0
core_system_version="v0.0.1"
current_fee="0.001"
currency_symbol="UCC"
initial_coinload=10000
files_to_fetch=""
while [ 1 != 2 ]
do
	if [ $user_logged_in = 0 ]
	then
		main_menu=`dialog --ok-label 'Auswählen' --cancel-label 'Beenden' --title "UNIVERSAL CREDIT SYSTEM" --backtitle "Universal Credit System ${core_system_version}" --menu "MMMWMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMWMWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMWK0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMW0ONMMMMMMMMMMMMMMMMMWWX0xdllcloxOKWMMMMMMMMMMM\nMMW0xXMMMMMMMMMMMMMMMMXx:'..   .......,lONMMMMMMMM\nMMKokWMMMMMMMMMMMMMMXo.    .:xOKKXK0kdl,.,xNMMWMMM\nMMx:0MMMMMMMMMMMMMM0,      :0NMMMMMMMWWN0o,;OWMMMM\nMMo;KMMMMMMMMMMMMMX;        .,dXMMMMMMMMMWKl'dNMMM\nMMo'OMMMMMMMMMMMMMx.           ;KMMMMMMMMWWWx'oWMM\nMMk'lWMMMMMMMMMMMMd             oWMMMMMMMMMMWo'kMM\nMMWo.dWMMMMMMMMMMMO.            lWMMMMMMMMMMMX;cWM\nMMWXo'lXMMMMMMMMMMWk.          .OMMMMMMMMMMMMWlcXM\nMMMMNx;;xXWWMMWMMMMWKd;.      .xWMMMMMMMMMMMMWooWM\nMMMMMWXd,'cx0NWWMMMWWXx'    .;OWMMMMMMMMMMMMMXokMM\nMMMMMMMMXx:'.';clllc;.   .'cONMMMMMMMMMMMMMMWkxNMM\nMMMMMMMMMMWXOdl:;,,,,:ldOKNMMMMMMMMMMMMMMMMMKkXMMM\nMMMMMMMMMMMMMMMMMWWWMMMMMMMMMMMMMMMMMMMMMMWK0XMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKKWWWMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWWMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n" 0 0 0 "Login" "" "Konto erstellen" "" "Exit" "" 3>&1 1>&2 2>&3`
		if [ $? != 0 ]
        	then
                	clear
                	exit
        	else
                	clear
                	case "$main_menu" in
                        	"Login")                account_entered_correct=0
							account_entered_aborted=0
							while [ $account_entered_correct = 0 ]
							do
								account_chosen=`dialog --title "Login" --backtitle "Universal Credit System" --inputbox "Kontoname eingeben:" 0 0 "" 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									check_input $account_chosen
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										account_entered_correct=1
									fi
								else
									account_entered_correct=1
									account_entered_aborted=1
								fi
							done
							if [ $account_entered_aborted = 0 ]
							then
								login_account $account_chosen
							fi
							;;
                        	"Konto erstellen")      account_entered_correct=0
							account_entered_aborted=0
							while [ $account_entered_correct = 0 ]
							do
								account_chosen=`dialog --title "Konto erstellen" --backtitle "Universal Credit System" --inputbox "Kontoname eingeben:" 0 0 "" 3>&1 1>&2 2>&3`
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									check_input $account_chosen
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										account_entered_correct=1
									fi
								else
									account_entered_correct=1
									account_entered_aborted=1
								fi
							done
							if [ $account_entered_aborted = 0 ]
							then
								create_keys $account_chosen
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									dialog --title "Hinweis" --backtitle "Universal Credit System" --msgbox "Sie können sich nun in Ihr Konto einloggen. Viel Spass!" 0 0
								else
									dialog --title "Fehler" --backtitle "Universal Credit System" --msgbox "User konnte nicht erstellt werden!" 0 0
								fi
							fi
							;;
                        	"Exit")			unset user_logged_in
							rm ${script_path}/*.tmp
							rm ${script_path}/*.dat
							exit
							;;
                	esac
        	fi

	else
		###FREETSA CERTIFICATE DOWNLOAD###
		freetsa_available=0
		freetsa_cert_available=0
		freetsa_rootcert_available=0
		cd ${script_path}/certs
		if [ ! -s ${script_path}/certs/freetsa/tsa.crt ]
		then
			wget https://freetsa.org/files/tsa.crt
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				mv ${script_path}/certs/tsa.crt ${script_path}/certs/freetsa/tsa.crt
				freetsa_cert_available=1
			else
				rm ${script_path}/certs/tsa.crt
			fi
		else
			freetsa_cert_available=1
		fi
		if [ ! -s ${script_path}/certs/freetsa/tsacert.pem ]
		then
			wget https://freetsa.org/files/cacert.pem
			rt_quiery=$?
			if [ $rt_quiery = 0 ]
			then
				mv ${script_path}/certs/cacert.pem ${script_path}/certs/freetsa/tsacert.pem
				freetsa_rootcert_available=1
			else
				rm ${script_path}/certs/cacert.pem
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
		ls -1 ${script_path}/keys >${script_path}/all_accounts.tmp
		while read line
		do
			account_to_check=`echo $line|cut -d'.' -f1`
			while read line
			do
				accountname_to_check=`echo $line|cut -d'.' -f1`
				accountdate_to_check=`echo $line|cut -d'.' -f2`
				###FREETSA CHECK###############################
				if [ $freetsa_available = 1 ]
				then
					openssl ts -verify -queryfile ${script_path}/proofs/${accountname_to_check}/freetsa.tsq -in ${script_path}/proofs/${accountname_to_check}/freetsa.tsr -CAfile ${script_path}/certs/freetsa/cacert.pem -untrusted ${script_path}/certs/freetsa/tsa.crt
					rt_quiery=$?
					if [ $rt_quiery = 0 ]
					then
						openssl ts -reply -in ${script_path}/proofs/${accountname_to_check}/freetsa.tsr -text >${script_path}/timestamp_check.tmp
						rt_quiery=$?
						if [ $rt_quiery = 0 ]
						then
							date_to_verify=`cat ${script_path}/timestamp_check.tmp|grep "Time stamp:"|cut -c 13-37`
							date_to_verify_converted=`date -d "${date_to_verify}" +%Y%m%d`
							if [ $date_to_verify_converted != $accountdate_to_check ]
							then
								echo $line >>${script_path}/blacklisted_accounts.dat
							fi
						fi
						rm ${script_path}/timestamp_check.tmp
					fi
				fi
				###############################################
			done <${script_path}/proofs/${account_to_check}.txt
		done <${script_path}/all_accounts.tmp
		
		###CHECK KEYS IF ALREADY IN KEYRING AND IMPORT THEM IF NOT
                ls -1 ${script_path}/keys >${script_path}/keys_import.tmp
                while read line
                do
                        key_uname=`echo $line|cut -d'.' -f1`
                        key_imported=`gpg2 --no-default-keyring --keyring=${script_path}/keyring.file --with-colons --list-keys|grep "${key_uname}"|wc -l`
                        if [ $key_imported = 0 ]
                        then
                                gpg2 --batch --no-default-keyring --keyring=${script_path}/keyring.file --import ${script_path}/keys/${line}
                                rt_quiery=$?
                                if [ $rt_quiery -gt 0 ]
                                then
                        		dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Öffentlicher Schlüssel für user <${key_uname}> konnte nicht importiert werden (Datei: ${script_path}/keys/$line)!" 0 0
                                        key_already_blacklisted=`cat ${script_path}/blacklisted_accounts.dat|grep "${key_uname}"|wc -l`
                                        if [ $key_already_blacklisted = 0 ]
                                        then
                                                echo "${line}" >>${script_path}/blacklisted_accounts.dat
                                        fi
                                fi
                        fi
                done <${script_path}/keys_import.tmp
		rm ${script_path}/keys_import.tmp
                ##########################################################

		###VERIFY TRX AT THE BEGINNING AND MOVE TRX THAT HAVE NOT BEEN SIGNED BY THE OWNER TO BLACKLISTED
		ls -1 ${script_path}/trx >${script_path}/all_trx.tmp
		while read line
		do
			file_to_check=${script_path}/trx/${line}
			user_to_check=`echo $line|cut -d'.' -f2`
			usr_blacklisted=`cat ${script_path}/blacklisted_accounts.dat|grep "${user_to_check}"|wc -l`
			if [ $usr_blacklisted = 0 ]
			then
				user_file=`ls -1 ${script_path}/keys/|grep "${user_to_check}"`
				verify_signature $file_to_check $user_file
				rt_quiery=$?
				if [ $rt_quiery -gt 0 ]
				then
					echo $file_to_check >>${script_path}/blacklisted_trx.dat
				else
					trx_date_filename=`echo $line|cut -d'.' -f1`
					trx_date_inside=`head -1 ${script_path}/trx/${line}|cut -d' ' -f4`
					if [ $trx_date_filename != $trx_date_inside ]
					then
						echo $file_to_check >>${script_path}/blacklisted_trx.dat
					fi
				fi
			fi
		done <${script_path}/all_trx.tmp
		####################################################################################

		###CREATE INDEX FILE CONTAINING ALL KNOWN TRX
		now=`date +%s`
		make_signature "none" $now 1

		####GET COINS FOR ACCOUNT LOGGED IN
		build_ledger
		account_my_balance=`cat ${script_path}/ledger.tmp|grep "${keylist_hash}"|cut -d'=' -f2`
		user_menu=`dialog --ok-label 'Auswählen' --cancel-label 'Zurück' --title "Menü" --backtitle "Universal Credit System" --menu "\nAngemeldet als :\n${account_name_chosen}\n\nAdresse :\n${keylist_hash}\n\nKontostand :\n${account_my_balance} ${currency_symbol}\n\nBitte wählen:" 0 0 0 "Senden" "" "Empfangen" "" "Sync" "" "Historie" "" "Stats" "" "Log out" "" 3>&1 1>&2 2>&3`
        	if [ $? != 0 ]
		then
			user_logged_in=0
			clear
		else
			clear
			case "$user_menu" in
				"Senden")	receipient_found=0
						order_aborted=0
              			        	while [ $receipient_found = 0 ]
                              		        do
							order_receipient=`dialog --title "Senden" --backtitle "Universal Credit System" --inputbox "Bitte geben Sie eine Empfangsadresse ein:" 0 0 "260dfa9766929ee5a8a00cadde8f9993182ac5c5b5a67a037fb087ecc1cf6ce0" 3>&1 1>&2 2>&3`
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								receipient_found=1
								amount_selected=0
								while [ $amount_selected = 0 ]
								do
									order_amount=`dialog --title "Senden" --backtitle "Universal Credit System" --inputbox "Bitte geben Sie einen Betrag ein:" 0 0 "1.000000" 3>&1 1>&2 2>&3`
								        rt_quiery=$?
             								if [ $rt_quiery = 0 ]
                							then
										order_amount_alnum=`echo $order_amount|grep '[^[:alnum:]]'|wc -l`
										if [ $order_amount_alnum -gt 0 ]
										then
											order_amount_formatted=`echo $order_amount|sed 's/,/./g'|sed 's/ //g'`
											order_amount_formatted="0${order_amount_formatted}"
											trx_fee=`echo "${order_amount_formatted} * ${current_fee}"|bc`
											trx_fee="0${trx_fee}"
											order_amount_with_trx_fee=`echo "${order_amount_formatted} + ${trx_fee}"|bc`
											amount_selected=1
										else
											dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Buchstaben und Alphanumerische Zeichen sind nicht erlaubt. Gültige Beispiele sind: 1.000000 oder 1,000000 oder 10.00 oder 500.50 etc.!" 0 0
										fi
									else
										amount_selected=1
										receipient_found=1
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
							dialog --title "HINWEIS" --backtitle "Universal Credit System" --yesno "Wollen Sie folgende überweisung wirklich tätigen: \n\nEMPFANGSADRESSE :\n${order_receipient}\n\nIHR AKTUELLER KONTOSTAND: \n${account_balance} ${currency_symbol}\n\nZU ÜBERWEISENDER BETRAG :\n-${order_amount_formatted} ${currency_symbol}\n\nANFALLENDE GEBÜHR :\n-${trx_fee} ${currency_symbol}\n\nTOTAL :\n-${order_amount_with_trx_fee} ${currency_symbol}" 30 120
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								trx_now=`date +%s`
								make_signature "S:${handover_account} ${order_amount_formatted} R:${order_receipient} ${trx_now}" ${trx_now} 0
								last_trx=`ls -1 ${script_path}/trx/*.${handover_account}|tail -1`
								verify_signature ${last_trx} ${account_file}
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									cd ${script_path}/trx/
									grep "R:${handover_account}" *.* >${script_path}/dependent_trx.tmp
									rm ${script_path}/dependencies.tmp
									while read line
									do
										user_to_append_till_date=`echo $line|cut -d':' -f1|cut -d'.' -f1`
										user_to_append=`echo $line|cut -d':' -f1|cut -d'.' -f2`
										already_in_tree=`cat ${script_path}/dependencies.tmp|grep "${user_to_append}="|wc -l`
										if [ $already_in_tree = 0 ]
										then
											echo "${user_to_append}=${user_to_append_till_date}" >>${script_path}/dependencies.tmp
										else
											user_to_append_old_date=`cat ${script_path}/dependencies.tmp|grep "${user_to_append}="|cut -d'=' -f2`
											cat ${script_path}/dependencies.tmp|sed "s/${user_to_append}=${user_to_append_old_date}/${user_to_append}=${user_to_append_till_date}/g" >${script_path}/dependencies_mod.tmp
											mv ${script_path}/dependencies_mod.tmp ${script_path}/dependencies.tmp
										fi
									done <${script_path}/dependent_trx.tmp
									keys_to_append="keys/${keylist_hash}.${keylist_stamp} "
									proof_to_append="proofs/${keylist_hash}/*.tsq proofs/${keylist_hash}/*.tsr "
									trx_to_append="trx/${trx_now}.${handover_account} "
									while read line
									do
										user_to_append=`echo $line|cut -d'=' -f1`
										user_to_append_key=`ls -1 ${script_path}/keys|grep "${user_to_append}"`
										proof_to_append="${proof_to_append}proofs/${user_to_append}/*.tsq proofs/${user_to_append}/*.tsr "
										keys_to_append="${keys_to_append}keys/${user_to_append_key} "
										user_to_append_till_date=`echo $line|cut -d'=' -f2`
										ls -1 ${script_path}/trx|grep "${user_to_append}" >${script_path}/dep_user_trx.tmp
										trx_till_line=`grep -n ${user_to_append_till_date} ${script_path}/dep_user_trx.tmp`
										append_line_counter=1
										while read line
										do
											if [ $append_line_counter -lt $trx_till_line ]
											then
												trx_to_append="${trx_to_append}trx/${line} "
											else
								 				if [ $append_line_counter = $trx_till_line ]
												then
													trx_to_append="${trx_to_append}trx/${line} "
												fi
											fi
										done <${script_path}/dep_user_trx.tmp
									done <${script_path}/dependencies.tmp
									make_signature "none" ${trx_now} 1
									cd ${script_path}
									#tar -cvf ${trx_now}.tar ${keys_to_append} ${trx_to_append} ${handover_account}.txt
									tar -cvf ${trx_now}.tar ${keys_to_append} ${proof_to_append} ${trx_to_append} proofs/${handover_account}/${handover_account}.txt
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Überweisung erfolgreich erstellt!\nDatei :\n${script_path}/${trx_now}.tar" 0 0
									else
										dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Fehler beim zusammenstellen der Überweisung!" 0 0
									fi
									rm ${script_path}/manifest.txt
								else
									dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Fehler beim senden der Überweisung!" 0 0
								fi
							fi
						fi
						;;
				"Empfangen")	file_found=0
						path_to_search=$HOME
						while [ $file_found = 0 ]
						do
							file_path=`dialog --title "Datei einlesen" --backtitle "Universal Credit System" --fselect $path_to_search 20 48 3>&1 1>&2 2>&3`
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								check_archive $file_path
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									dialog --ok-label 'Weiter' --extra-button --extra-label 'Abbrechen' --title "Datei-Inhalt" --backtitle "Universal Credit System" --prgbox "cat ${script_path}/files_to_fetch.tmp" 15 100
									rt_quiery=$?
									if [ $rt_quiery = 0 ]
									then
										cd ${script_path}
										dialog --title "HINWEIS" --backtitle "Universal Credit System" --yesno "Nur neue Dateien hinzufügen?" 0 0
										rt_quiery=$?
										if [ $rt_quiery = 0 ]
										then
											tar -xkf $file_path $files_to_fetch
										else
											tar -xvf $file_path $files_to_fetch
										fi
										file_found=1
									else
										file_found=1
									fi
								else
									dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Die Datei $file_path konnte leider nicht geöffnet werden!" 0 0
								fi
								rm ${script_path}/files_to_fetch.tmp
							else
								file_found=1
							fi
						done
						;;
				"Sync")		dialog --title "Synchronisieren" --backtitle "Universal Credit System" --yes-label "Syncfile einlesen" --no-label "Syncfile erstellen" --yesno "Wollen Sie eine Synchronisations-Datei von anderen Benutzern einlesen oder wollen Sie selbst eine Synchronistations-Datei für andere Benutzer erstellen?" 0 0
						rt_quiery=$?
						case $rt_quiery in
							"0")	file_found=0
                        					path_to_search=$HOME
              			          			while [ $file_found = 0 ]
                        					do
                                					file_path=`dialog --title "Datei einlesen" --backtitle "Universal Credit System" --fselect $path_to_search 20 48 3>&1 1>&2 2>&3`
 			                               			rt_quiery=$?
                        		        			if [ $rt_quiery = 0 ]
                                					then
										check_archive $file_path
                              	  						rt_quiery=$?
						                                if [ $rt_quiery = 0 ]
										then
   											dialog --ok-label 'Weiter' --extra-button --extra-label 'Abbrechen' --title "Datei-Inhalt" --backtitle "Universal Credit System" --prgbox "cat ${script_path}/files_to_fetch.tmp" 15 100
                                 				       			rt_quiery=$?
                                        						if [ $rt_quiery = 0 ]
                               			        	 			then
                                                						cd ${script_path}
                                                						dialog --title "HINWEIS" --backtitle "Universal Credit System" --yesno "Nur neue Dateien hinzufügen?" 0 0
                                        		        				rt_quiery=$?
                     		                           					if [ $rt_quiery = 0 ]
                                	                					then
                                        	               			 			tar -xkf $file_path $files_to_fetch
                                                						else
                                                 				       			tar -xvf $file_path $files_to_fetch
                                                						fi
                                        						else
                                                						file_found=1
                                        						fi
										else
											dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Die Datei $file_path konnte leider nicht geöffnet werden!" 0 0
										fi
										rm ${script_path}/files_to_fetch.tmp
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
									echo "proofs/$line/freetsa.tsq" >>${script_path}/files_for_sync.tmp
									echo "proofs/$line/freetsa.tsr" >>${script_path}/files_for_sync.tmp
								done <${script_path}/keys_for_sync.tmp

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
								#echo $tar_string
								synch_now=`date +%s`
								tar_string="${tar_string} proofs/${handover_account}/${handover_account}.txt"
								cd ${script_path}
								tar -cvf ${synch_now}.tar ${tar_string}
								rt_quiery=$?
								if [ $rt_quiery = 0 ]
								then
									dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Synchronisations-Datei erfolgreich erstellt.\n\nPfad:\n${script_path}/${synch_now}.tar" 0 0
                        					else
									dialog --title "FEHLER" --backtitle "Universal Credit System" --msgbox "Synchronisations-Datei (${script_path}/${synch_now}.tar) konnte nicht erstellt werden!" 0 0
								fi
								rm ${script_path}/keys_sync.tmp
								rm ${script_path}/files_for_sync.tmp
								;;
						esac
						;;
				"Historie")	cd ${script_path}/trx
						grep -l "S:${keylist_hash}" *.* >${script_path}/my_trx.tmp
						grep -l " R:${keylist_hash}" *.* >>${script_path}/my_trx.tmp
						cd ${script_path}
						no_trx=`cat ${script_path}/my_trx.tmp|wc -l`
						menu_display_text=""
						if [ $no_trx -gt 0 ]
						then
							while read line
							do
								line_extracted=`echo $line`
								sender=`head -1 ${script_path}/trx/${line_extracted}|cut -d' ' -f1|cut -d':' -f2`
								trx_date=`head -1 ${script_path}/trx/${line_extracted}|cut -d' ' -f4`
                              	                        	trx_amount=`head -1 ${script_path}/trx/${line_extracted}|cut -d' ' -f2`
								trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
								trx_fee="0${trx_fee}"
                                                               	trx_amount_with_fee=`echo "${trx_amount} + ${trx_fee}"|bc`
								is_user_sender_blacklisted=`grep "${sender}" ${script_path}/blacklisted_accounts.dat|wc -l|sed 's/ //g'`
								is_user_receiver_blacklisted=`grep "${handover_user}" ${script_path}/blacklisted_accounts.dat|wc -l|sed 's/ //g'`
								is_trx_blacklisted=`grep "${line_extracted}" ${script_path}/blacklisted_trx.dat|wc -l|sed 's/ //g'`
								if [ $is_user_sender_blacklisted = 0 ]
								then
									if [ $is_user_receiver_blacklisted = 0 ]
									then

										if [ $is_trx_blacklisted = 0 ]
										then
											if [ $sender = $handover_account ]
											then
												menu_display_text="${menu_display_text}${trx_date}:-${trx_amount_with_fee} GESENDET "
											else
												menu_display_text="${menu_display_text}${trx_date}:+${trx_amount} EMPFANGEN "
											fi
										else
											if [ $sender = $handover_account ]
											then
												menu_display_text="${menu_display_text}${trx_date}:-${trx_amount_with_fee} WIDERRUFEN "
											else
												menu_display_text="${menu_display_text}${trx_date}:+${trx_amount} WIDERRUFEN "
											fi
										fi
									else
										if [ $sender = $handover_account ]
										then
											menu_display_text="${menu_display_text}${trx_date}:-${trx_amount_with_fee} WIDERRUFEN "
										else
											menu_display_text="${menu_display_text}${trx_date}:+${trx_amount} WIDERRUFEN "
										fi
									fi
								else
									if [ $sender = $handover_account ]
									then
										menu_display_text="${menu_display_text}${trx_date}:-${trx_amount_with_fee} WIDERRUFEN "
									else
										menu_display_text="${menu_display_text}${trx_date}:+${trx_amount} WIDERRUFEN "
                                                                        fi
								fi
							done <${script_path}/my_trx.tmp
						else
							menu_display_text="Keine Ergebnisse"
						fi
						overview_quit=0
						while [ $overview_quit = 0 ]
						do
							decision=`dialog --ok-label 'Öffnen' --cancel-label 'Zurück' --title "Transaktionshistorie" --backtitle "Universal Credit System" --menu "Übersicht über die Transaktionen Ihres Kontos:" 0 0 0 ${menu_display_text} 3>&1 1>&2 2>&3`
							rt_quiery=$?
							if [ $rt_quiery = 0 ]
							then
								if [ $decision != "Keine" ]
								then
									trx_sign=`echo $decision|cut -d':' -f2|cut -c 1`
									trx_date=`echo $decision|cut -d':' -f1`
									trx_file=`cat ${script_path}/my_trx.tmp|grep "${trx_date}"`
									sender=`head -1 ${script_path}/trx/${trx_file}|cut -d' ' -f1|cut -d':' -f2`
									receiver=`head -1 ${script_path}/trx/${trx_file}|cut -d' ' -f3|cut -d':' -f2`
									trx_status=""
									trx_confirmations=0
									trx_blacklisted=`cat ${script_path}/blacklisted_trx.dat|grep "${trx_file}"|wc -l|sed 's/ //g'`
									if [ $trx_blacklisted = 1 ]
									then
										trx_status="TRX_BLACKLISTED "
									fi
									sender_blacklisted=`cat ${script_path}/blacklisted_accounts.dat|grep "${sender}"|wc -l|sed 's/ //g'`
									if [ $sender_blacklisted = 1 ]
									then
									trx_status="${trx_status}SDR_BLACKLISTED "
									fi
									receiver_blacklisted=`cat ${script_path}/blacklisted_accounts.dat|grep "${sender}"|wc -l|sed 's/ //g'`
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
										trx_confirmations_user=`grep "${trx_file}" ${script_path}/proofs/$line/$line.txt|wc -l`
										if [ $trx_confirmations_user = 1 ]
										then
											trx_confirmations=$(( $trx_confirmations + 1 ))
										fi
									done <${script_path}/friends.dat
									if [ $sender = $handover_account ]
									then
										trx_amount_with_fee=`echo $decision|cut -d':' -f2|sed 's/+//g'|sed 's/-//g'|sed 's/IMP//g'`
										trx_amount=`echo "${trx_amount_with_fee} / 1.001"|bc`
										trx_fee=`echo "${trx_amount_with_fee} - ${trx_amount}"|bc`
										trx_fee="0${trx_fee}"
										dialog --title "Transaktion anzeigen" --backtitle "Universal Credit System" --msgbox "TYP :\nAusgehende Transaktion\n\nEMPFÄNGER :\n${receiver}\n\nBETRAG :\n-${trx_amount} ${currency_symbol}\n\nGEBÜHR :\n-${trx_fee} ${currency_symbol}\n\nTOTAL :\n-${trx_amount_with_fee} ${currency_symbol}\n\nDATUM :\n${trx_date}\n\nDATEI :\n${trx_file}\n\nSTATUS :\n${trx_status}\n\nCONFIRMATIONS :\n${trx_confirmations}" 0 0
									else
										trx_amount=`echo $decision|cut -d':' -f2|sed 's/+//g'|sed 's/-//g'|sed 's/IMP//g'`
                                                                        	trx_fee=`echo "${trx_amount} * ${current_fee}"|bc`
                                                                        	trx_fee="0${trx_fee}"
                                                                        	trx_amount_with_fee=`echo "${trx_amount} + ${trx_fee}"|bc`
										dialog --title "Transaktion anzeigen" --backtitle "Universal Credit System" --msgbox "TYP :\nEingehende Transaktion\n\nSENDER :\n${sender}\n\nBETRAG :\n+${trx_amount} ${currency_symbol}\n\nDATUM :\n${trx_date}\n\nDATEI :\n${trx_file}\n\nSTATUS :\n${trx_status}\n\nCONFIRMATIONS :\n${trx_confirmations}" 0 0
									fi
								else
									dialog --title "HINWEIS" --backtitle "Universal Credit System" --msgbox "Es gibt keine Transaktionen zum anzeigen!" 0 0
								fi
							else
								overview_quit=1
							fi
						done
						;;
				"Stats")	dialog --title "Statistik" --backtitle "Universal Credit System" --msgbox "Aktuelle Auszahlung pro Tag :\n${coinload} ${currency_symbol}\n\nNächste Phase beginnt :\nin ${in_days} Tagen\n\nNächste Auszahlung pro Tag :\n${next_coinload} ${currency_symbol}\n\n" 0 0
						;;
				"Log out")	user_logged_in=0
						;;
			esac
		fi
	fi
done
