MT100_process(){
		###ALLOW DEBUGGING############################################
		if [ "$debug" -eq 1 ]
		then
			set -x
			set -v
		fi

		###EXRACT DATA FOR CHECK######################################
		trx_file="${script_path}/trx/${trx_filename}"
		trx_stamp=$(awk -F: '/:TIME:/{print $3}' "$trx_file")
		trx_sender=$(awk -F: '/:SNDR:/{print $3}' "$trx_file")
		trx_receiver=$(awk -F: '/:RCVR:/{print $3}' "$trx_file")
		trx_hash=$(sha256sum "$trx_file")
		trx_hash=${trx_hash%% *}
		trx_path="trx/${trx_filename}"

		###CHECK IF INDEX-FILE EXISTS#################################
		if [ -f "${script_path}/proofs/${trx_sender}/${trx_sender}.txt" ] && [ -s "${script_path}/proofs/${trx_sender}/${trx_sender}.txt" ] || [ "${trx_sender}" = "${handover_account}" ]
		then
			###CHECK IF TRX IS SIGNED BY USER#############################
			is_signed=$(grep -c "trx/${trx_filename} ${trx_hash}" "${script_path}/proofs/${trx_sender}/${trx_sender}.txt")
			if [ "$is_signed" -gt 0 ] || [ "${trx_sender}" = "${handover_account}" ]
			then
				###EXTRACT TRX AMOUNT#########################################
				trx_amount=$(awk -F: '/:AMNT:/{print $3}' "$trx_file")
				trx_asset=$(awk -F: '/:ASST:/{print $3}' "$trx_file")
				
				###CHECK IF SENDER IS IN LEDGER###############################
				sender_in_ledger=$(grep -c "${trx_asset}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
				if [ "$sender_in_ledger" -eq 1 ]
				then
					###GET ACCOUNT BALANCE########################################
					account_balance=$(grep "${trx_asset}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
					account_balance=${account_balance#*=}

					###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
					account_check_balance=$(echo "${account_balance} - ${trx_amount}"|bc|sed 's/^\./0./g')
					enough_balance=$(echo "${account_check_balance} >= 0"|bc)

					###CHECK IF BALANCE IS OK#####################################
					if [ "$enough_balance" -eq 1 ]
					then
						self_signed=0
						is_multi_sign=0
						is_multi_sign_wallet=0
						is_multi_sign_trx=0

						###CHECK IF MULTI SIG WALLET##################################
						if [ -f "${script_path}/proofs/${trx_sender}/multi.sig" ] && [ -s "${script_path}/proofs/${trx_sender}/multi.sig" ]
						then
							is_multi_sign=1
							is_multi_sign_wallet=1
						fi

						###CHECK IF MULTI SIG TRANSACTION#############################
						if [ "$(grep -c ":MSIG:" "${trx_file}")" -gt 0 ]
						then
							is_multi_sign=1
							is_multi_sign_trx=1
						fi

						###CONTINUE WITH MULTI SIGN PROCESSING########################
						if [ "${is_multi_sign}" -eq 1 ]
						then
							####CHECK IF USER NEEDS TO SIGN THE FILE######################
							if [ "$(grep -c ":MSIG:${handover_account}" "${script_path}/proofs/${trx_sender}/multi.sig")" -gt 0 ] || [ "$(grep -c ":MSIG:${handover_account}" "${trx_file}")" -eq 1 ]
							then
								###CHECK FOR ACKNOWLEDGED AND DECLINED FILES##################
								if [ ! -f "${user_path}"/messages_ack.sig ]
								then
									touch "${user_path}"/messages_ack.sig
								fi
								if [ ! -f "${user_path}"/messages_dec.sig ]
								then
									touch "${user_path}"/messages_dec.sig
								fi
								
								###CHECK IF MESSAGE ALREADY HAS BEEN SIGNED###################
								already_signed=$(cat "${user_path}"/messages_ack.sig "${user_path}"/messages_dec.sig|grep -c "trx/${trx_filename} ${trx_hash}" )
								if [ "${already_signed}" -eq 0 ] && [ "$gui_mode" -eq 1 ]
								then
									###SHOW GUI AND ASK IF TO SIGN################################
									dialog --exit-label "SIGN" --help-button --help-label "DECLINE" --title "MULTI SIGNATURE" --backtitle "$core_system_name $core_system_version" --output-fd 1 --textbox "${trx_file}" 0 0
									rt_query=$?
									if [ "${rt_query}" -eq 0 ]
									then
										self_signed=1
			
										###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
										echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
										
										###SAVESTORE SO PRORGAM REMEMBERS#############################
										echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_ack.sig
									else
										###SAVESTORE SO PRORGAM REMEMBERS#############################
										echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_dec.sig
									fi
								else
									###CHECK IF PREVIOUSLY ACKNOWLEDGED OR DECLINED###############
									already_signed=$(cat "${user_path}"/messages_ack.sig "${user_path}"/messages_dec.sig|grep -c "trx/${trx_filename} ${trx_hash}")
									if [ "${already_signed}" -eq 1 ]
									then
										if [ "$(grep -c "trx/${trx_filename} ${trx_hash}" "${user_path}"/messages_ack.sig)" -eq 1 ]
										then
											###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
											echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
										fi
										self_signed=1
									else
										if [ "$gui_mode" -eq 0 ] && [ -n "${cmd_path}" ] && [ "$(echo "${cmd_path}"|grep -c "${trx_filename}")" -eq 1 ]
										then
											if [ "${cmd_action}" = "sign" ]
											then
												self_signed=1

												###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
												echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
												
												###SAVESTORE SO PRORGAM REMEMBERS#############################
												echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_ack.sig
											fi
											if [ "${cmd_action}" = "decline" ]
											then
												###SAVESTORE SO PRORGAM REMEMBERS#############################
												echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_dec.sig
											fi
										fi
									fi
								fi
							fi
						else
							###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
							echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
						fi

						###CHECK IF RECEIVER IS ASSET#################################
						is_asset=$(grep -c "${trx_receiver}" "${user_path}"/all_assets.dat)
						if [ "$is_asset" -eq 1 ]
						then
							is_fungible=$(grep -c "asset_fungible=1" "${script_path}/assets/${trx_receiver}")
						fi

						###CHECK IF RECEIVER IS IN LEDGER#############################
						receiver_in_ledger=$(grep -c "${trx_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
						if [ "$receiver_in_ledger" -eq 0 ]
						then
							###CHECK IF RECEIVER IS IN LEDGER WITH UCC BALANCE############
							receiver_in_ledger=$(grep -c "${main_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
							if [ "$receiver_in_ledger" -eq 1 ]
							then
								###CHECK IF RECEIVER IS ASSET#################################
								if [ "$is_asset" -eq 1 ]
								then
									###CHECK IF ASSET IS FUNGIBLE################################
									if [ "$is_fungible" -eq 1 ]
									then
										echo "${trx_asset}:${trx_receiver}=0" >>"${user_path}/${focus}_ledger.dat"
									else
										receiver_in_ledger=0
									fi
								else
									###WRITE LEDGER ENTRY########################################
									echo "${trx_asset}:${trx_receiver}=0" >>"${user_path}/${focus}_ledger.dat"
								fi
							fi
						fi
						if [ "$receiver_in_ledger" -eq 1 ]
						then
							is_multi_sign_okay=0

							###CHECK IF MULTI SIGN########################################
							if [ "${is_multi_sign}" -eq 1 ]
							then
								###LOGIC FOR WALLET MULTI SIGNATURE CONFIRMATIONS#############
								if [ "${is_multi_sign_wallet}" -eq 1 ]
								then
									is_multi_sign_okay=1
									number_multi_signed=0
									total_number_signer=0
									
									###GO THROUGH LIST OF WALLET MULTI SIGN ENTRIES###############
									for signer in $(awk -F: '/:MSIG:/{print $3}' "${script_path}/proofs/${trx_sender}/multi.sig")
									do
										###ADD CONFIRMATION FOR OWN###################################
										if [ "${signer}" = "${handover_account}" ] && [ "${self_signed}" -eq 1 ]
										then
											number_multi_signed=$(( number_multi_signed + 1 ))
										else
											if [ -f "${script_path}/proofs/${signer}/${signer}.txt" ] && [ -s "${script_path}/proofs/${signer}/${signer}.txt" ]
											then
												###GET CONFIRMATIONS##########################################
												is_multi_signed=$(grep -c "trx/${trx_filename} ${trx_hash}" "${script_path}/proofs/${signer}/${signer}.txt")
												if [ "${is_multi_signed}" -eq 1 ]
												then
													number_multi_signed=$(( number_multi_signed + 1 ))
												fi
											fi
										fi
										total_number_signer=$(( total_number_signer + 1 ))
									done

									###CALCULATE MAJORITY#########################################
									majority=$(( total_number_signer / 2 ))
									majority=$(( majority + 1 ))
									if [ "${number_multi_signed}" -ge "${majority}" ]
									then
										is_multi_sign_okay=0
									fi
								fi
								
								###LOGIC FOR TRX MULTI SIGNATURE CONFIRMATIONS################
								if [ "${is_multi_sign_trx}" -eq 1 ]
								then
									is_multi_sign_okay=1
									number_multi_signed=0
									total_number_signer=0

									###GO THROUGH LIST OF TRX MULTI SIGN ENTRIES##################
									for signer in $(awk -F: '/:MSIG:/{print $3}' "${trx_file}"|sort -u)
									do
										###ADD CONFIRMATION FOR OWN###################################
										if [ "${signer}" = "${handover_account}" ] && [ "${self_signed}" -eq 1 ]
										then
											number_multi_signed=$(( number_multi_signed + 1 ))
										else
											###CHECK IF SIGNER HAS INDEX FILE#############################
											if [ -f "${script_path}/proofs/${signer}/${signer}.txt" ] && [ -s "${script_path}/proofs/${signer}/${signer}.txt" ]
											then
												###GET CONFIRMATIONS##########################################
												is_multi_signed=$(grep -c "trx/${trx_filename} ${trx_hash}" "${script_path}/proofs/${signer}/${signer}.txt")
												if [ "${is_multi_signed}" -eq 1 ]
												then
													number_multi_signed=$(( number_multi_signed + 1 ))
												fi
											fi
										fi
										total_number_signer=$(( total_number_signer + 1 ))
									done
		
									###CALCULATE MAJORITY#########################################
									majority=$(( total_number_signer / 2 ))
									majority=$(( majority + 1 ))
									if [ "${number_multi_signed}" -ge "${majority}" ]
									then
										is_multi_sign_okay=0
									fi
								fi

								###ACKNOWLEDGE TRANSACTION####################################
								if [ "${is_multi_sign_okay}" -eq 0 ] || [ "${trx_sender}" = "${handover_account}" ]
								then
									###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
									echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
								fi
							fi
							
							###ONLY CONTINUE IF MULTI SIGN IS OKAY########################
							if [ "${is_multi_sign_okay}" -eq 0 ]
							then
								###GET CONFIRMATIONS##########################################
								total_confirmations=$(grep -s -l "trx/${trx_filename} ${trx_hash}" "${script_path}"/proofs/*/*.txt|grep -c -v "${trx_sender}\|${trx_receiver}")

								###ADD 1 CONFIRMATION FOR OWN#################################
								if [ ! "${trx_sender}" = "${handover_account}" ] && [ ! "${trx_receiver}" = "${handover_account}" ]
								then
									total_confirmations=$(( total_confirmations + 1 ))
								fi

								###CHECK CONFIRMATIONS########################################
								if [ "$total_confirmations" -ge "$confirmations_from_users" ]
								then
									###SET BALANCE FOR SENDER#####################################
									account_new_balance=$account_check_balance
									sed -i."$my_pid".bak "s/${trx_asset}:${trx_sender}=${account_balance}/${trx_asset}:${trx_sender}=${account_new_balance}/g" "${user_path}/${focus}_ledger.dat" && rm "${user_path}/${focus}_ledger.dat.${my_pid}.bak" 2>/dev/null
							
									###SET BALANCE FOR RECEIVER###################################
									receiver_old_balance=$(grep "${trx_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
									receiver_old_balance=${receiver_old_balance#*=}
									receiver_new_balance=$(echo "${receiver_old_balance} + ${trx_amount}"|bc|sed 's/^\./0./g')
									sed -i."$my_pid".bak "s/${trx_asset}:${trx_receiver}=${receiver_old_balance}/${trx_asset}:${trx_receiver}=${receiver_new_balance}/g" "${user_path}/${focus}_ledger.dat" && rm "${user_path}/${focus}_ledger.dat.${my_pid}.bak" 2>/dev/null

									###CHECK IF EXCHANGE REQUIRED#################################
									if [ "$is_asset" -eq 1 ] && [ "$is_fungible" -eq 1 ]
									then
										###EXCHANGE###################################################
										asset_type_price=$(grep "asset_price=" "${script_path}/assets/${trx_asset}")
										asset_type_price=${asset_type_price#*=}
										asset_price=$(grep "asset_price=" "${script_path}/assets/${trx_receiver}")
										asset_price=${asset_price#*=}
										asset_value=$(echo "scale=9; ${trx_amount} * ${asset_type_price} / ${asset_price}"|bc|sed 's/^\./0./g')

										###WRITE ENTRY TO LEDGER FOR EXCHANGE#########################
										receiver_in_ledger=$(grep -c "${trx_receiver}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
										if [ "$receiver_in_ledger" -eq 1 ]
										then
											sender_old_balance=$(grep "${trx_receiver}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
											sender_old_balance=${sender_old_balance#*=}
											sender_new_balance=$(echo "${sender_old_balance} + ${asset_value}"|bc|sed 's/^\./0./g')
											sed -i."$my_pid".bak "s/${trx_receiver}:${trx_sender}=${sender_old_balance}/${trx_receiver}:${trx_sender}=${sender_new_balance}/g" "${user_path}/${focus}_ledger.dat" && rm "${user_path}/${focus}_ledger.dat.${my_pid}.bak" 2>/dev/null
										else
											echo "${trx_receiver}:${trx_sender}=${asset_value}" >>"${user_path}/${focus}_ledger.dat"
										fi
									fi
								fi
							fi
							ignore=0
						fi
					fi
				fi
			fi
		fi
}
MT100_verify(){
		###ALLOW DEBUGGING############################################
		if [ "$debug" -eq 1 ]
		then
			set -x
			set -v
		fi
		###CHECK IF PURPOSE CONTAINS ALNUM######################
		purpose_key_start=$(awk -F: '/:PRPK:/{print NR}' "$file_to_check")
		purpose_key_start=$(( purpose_key_start + 1 ))
		purpose_key_end=$(awk -F: '/:PRPS:/{print NR}' "$file_to_check")
		purpose_key_end=$(( purpose_key_end - 1 ))
		purpose_key=$(sed -n "${purpose_key_start},${purpose_key_end}p" "$file_to_check")
		purpose_key_contains_alnum=$(printf "%s" "${purpose_key}"|grep -c '[^a-zA-Z0-9+/=]')
		purpose_start=$(awk -F: '/:PRPS:/{print NR}' "$file_to_check")
		purpose_start=$(( purpose_start + 1 ))
		purpose_end=$(awk -F: '/BEGIN PGP SIGNATURE/{print NR}' "$file_to_check")
		purpose_end=$(( purpose_end - 1 ))
		purpose=$(sed -n "${purpose_start},${purpose_end}p" "$file_to_check")
		purpose_contains_alnum=$(printf "%s" "${purpose}"|grep -c '[^a-zA-Z0-9+/=]')
		if [ "$purpose_key_contains_alnum" -eq 0 ] && [ "$purpose_contains_alnum" -eq 0 ]
		then
			###CHECK FOR MULTI SIGNATURE ENTRIES####################
			multi_sig_okay=0
			multi_sig_number=$(grep -c ":MSIG:" "$file_to_check")
			if [ "${multi_sig_number}" -gt 0 ]
			then
				###CHECK FOR DOUBLE ENTRIES#############################
				if [ "${multi_sig_number}" -ne "$(grep ":MSIG:" "$file_to_check"|sort -u|wc -l)" ] || [ "${multi_sig_number}" -gt 10 ]
				then
					multi_sig_okay=1
				else
					###CHECK FOR NON COMPLIANT CHARACTERS###################
					multi_sig_okay=$(awk -F: '/:MSIG:/{print $3}' "$file_to_check"|grep -c '[^a-zA-Z0-9]')
				fi
			fi

			###EXTRACT ASSET########################################
			trx_asset=$(awk -F: '/:ASST:/{print $3}' "$file_to_check")

			###CHECK IF ASSET TYPE EXISTS###########################
			if [ "$(grep -c "${trx_asset}" "${user_path}"/all_assets.dat)" -eq 1 ] && [ "${multi_sig_okay}" -eq 0 ]
			then
				###EXTRACT AMOUNT#######################################
				trx_amount=$(awk -F: '/:AMNT:/{print $3}' "$file_to_check")
				if [ "$(printf "%s" "${trx_amount}"|grep -c '[^0-9.]')" -eq 0 ]
				then
					###CHECK IF AMOUNT IS MINIMUM 0.000000001###############
					is_amount_ok=$(echo "${trx_amount} >= 0.000000001"|bc)
					is_amount_mod=$(echo "${trx_amount} % 0.000000001"|bc)
					is_amount_mod=$(echo "${is_amount_mod} > 0"|bc)

					###CHECK IF USER HAS CREATED A INDEX FILE###############
					if [ -f "${script_path}/proofs/${user_to_check}/${user_to_check}.txt" ] && [ -s "${script_path}/proofs/${user_to_check}/${user_to_check}.txt" ]
					then
						####CHECK IF USER HAS INDEXED THE TRANSACTION###########
						is_trx_signed=$(grep -c "trx/${line}" "${script_path}/proofs/${user_to_check}/${user_to_check}.txt")
						if [ "$is_trx_signed" -eq 1 ] && [ "$is_amount_ok" -eq 1 ] && [ "$is_amount_mod" -eq 0 ]
						then
							trx_acknowledged=1
						else
							if [ "$delete_trx_not_indexed" -eq 0 ] && [ "$is_amount_ok" -eq 1 ] && [ "$is_amount_mod" -eq 0 ]
							then
								trx_acknowledged=1
							fi
						fi
					else
						if [ "$delete_trx_not_indexed" -eq 0 ] && [ "$is_amount_ok" -eq 1 ] && [ "$is_amount_mod" -eq 0 ]
						then
							trx_acknowledged=1
						fi
					fi
				fi
			fi
		fi
}
