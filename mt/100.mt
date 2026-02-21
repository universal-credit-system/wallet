MT100_process(){
		###ALLOW DEBUGGING############################################
		if [ "${debug}" -eq 1 ]
		then
			set -x
			set -v
		fi

		###EXRACT DATA FOR CHECK######################################
		trx_file="${script_path}/trx/${trx_filename}"
		trx_hash=$(sha256sum "${trx_file}")
		trx_hash=${trx_hash%% *}
		trx_path="trx/${trx_filename}"
		IFS='|' read -r trx_stamp trx_sender trx_receiver trx_amount trx_asset <<-EOF
		$(awk -F: '
			/:TIME:/ {time=$3}
			/:SNDR:/ {sndr=$3}
			/:RCVR:/ {rcvr=$3}
			/:AMNT:/ {amnt=$3}
			/:ASST:/ {asst=$3}
			END { printf "%s|%s|%s|%s|%s\n", time, sndr, rcvr, amnt, asst }
		' "${trx_file}")
		EOF

		###CHECK IF INDEX-FILE EXISTS#################################
		if [ -f "${script_path}/proofs/${trx_sender}/${trx_sender}.txt" ] && [ -s "${script_path}/proofs/${trx_sender}/${trx_sender}.txt" ] || [ "${trx_sender}" = "${handover_account}" ]
		then
			###CHECK IF TRX IS SIGNED BY USER#############################
			is_signed=$(grep -c "^${trx_path} ${trx_hash}" "${script_path}/proofs/${trx_sender}/${trx_sender}.txt")
			if [ "${is_signed}" -gt 0 ] || [ "${trx_sender}" = "${handover_account}" ]
			then
				###CHECK IF SENDER IS IN LEDGER###############################
				sender_in_ledger=$(grep -c "^${trx_asset}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
				if [ "${sender_in_ledger}" -eq 1 ]
				then
					###GET ACCOUNT BALANCE########################################
					account_balance=$(grep "^${trx_asset}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
					account_balance=${account_balance#*=}

					###CHECK IF ACCOUNT HAS ENOUGH BALANCE FOR THIS TRANSACTION###
					set -- $(awk -v balance="${account_balance}" -v amount="${trx_amount}" '
						BEGIN { d=balance-amount; printf "%.9f %d\n", d, (d >= 0 ? 1 : 0) }
					')
					: "${1:=0.000000000}"
					: "${2:=0}"
					account_check_balance=$1
					enough_balance=$2

					###CHECK IF BALANCE IS OK#####################################
					if [ "${enough_balance}" -eq 1 ]
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
						if [ "$(grep -c "^:MSIG:" "${trx_file}")" -gt 0 ]
						then
							is_multi_sign=1
							is_multi_sign_trx=1
						fi

						###CONTINUE WITH MULTI SIGN PROCESSING########################
						if [ "${is_multi_sign}" -eq 1 ]
						then
							###CHECK FOR ACKNOWLEDGED AND DECLINED FILES##################
							if [ ! -e "${user_path}"/messages_ack.sig ]
 							then
								touch "${user_path}"/messages_ack.sig
							fi
							if [ ! -e "${user_path}"/messages_dec.sig ]
							then
								touch "${user_path}"/messages_dec.sig
							fi
							####CHECK IF USER NEEDS TO SIGN THE FILE######################
							if [ -n "$(grep -s "^:MSIG:${handover_account}" "${script_path}/proofs/${trx_sender}/multi.sig")" ] || [ "$(grep -c "^:MSIG:${handover_account}" "${trx_file}")" -eq 1 ]
							then
								###CHECK IF MESSAGE ALREADY HAS BEEN SIGNED###################
								already_signed=$(cat "${user_path}"/messages_ack.sig "${user_path}"/messages_dec.sig|grep -c "^trx/${trx_filename} ${trx_hash}" )
								if [ "${already_signed}" -eq 0 ] && [ "${gui_mode}" -eq 1 ]
								then
									###SHOW GUI AND ASK IF TO SIGN################################
									dialog --exit-label "SIGN" --help-button --help-label "DECLINE" --title "MULTI SIGNATURE" --backtitle "${core_system_name} ${core_system_version}" --output-fd 1 --textbox "${trx_file}" 0 0
									rt_query=$?
									if [ "${rt_query}" -eq 0 ]
									then
										self_signed=1
			
										###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
										echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
										
										###SAVESTORE SO PRORGAM REMEMBERS#############################
										echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_ack.sig
									else
										if [ "${rt_query}" -eq 1 ]
										then
											###SAVESTORE SO PRORGAM REMEMBERS#############################
											echo "${trx_path} ${trx_hash}" >>"${user_path}"/messages_dec.sig
										fi
									fi
								else
									if [ "${already_signed}" -eq 1 ]
									then
										if [ "$(grep -c "^trx/${trx_filename} ${trx_hash}" "${user_path}"/messages_ack.sig)" -eq 1 ]
										then
											self_signed=1
											###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
											echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
										fi
									else
										if [ "${gui_mode}" -eq 0 ] && [ -n "${cmd_path}" ] && [ "$(echo "${cmd_path}"|grep -c "${trx_filename}")" -eq 1 ]
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
						if [ "${is_asset}" -eq 1 ]
						then
							is_fungible=$(grep -c "asset_fungible=1" "${script_path}/assets/${trx_receiver}")
						fi

						###CHECK IF RECEIVER IS IN LEDGER#############################
						receiver_in_ledger=$(grep -c "^${trx_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
						if [ "${receiver_in_ledger}" -eq 0 ]
						then
							###CHECK IF RECEIVER IS IN LEDGER WITH UCC BALANCE############
							receiver_in_ledger=$(grep -c "^${main_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
							if [ "${receiver_in_ledger}" -eq 1 ]
							then
								###CHECK IF RECEIVER IS ASSET#################################
								if [ "${is_asset}" -eq 1 ]
								then
									###CHECK IF ASSET IS FUNGIBLE################################
									if [ "${is_fungible}" -eq 1 ]
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
						if [ "${receiver_in_ledger}" -eq 1 ]
						then
							is_multi_sign_okay=0

							###CHECK IF MULTI SIGN########################################
							if [ "${is_multi_sign}" -eq 1 ]
							then
								###LOGIC FOR WALLET MULTI SIGNATURE CONFIRMATIONS#############
								if [ "${is_multi_sign_wallet}" -eq 1 ]
								then
									is_multi_sign_okay=1
									
									###CHECK CONFIRMATIONS#######################################
									if awk \
									    -v DEBUG_MODE="${debug}" \
									    -v PROOF_PATH="${script_path}/proofs" \
									    -v TRX_REF="${trx_path} ${trx_hash}" \
									    -f "${script_path}"/control/functions/check_multisig.awk \
									    "${script_path}/proofs/${trx_sender}/multi.sig"
									then
										is_multi_sign_okay=0
									fi
								fi
								
								###LOGIC FOR TRX MULTI SIGNATURE CONFIRMATIONS################
								if [ "${is_multi_sign_trx}" -eq 1 ]
								then
									is_multi_sign_okay=1

									###CHECK CONFIRMATIONS#######################################
									if awk \
									    -v DEBUG_MODE="${debug}" \
									    -v PROOF_PATH="${script_path}/proofs" \
									    -v TRX_REF="${trx_path} ${trx_hash}" \
									    -f "${script_path}"/control/functions/check_multisig.awk \
									    "${trx_file}"
									then
										is_multi_sign_okay=0
									fi
								fi

								###ACKNOWLEDGE TRANSACTION####################################
								if [ "${is_multi_sign_okay}" -eq 0 ] || [ "${trx_sender}" = "${handover_account}" ]
								then
									if [ "${self_signed}" -eq 0 ]
									then
										###WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)##############
										echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
									fi
								fi
							fi
							
							###ONLY CONTINUE IF MULTI SIGN IS OKAY########################
							if [ "${is_multi_sign_okay}" -eq 0 ]
							then
								###GET CONFIRMATIONS##########################################
								total_confirmations=$(grep -s -l "trx/${trx_filename} ${trx_hash}" "${script_path}"/proofs/*/*.txt|grep -c -v "${trx_sender}\|${trx_receiver}")
								total_confirmations=$(awk \
											-v trx_ref="trx/${trx_filename} ${trx_hash}" \
											-v sndr="${trx_sender}" \
											-v rcvr="${trx_receiver}" \
											-f "${script_path}"/control/functions/get_confirmations.awk \
											"${script_path}"/proofs/*/*.txt)

								###ADD 1 CONFIRMATION FOR OWN#################################
								if [ ! "${trx_sender}" = "${handover_account}" ] && [ ! "${trx_receiver}" = "${handover_account}" ]
								then
									total_confirmations=$(( total_confirmations + 1 ))
								fi

								###CHECK CONFIRMATIONS########################################
								if [ "${total_confirmations}" -ge "${confirmations_from_users}" ]
								then
									###SET BALANCE FOR SENDER#####################################
									account_new_balance=${account_check_balance}
									
									###SET BALANCE FOR RECEIVER###################################
									receiver_old_balance=$(grep "^${trx_asset}:${trx_receiver}" "${user_path}/${focus}_ledger.dat")
									receiver_old_balance=${receiver_old_balance#*=}
									receiver_new_balance=$(awk -v balance="${receiver_old_balance}" -v amount="${trx_amount}" 'BEGIN { printf "%.9f\n", balance + amount }')
									
									###WRITE LEDGER ENTRY FOR SENDER AND RECEIVER#################
									sed -e "s|^${trx_asset}:${trx_sender}=${account_balance}|${trx_asset}:${trx_sender}=${account_new_balance}|g" \
									    -e "s|^${trx_asset}:${trx_receiver}=${receiver_old_balance}|${trx_asset}:${trx_receiver}=${receiver_new_balance}|g" \
									    "${user_path}/${focus}_ledger.dat" >"${user_path}/${focus}_ledger.dat.${my_pid}.bak" && mv "${user_path}/${focus}_ledger.dat.${my_pid}.bak" "${user_path}/${focus}_ledger.dat"

									###CHECK IF EXCHANGE REQUIRED#################################
									if [ "${is_asset}" -eq 1 ] && [ "${is_fungible}" -eq 1 ]
									then
										###EXCHANGE###################################################
										asset_type_price=$(grep "asset_price=" "${script_path}/assets/${trx_asset}")
										asset_type_price=${asset_type_price#*=}
										asset_price=$(grep "asset_price=" "${script_path}/assets/${trx_receiver}")
										asset_price=${asset_price#*=}
										asset_value=$(awk -v amount="${trx_amount}" -v asset_type_price="${asset_type_price}" -v asset_price="${asset_price}" 'BEGIN { printf "%.9f\n", amount * asset_type_price / asset_price }')

										###WRITE ENTRY TO LEDGER FOR EXCHANGE#########################
										receiver_in_ledger=$(grep -c "${trx_receiver}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
										if [ "${receiver_in_ledger}" -eq 1 ]
										then
											sender_old_balance=$(grep "${trx_receiver}:${trx_sender}" "${user_path}/${focus}_ledger.dat")
											sender_old_balance=${sender_old_balance#*=}
											sender_new_balance=$(awk -v balance="${sender_old_balance}" -v asset_value="${asset_value}" 'BEGIN { printf "%.9f\n", balance + asset_value }')
											sed "s|^${trx_receiver}:${trx_sender}=${sender_old_balance}|${trx_receiver}:${trx_sender}=${sender_new_balance}|g" "${user_path}/${focus}_ledger.dat" >"${user_path}/${focus}_ledger.dat.${my_pid}.bak" && mv "${user_path}/${focus}_ledger.dat.${my_pid}.bak" "${user_path}/${focus}_ledger.dat"
										else
											echo "${trx_receiver}:${trx_sender}=${asset_value}" >>"${user_path}/${focus}_ledger.dat"
										fi
									fi
								fi
							fi
							###INITIALLY SET IN UCS_CLIENT.SH
							ignore=0
						fi
					fi
				fi
			fi
		fi
}
MT100_verify(){
		###ALLOW DEBUGGING############################################
		if [ "${debug}" -eq 1 ]
		then
			set -x
			set -v
		fi

		###CHECK IF PURPOSE CONTAINS ALNUM############################
		IFS='|' read -r  purpose_key_bad purpose_bad multi_sig_bad amount_ok trx_asset trx_amount <<-EOF
		$(awk -F: '
			BEGIN {
				in_prpk=0; in_prps=0
				prpk=""; prps=""
				msig_cnt=0; msig_dup=0
			}

			{
				if ($0 ~ /^:PRPK:/) { in_prpk=1; next }
				if ($0 ~ /^:PRPS:/) { in_prpk=0; in_prps=1; next }
				if ($0 ~ /BEGIN PGP SIGNATURE/) { in_prps=0 }

				if (in_prpk) prpk = prpk $0
				if (in_prps) prps = prps $0

				if ($0 ~ /^:MSIG:/) {
					msig_cnt++
					if (seen[$0]++) msig_dup=1

					msig_value = $3

					if (msig_value ~ /[^a-zA-Z0-9]/) msig_bad = 1
				}

				if ($0 ~ /^:ASST:/) { asst = $3 }
    				if ($0 ~ /^:AMNT:/) { amnt = $3 }
			}

			END {
				prpk_bad = (prpk ~ /[^a-zA-Z0-9+/=]/)
				prps_bad = (prps ~ /[^a-zA-Z0-9+/=]/)

				if (msig_cnt > 10) msig_bad=1
				if (msig_dup) msig_bad=1

				amnt_bad = (amnt ~ /[^0-9.]/)

				min = 0.000000001
				split(amnt, p, ".")
				scale_ok = (length(p[2]) == 9)
				amount_ok = (amnt >= min && scale_ok)

				printf "%d|%d|%d|%d|%s|%s\n",
					prpk_bad,
					prps_bad,
					(msig_bad ? 1 : 0),
					amount_ok,
					asst,
					amnt
			}' "${trx_file_path}")
		EOF
		
		###CHECK RESULTS##############################################
		trx_acknowledged=0
		if [ "${purpose_key_bad}" -eq 0 ] && [ "${purpose_bad}" -eq 0 ] && [ "${multi_sig_bad}" -eq 0 ] && [ "${amount_ok}" -eq 1 ]
		then
			###CHECK IF ASSET EXISTS######################################
			if grep -q "^${trx_asset}$" "${user_path}/all_assets.dat"
			then
				###CHECK IF INDEXED###########################################
				if [ -f "${script_path}/proofs/${user_to_check}/${user_to_check}.txt" ] && [ -s "${script_path}/proofs/${user_to_check}/${user_to_check}.txt" ]
				then
					if grep -q "trx/${line}" "${script_path}/proofs/${user_to_check}/${user_to_check}.txt"
		       			then
						trx_acknowledged=1
					fi
				else
			    		if [ "${delete_trx_not_indexed}" -eq 0 ]
			    		then
			    			trx_acknowledged=1
					fi
				fi
			fi
		fi
}
