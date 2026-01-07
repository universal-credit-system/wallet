MT100_process(){	
		###EXRACT DATA FOR CHECK######################################
		trx_file="${script_path}/trx/${trx_filename}"
		trx_stamp=$(awk -F: '/:TIME:/{print $3}' "$trx_file")
		trx_sender=$(awk -F: '/:SNDR:/{print $3}' "$trx_file")
		trx_receiver=$(awk -F: '/:RCVR:/{print $3}' "$trx_file")
		trx_hash=$(sha256sum "$trx_file")
		trx_hash=${trx_hash%% *}
		trx_path="trx/${trx_filename}"
		##############################################################

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
						####WRITE TRX TO FILE FOR INDEX (ACKNOWLEDGE TRX)#############
						echo "${trx_path} ${trx_hash}" >>"${user_path}/${focus}_index_trx.dat"
						##############################################################

						###SET BALANCE FOR SENDER#####################################
						account_new_balance=$account_check_balance
						sed -i."$my_pid".bak "s/${trx_asset}:${trx_sender}=${account_balance}/${trx_asset}:${trx_sender}=${account_new_balance}/g" "${user_path}/${focus}_ledger.dat" && rm "${user_path}/${focus}_ledger.dat.${my_pid}.bak" 2>/dev/null
						##############################################################

						###CHECK IF RECEIVER IS ASSET#################################
						is_asset=$(grep -c "${trx_receiver}" "${user_path}"/all_assets.dat)
						if [ "$is_asset" -eq 1 ]
						then
							is_fungible=$(grep -c "asset_fungible=1" "${script_path}/assets/${trx_receiver}")
						fi
						##############################################################

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
							ignore=0
						fi
					fi
				fi
			fi
		fi
}
MT100_verify(){
		###CHECK IF PURPOSE CONTAINS ALNUM######################
		purpose_key_start=$(awk -F: '/:PRPK:/{print NR}' "$file_to_check")
		purpose_key_start=$(( purpose_key_start + 1 ))
		purpose_key_end=$(awk -F: '/:PRPS:/{print NR}' "$file_to_check")
		purpose_key_end=$(( purpose_key_end - 1 ))
		purpose_key=$(sed -n "${purpose_key_start},${purpose_key_end}p" "$file_to_check")
		purpose_key_contains_alnum=$(printf "%s" "${purpose_key}"|grep -c -v '[a-zA-Z0-9+/=]')
		purpose_start=$(awk -F: '/:PRPS:/{print NR}' "$file_to_check")
		purpose_start=$(( purpose_start + 1 ))
		purpose_end=$(awk -F: '/BEGIN PGP SIGNATURE/{print NR}' "$file_to_check")
		purpose_end=$(( purpose_end - 1 ))
		purpose=$(sed -n "${purpose_start},${purpose_end}p" "$file_to_check")
		purpose_contains_alnum=$(printf "%s" "${purpose}"|grep -c -v '[a-zA-Z0-9+/=]')
		if [ "$purpose_key_contains_alnum" -eq 0 ] && [ "$purpose_contains_alnum" -eq 0 ]
		then
			###EXTRACT ASSET########################################
			trx_asset=$(awk -F: '/:ASST:/{print $3}' "$file_to_check")

			###CHECK IF ASSET TYPE EXISTS###########################
			if [ "$(grep -c "${trx_asset}" "${user_path}"/all_assets.dat)" -eq 1 ]
			then
				###EXTRACT AMOUNT#######################################
				trx_amount=$(awk -F: '/:AMNT:/{print $3}' "$file_to_check")
				if [ "$(printf "%s" "${trx_amount}"|grep -c -v '[0-9.]')" -eq 0 ]
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
