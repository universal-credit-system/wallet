#!/usr/bin/awk -f
BEGIN {
	FS=":"
	signed = 0
	total  = 0
}

# READ :MSIG: ENTRIES OF FILE
/:MSIG:/ {
	signer = $3
	if (!(signer in seen)) {
		seen[signer] = 1
		signers[++total] = signer
	}
}

END {
	if (DEBUG_MODE) {
		print "trx:", TRX_REF > "/dev/stderr"
	}

	# GET CONFIRMATIONS 
	for (i = 1; i <= total; i++) {
		signer = signers[i]
		proof  = PROOF_PATH "/" signer "/" signer ".txt"

		if ((getline < proof) >= 0) {
			while ((getline line < proof) > 0) {
				if (index(line, TRX_REF)) {
					if (DEBUG_MODE) {
						print "signed:", signer > "/dev/stderr"
					}
					signed++
					break
				}
			}
			close(proof)
		}
	}

	# CALCULATE MAJORITY
	majority = int(total / 2) + 1

	# RETURN RESULT
	if (signed >= majority) {
		# IF OKAY
		if (DEBUG_MODE) {
			print "authorized:", signed > "/dev/stderr"
		}
		exit 0
	}
	else {
		# IF NOT OKAY
		if (DEBUG_MODE) {
			print "not authorized:", signed > "/dev/stderr"
		}
		exit 1
	}
}

