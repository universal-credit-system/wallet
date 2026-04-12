##############################################################################
###
### EXPECTS :	-v trx_ref="trx/${trx_filename} ${trx_hash}"	[REQUIRED]
###		-v check_file="${file_path}"			[OPTIONAL]
###		-v sndr="${trx_sender}"				[OPTIONAL]
###		-v rcvr="${trx_receiver}"			[OPTIONAL]
###
### INPUT :	"${script_path}"/proofs/*/*.txt			[REQUIRED]
###
### OUTPUT :	total number of confirmations
###
##############################################################################

### BEGIN
BEGIN {
	count = 0
	use_check = (check_file != "")

	### READ CHECK FILE ONCE INTO ARRAY
	if (use_check) {
		while ((getline < check_file) > 0)
		allowed[$0] = 1
		close(check_file)
	}
}

### EARLY REJECT
FNR == 1 {
	### PROCESS PREVIOUS FILE
	if (NR > 1 && !skip && found) {
		count++
	}
	
	### SET VARIABLES
	skip = 0
	found = 0
	file = FILENAME

	### REMOVE PATH FROM VARIABLE
	sub(/^.*\//, "", file)

	### REMOVE EXTENSION
	sub(/\..*$/, "", file)

	user = file

	### IF INDEX FROM SENDER / RECEIVER SKIP
	if ((sndr != "" && user ~ sndr) || (rcvr != "" && user ~ rcvr))
		skip = 1

	### IF INDEX-USER NOT IN CHECK-FILE SKIP
	if (use_check && !(user in allowed))
		skip = 1
}

### SKIP FILTER
skip { next }

### FAST MATCH
index($0, trx_ref) {
	found = 1
}

### END PROCESSING
END {
	if (!skip && found) {
		count++
	}
	print count
}
