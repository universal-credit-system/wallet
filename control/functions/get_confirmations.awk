#!/usr/bin/awk -f
##############################################################################
### EXPECTS :	-v trx_ref="trx/${trx_filename} ${trx_hash}"	[REQUIRED]
###		-v check_file="${file_path}"			[OPTIONAL]
###		-v sndr="${trx_sender}"				[OPTIONAL]
###		-v rcvr="${trx_receiver}"			[OPTIONAL]
###
### INPUT :	"${script_path}"/proofs/*/*.txt			[REQUIRED]
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

### CHECK IF INDEX-FILE CONTAINS CONFIRMATION
index($0, trx_ref) {
	found = 1
}

### EARLY REJECT
FNR == 1 {

	file = FILENAME

	### REMOVE PATH FROM VARIABLE
	sub(/^.*\//, "", file)

	#### REMOVE EXTENSION
	sub(/\..*$/, "", file)

	user = file

	### IF INDEX FROM SENDER / RECEIVER SKIP
	if ((sndr != "" && user ~ sndr) || (rcvr != "" && user ~ rcvr))
		nextfile

	### IF INDEX-USER NOT IN CHECK-FILE SKIP
	if (use_check && !(user in allowed))
		nextfile
}

### FAST MATCH
index($0, trx_ref) {
	found = 1
}

### FILE END
ENDFILE {
	if (found) {
		### COUNT CONFIRMATION
		count++
	}
	found = 0
}

END {
	print count
}
