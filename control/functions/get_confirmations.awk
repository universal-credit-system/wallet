#!/usr/bin/awk -f
# EXPECTS :	-v trx_ref="trx/${trx_filename} ${trx_hash}"	[REQUIRED]
#		-v check_file="${file_path}"			[OPTIONAL]
#		-v sndr="${trx_sender}"				[OPTIONAL]
#		-v rcvr="${trx_receiver}"			[OPTIONAL]

BEGIN {
	use_check = (check_file != "")
	count = 0
}

index($0, trx_ref) {
	found = 1
}

ENDFILE {
	if (found) {
		if (use_check) {
			user_ok = 0
			while ((getline line < check_file) > 0) {
				if (line == FILENAME && FILENAME !~ sndr && FILENAME !~ rcvr) {
					user_ok = 1
					break
				}
			}
			close(check_file)

			if (user_ok) {
				count++
			}
		} else {
			if (length(sndr) > 0 && length(rcvr) > 0) { 
				if (found && FILENAME !~ sndr && FILENAME !~ rcvr) {
					count++
				}
			} else {
				count++
			}
		}
        }
        found = 0
}

END {
	print count
}
