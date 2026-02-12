#!/usr/bin/awk -f
BEGIN {
	all_acc_file = USER_PATH "/all_accounts.dat"
	all_ast_file = USER_PATH "/all_assets.dat"
	all_trx_file = USER_PATH "/all_trx.dat"
	dep_acc_file = USER_PATH "/depend_accounts.dat"
	dep_trx_file = USER_PATH "/depend_trx.dat"
	trx_dir      = SCRIPT_PATH "/trx"
	
	# READ ALL_ACCOUNTS.DAT
	while ((getline < all_acc_file) > 0) {
		all_accounts[$1] = 1
		acc_count++
	}
	close(all_acc_file)

	# READ ALL_ASSETS.DAT
	while ((getline < all_ast_file) > 0) {
		all_assets[$1] = 1
		ast_count++
	}
	close(all_ast_file)

	# READ ALL_TRX.DAT
	while ((getline < all_trx_file) > 0)
		trx_list[++trx_count] = $0
	close(all_trx_file)

	if (DEBUG_MODE) {
		print "=== DEBUG MODE ===" > "/dev/stderr"
		print "all_accounts.dat :", acc_count > "/dev/stderr"
		print "all_assets.dat :", ast_count > "/dev/stderr"
		print "all_trx.dat :", trx_count > "/dev/stderr"
		print "==================" > "/dev/stderr"
	}

	# PARSE TRX AND CREATE INDEX
	for (i = 1; i <= trx_count; i++) {
		trx = trx_list[i]
		file = trx_dir "/" trx

		while ((getline line < file) > 0) {
			split(line, f, ":")

			if (f[2] == "SNDR") {
				trx_sender[trx] = f[3]
				trx_by_account[f[3] SUBSEP trx] = 1
			}
			else if (f[2] == "RCVR") {
				trx_receiver[trx] = f[3]
				trx_by_account[f[3] SUBSEP trx] = 1
			}
			else if (f[2] == "MSIG") {
				trx_msig[trx SUBSEP f[3]] = 1
				trx_by_account[f[3] SUBSEP trx] = 1
			}
		}
		close(file)
	}

	# MSIG REVERSE INDEX
	n = split(MSIG_FILES, msig_list, "\n")
	for (i = 1; i <= n; i++) {
		file = msig_list[i]
		if (file == "") continue

		split(file, p, "/")
		wallet = p[length(p)-1]

		while ((getline line < file) > 0) {
			gsub(/[ \t\r\n]/, "", line)
			if (line != "")
				msig_dependents[line SUBSEP wallet] = 1
		}
		close(file)
	}

	# INITIAL QUEUE
	while ((getline < dep_acc_file) > 0) {
		if (!seen[$1]) {
			seen[$1] = 1
			initial[$1] = 1
			queue[++qlen] = $1
			seen_count++
		}
	}
	close(dep_acc_file)

	# BFS
	head = 1
	while (head <= qlen) {
		user = queue[head++]

		# TRX VIA INDEX
		for (key in trx_by_account) {
			split(key, k, SUBSEP)
			if (k[1] != user) continue
			trx = k[2]

			if (depend_trx[trx]) continue
			depend_trx[trx] = 1
			trx_hit_count++

			receiver = trx_receiver[trx]
			if (!receiver) continue
			if (receiver in all_assets) continue
			if (!(receiver in all_accounts)) continue
			if (seen[receiver]) continue

			seen[receiver] = 1
			queue[++qlen] = receiver
			seen_count++
		}

		# MSIG REVERSE
		for (key in msig_dependents) {
			split(key, k, SUBSEP)
			if (k[1] != user) continue

			wallet = k[2]
			if (seen[wallet]) continue
			if (!(wallet in all_accounts)) continue

			seen[wallet] = 1
			queue[++qlen] = wallet
			seen_count++
		}
	}

	# WRITE ACCOUNTS TO DEPEND_ACCOUNT.DAT
	for (acc in seen) {
		if (DEBUG_MODE) {
			print "ACC", acc > "/dev/stderr"
		}
		print acc > dep_acc_file
	}

	# WRITE TRX TO DEPEND_TRX.DAT
	for (trx in depend_trx) {
		if (DEBUG_MODE) {
			print "TRX", trx > "/dev/stderr"
		}
		print trx > dep_trx_file
	}
}
