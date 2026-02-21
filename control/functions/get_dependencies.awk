##############################################################################
###
### EXPECTS :	-v DEBUG_MODE="${debug}"		[OPTIONAL]
###		-v BASE="${script_path}"		[REQUIRED]
###		-v UPATH="${user_path}"			[REQUIRED]
###		-v START="${handover_account}"		[REQUIRED]
###
### INPUT :	"${script_path}"/proofs/*/multi.sig	[REQUIRED]
###		"${script_path}"/trx/*			[REQUIRED]
###		"${user_path}/all_assets.dat"		[REQUIRED]
###		"${user_path}/all_accounts.dat"		[REQUIRED]
###		"${user_path}/all_trx.dat"		[REQUIRED]
###
### OUTPUT :	"${user_path}/depend_accounts.dat
###		"${user_path}/depend_trx.dat
###
##############################################################################

##############################################################################
### HELP FUNCTIONS
##############################################################################

### EXTRACT USER FROM TRX FILENAME (ANYTHING BEFORE A DOT IN FILENAME)
function trx_owner_name(file, tmp) {
	tmp = file
	sub(/^.*\//, "", tmp)   # REMOVE ANYTHING IN FRONT OF /
	sub(/\..*$/, "", tmp)   # REMOVE ANYTHING AFTER FIRST DOT
	return tmp
}

### EXTRACT USER FROM proofs/*/multi.sig PATH
function proof_owner(file, tmp) {
	tmp = file
	sub(/\/multi\.sig$/, "", tmp)
	sub(/^.*\//, "", tmp)
	return tmp
}

### WRITE ACCOUNT TO DEPEND_ACCOUNTS.DAT
function add_account(u) {
	if (!(u in seen) && (u in account)) {
		seen[u] = 1
		queue[++q_end] = u
		print u >> UPATH "/depend_accounts.dat"
		if (DEBUG_MODE) {
			print "USER:", u  > "/dev/stderr"
		}
	}
}

### WRITE TRX TO DEPEND_TRX.DAT
function add_trx(t) {
	if (!(t in seen_trx)) {
		seen_trx[t] = 1
		print t >> UPATH "/depend_trx.dat"
		if (DEBUG_MODE) {
			print "TRX:", t  > "/dev/stderr"
		}
	}
}

##############################################################################
### BEGIN
##############################################################################
BEGIN {
	for (u in account) {
		if (!(u in msig)) delete msig[u]
		if (!(u in trx_owner)) delete trx_owner[u]
	}
}

##############################################################################
### PASS 1: READ
##############################################################################

### READ proofs/*/multi.sig
FILENAME ~ /\/proofs\/.*\/multi\.sig$/ {
	if (FNR == 1) {
		current_owner = proof_owner(FILENAME)
	}
	if ($0 ~ /^:MSIG:/) {
		msig[current_owner][$3] = 1
	}
	next
}

### READ ALL TRANSACTIONS IN trx/*
FILENAME ~ /\/trx\/[^/]+$/ {
	if (FNR == 1) {
		trx = FILENAME
		
		### TRIM TIMESTAMP AWAY SO ONLY OWNER REMAINS
		sub(/^.*\//, "", trx)
		owner = trx_owner_name(FILENAME)
		
		trx_owner[owner][trx] = 1
		trx_sndr[trx] = owner
	}

	### GET RECEIVER OF TRX
	if ($0 ~ /^:RCVR:/) {
		trx_receiver[trx] = $3
	}
	
	### GET MSIG USERS OF TRX
	if ($0 ~ /^:MSIG:/) {
		trx_msig[trx][$3] = 1
	}
	next
}

### READ all_assets.dat
FILENAME ~ /all_assets\.dat$/ {
	asset[$0] = 1
	next
}

### READ all_accounts.dat ----
FILENAME ~ /all_accounts\.dat$/ {
	account[$0] = 1
	next
}

##############################################################################
### PASS 2: BFS & DOT
##############################################################################

END {
	if (DEBUG_MODE) {
		### DOT
		dotfile = UPATH "/dependencies.dot"
		print "digraph dependencies {" > dotfile
		print "    rankdir=LR;" >> dotfile
		print "    node [shape=ellipse];" >> dotfile
		
		### ADD DOT LEGEND
		print "    subgraph cluster_legend {" >> dotfile
		print "        label=\"Legend\";" >> dotfile
		print "        fontsize=12;" >> dotfile
		print "        color=gray;" >> dotfile
		print "        style=dashed;" >> dotfile
		print "        legend_proofs [label=\"wallet multi-sig\", shape=ellipse, color=blue];" >> dotfile
		print "        legend_trx    [label=\"trx multi-sig\", shape=ellipse, color=green];" >> dotfile
		print "        legend_recv   [label=\"trx receiver/sender\", shape=ellipse, color=red];" >> dotfile
		print "        legend_proofs -> legend_trx  [style=invis];" >> dotfile
		print "        legend_trx    -> legend_recv [style=invis];" >> dotfile
		print "    }" >> dotfile
	}
	
	add_account(START)

	while (q_start < q_end) {
		user = queue[++q_start]

		### OWN TRANSACTIONS
		for (trx in trx_owner[user]) {
			add_trx(trx)

			### RECEIVER
			receiver = trx_receiver[trx]
			if (receiver && !(receiver in asset) && (receiver in account)) {
				add_account(receiver)
				if (DEBUG_MODE) {
					print "    \"" user "\" -> \"" receiver "\" [color=red];" >> dotfile ### DOT
				}
			}

			### MSIG USERS OF TRANSACTION
			for (signer in trx_msig[trx]) {
				add_account(signer)
				if (DEBUG_MODE) {
					print "    \"" user "\" -> \"" signer "\" [color=green];" >> dotfile ### DOT
				}
			}
		}

		### TRANSACTIONS USER IS A RECEIVER OF
		for (trx in trx_receiver) {
			if (trx_receiver[trx] == user) {
				sndr = trx_sndr[trx]
				add_trx(trx)
				if (sndr && !(sndr in asset) && (sndr in account)) {
					add_account(sndr)
					if (DEBUG_MODE) {
						print "    \"" user "\" -> \"" sndr "\" [color=red];" >> dotfile ### DOT
					}
				}
			}
		}

		### MSIG USERS OF proofs/multi.sig
		for (signer in msig[user]) {
			add_account(signer)
			if (DEBUG_MODE) {
				print "    \"" user "\" -> \"" signer "\" [color=blue];" >> dotfile ### DOT
			}
		}
	}

	if (DEBUG_MODE) {
		print "}" >> dotfile
	}
}
