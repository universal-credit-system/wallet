##############################################################################
###
### EXPECTS :	-v DEBUG_MODE="${debug}"		[OPTIONAL]
###		-v today_start="${today_start}"		[REQUIRED]
###		-v UPATH="${user_path}"			[REQUIRED]
###		-v START="${handover_account}"		[REQUIRED]
###
### INPUT :	"${script_path}"/trx/*
###
### OUTPUT :	-total_number_trx
###		-total_number_trx_today
###		-total_volume_trx
###		-total_volume_trx_today
###
##############################################################################
BEGIN {
	total_number_trx=0
	total_number_trx_today=0
	total_volume_trx=0
	total_volume_trx_today=0
	trx_ts=0
}

### EXTRACT TIMESTAMP
/^:TIME:/ { trx_ts = substr($0,7) }

### GET TRX OF TODAY
$0 == ":ASST:"asset {
	total_number_trx++
	if (trx_ts >= today_start && trx_ts < tomorrow_start) {
		total_number_trx_today++
	}
}

### GET AMOUNTS OF TODAY AND TOTAL
/^:AMNT:/ {
	amount = substr($0,7)
	total_volume_trx += amount
	if (trx_ts >= today_start && trx_ts < tomorrow_start) {
		total_volume_trx_today += amount
	}
}

END {
	### PRINT OUT VARIABLES
	printf "%d|%d|%.9f|%.9f\n", total_number_trx, total_number_trx_today, total_volume_trx, total_volume_trx_today
}
