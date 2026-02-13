#!/usr/bin/awk -f
# READ USERDATES INTO ARRAY
FNR==NR && NR>0 { users[NR]=$1; next }

# AT THE END CALCULATE COINS
END {
	# SET DEFAULT VARIABLES
	current_day=start_day
	daily_payout=365250
	counter=1

	if (DEBUG_MODE) {
			print "=== DEBUG MODE ===" > "/dev/stderr"
			print "user_dates :", length(users) > "/dev/stderr"
	}

    	# READ USER TIMESTAMPS INTO ARRAY
    	for(i=1;i<=length(users);i++) join[users[i]]=1

	# START WITH DAY ONE DAY BY DAY
	while(current_day <= systime()) {
		total_users=0
		
		# COUNT USERS OF THIS DAY
		for(u in join) if(u <= current_day) {
			total_users++
		}

		# CALCULATE TOTAL COINS
		coins_today=total_users * daily_payout
		coins_per_day[current_day]=coins_today

		if (DEBUG_MODE) {
			print "day :", counter > "/dev/stderr"
			print "users :", total_users > "/dev/stderr"
			print "payout :", coins_today > "/dev/stderr"
		}

		# ADJUST COINLOAD
		if(counter>=2) daily_payout=1
		counter++
		current_day+=86400
	}

	# CALCULATE TOTAL NUMBER OF COINS
	total_number_coins=0

	# COINS PER DATE
	for(d in coins_per_day) {
		total_number_coins += coins_per_day[d]
	}

	# PRINT NUMBER OF COINS
	printf "%d\n", total_number_coins
}
