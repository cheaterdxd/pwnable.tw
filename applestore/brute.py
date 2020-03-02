for i in range(15): #499
	for j in range(18): #399
		for k in range(24):#299
			for m in range(37): #199
				if((m*199+k*299+j*399+i*499)==7174):
					print( '499: '+str(i) + ' 399:' + str(j) + ' 299:' +str(k) + ' 199:' +str(m) + ' ')
				if((m*199+k*299+j*399+i*499)>7174):
					break

