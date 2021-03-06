/* Arcan-fe (OS/device platform), scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the platform/LICENSE file distributed with this source distribution
 * for licensing terms.
 */
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <mach/mach_time.h>

#include <stdint.h>
#include <stdbool.h>
#include <arcan_math.h>
#include <arcan_general.h>

long long int arcan_timemillis()
{
	struct timeval tv;
	uint64_t time = mach_absolute_time();
	static double sf;

	if (!sf){
		mach_timebase_info_data_t info;
		kern_return_t ret = mach_timebase_info(&info);
		if (ret == 0)
			sf = (double)info.numer / (double)info.denom;
		else{
			arcan_warning("arcan_timemillis() couldn't get mach scalefactor.\n");
			sf = 1.0;
		}
	}
	return ( (double)time * sf) / 1000000;
}

void arcan_timesleep(unsigned long val)
{
	struct timespec req, rem;
	req.tv_sec = floor(val / 1000);
	val -= req.tv_sec * 1000;
	req.tv_nsec = val * 1000000;

	while( nanosleep(&req, &rem) == -1 ){
		assert(errno != EINVAL);
		if (errno == EFAULT)
			break;

/* sweeping EINTR introduces an error rate that can grow large,
 * check if the remaining time is less than a threshold */
		if (errno == EINTR) {
			req = rem;
			if (rem.tv_sec * 1000 + (1 + req.tv_nsec) / 1000000 < 4)
				break;
		}
	}
}
