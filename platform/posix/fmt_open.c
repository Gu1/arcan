/* Arcan-fe (OS/device platform), scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the platform/LICENSE file distributed with this source distribution
 * for licensing terms.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int fmt_open(int flags, mode_t mode, const char* fmt, ...)
{
	int rv = -1;

	unsigned cc;
	va_list args;
	va_start( args, fmt );
		cc = vsnprintf(NULL, 0,  fmt, args );
	va_end( args);

	char* dbuf;
	if (cc > 0 && (dbuf = (char*) malloc(cc + 1)) ) {
		va_start(args, fmt);
			vsprintf(dbuf, fmt, args);
		va_end(args);

		rv = open(dbuf, flags, mode);
		free(dbuf);
	}

#ifndef _WIN32
/* don't let spawned children have access to this one */
	if (-1 != rv)
		fcntl(rv, FD_CLOEXEC);
#endif

	return rv;
}
