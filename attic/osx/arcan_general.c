/* Arcan-fe, scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the COPYRIGHT file distributed with this source distribution.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include "arcan_math.h"
#include "arcan_general.h"

/* 
 * some mapping mechanisms other than arcan_map_resource
 * should be used for dealing with single resources larger
 * than this size.
 */ 
#ifndef MAX_RESMAP_SIZE
#define MAX_RESMAP_SIZE (1024 * 1024 * 10)
#endif

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

char* arcan_themepath      = NULL;
char* arcan_resourcepath   = NULL;
char* arcan_themename      = "welcome";
char* arcan_binpath        = NULL;
char* arcan_libpath        = NULL;

/* this should be moved to thread-local storage,
 * or, preferrably, be worked around entirely */
static const int   playbufsize = (64 * 1024) - 2;
static char playbuf[64 * 1024] = {0};

/* malloc() wrapper for now, entry point here
 * to easier switch to pooled storage */
static char* tag_resleak = "resource_leak";
static data_source* alloc_datasource()
{
	data_source* res = malloc(sizeof(data_source));
	res->fd     = -1;
	res->start  =  0;
	res->len    =  0;

/* trace for this value to track down leaks */
	res->source = tag_resleak; 
	
	return res;	
}

void arcan_release_resource(data_source* sptr)
{
/* relying on a working close() is bad form,
 * unfortunately recovery options are few */
	if (-1 != sptr->fd){
		int trycount = 10;
		while (trycount--){
			if (close(sptr->fd) == 0)
				break;
		}

/* don't want this one free:d */
	if ( sptr->source == tag_resleak )
		sptr->source = NULL;

/* something broken with the file-descriptor, 
 * not many recovery options but purposefully leak
 * the memory so that it can be found in core dumps etc. */
		if (trycount){
			free( sptr->source );
			snprintf(playbuf, playbufsize, "broken_fd(%d:%s)", 
				sptr->fd, sptr->source);
			sptr->source = strdup(playbuf);
		} else {
/* make the released memory distinguishable from a broken 
 * descriptor from a memory analysis perspective */
			free( sptr->source );
			sptr->fd     = -1;
			sptr->start  = -1;
			sptr->len    = -1;
		}
	}

	if (sptr->source){
		free(sptr->source);
		sptr->source = NULL;
	}
}

static bool is_dir(const char* fn)
{
	struct stat buf;
	bool rv = false;

	if (fn == NULL)
		return false;

	if (stat(fn, &buf) == 0) {
		rv = S_ISDIR(buf.st_mode);
	}

	return rv;
}

static bool file_exists(const char* fn)
{
	struct stat buf;
	bool rv = false;

	if (fn == NULL)
		return false;

	if (stat(fn, &buf) == 0) {
		rv = S_ISREG(buf.st_mode);
	}

	return rv;
}

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

	return rv;
}

/* currently " allowed ",
 * likely to block traversal outside resource / theme
 * in the future though */
char* strip_traverse(char* input)
{
	return input;
}

char* arcan_find_resource(const char* label, int searchmask)
{
	if (label == NULL)
		return NULL;

	playbuf[playbufsize-1] = 0;

	if (searchmask & ARCAN_RESOURCE_THEME) {
		snprintf(playbuf, playbufsize-2, "%s/%s/%s", arcan_themepath, 
			arcan_themename, label);
		strip_traverse(playbuf);

		if (file_exists(playbuf))
			return strdup(playbuf);
	}

	if (searchmask & ARCAN_RESOURCE_SHARED) {
		snprintf(playbuf, playbufsize-2, "%s/%s", arcan_resourcepath, label);
		strip_traverse(playbuf);

		if (file_exists(playbuf))
			return strdup(playbuf);
	}

	return NULL;
}

/* 
 * Somewhat rugged at the moment,
 * Mostly designed the way it is to account for the "zip is a container"
 * approach used in android and elsewhere, or (with some additional work)
 * actual URI references
 */
data_source arcan_open_resource(const char* url)
{
	data_source res = {.fd = BADFD};

	if (url){
		res.fd = open(url, O_RDONLY);
		if (res.fd != -1){
			res.start  = 0;
			res.source = strdup(url);
			res.len    = 0; /* map resource can figure it out */ 
		}
	}
	else 
		res.fd = BADFD;

	return res;
}

static bool check_paths()
{
	/* binpath, libpath, resourcepath, themepath */
	if (!arcan_binpath){
		arcan_fatal("Fatal: check_paths(), frameserver not found.\n");
		return false;
	}

	if (!arcan_libpath){
		arcan_warning("Warning: check_paths(), libpath not found (internal support downgraded to partial).\n");
	}

	if (!arcan_resourcepath){
		arcan_fatal("Fatal: check_paths(), resourcepath not found.\n");
		return false;
	}

	if (!arcan_themepath){
		arcan_fatal("Fatal: check_paths(), themepath not found.\n");
	}

	return true;
}

bool check_theme(const char* theme)
{
	if (theme == NULL)
		return false;

	snprintf(playbuf, playbufsize-1, "%s/%s", arcan_themepath, theme);

	if (!is_dir(playbuf)) {
		arcan_warning("Warning: theme check failed, directory %s not found.\n", playbuf);
		return false;
	}

	snprintf(playbuf, playbufsize-1, "%s/%s/%s.lua", arcan_themepath, theme, theme);
	if (!file_exists(playbuf)) {
		arcan_warning("Warning: theme check failed, script %s not found.\n", playbuf);
		return false;
	}

	return true;
}

char* arcan_expand_resource(const char* label, bool global)
{
	playbuf[playbufsize-1] = 0;

	if (global) {
		snprintf(playbuf, playbufsize-2, "%s/%s", arcan_resourcepath, label);
	}
	else {
		snprintf(playbuf, playbufsize-2, "%s/%s/%s", arcan_themepath, arcan_themename, label);
	}

	return strdup( strip_traverse(playbuf) );
}

char* arcan_find_resource_path(const char* label, const char* path, int searchmask)
{
	if (label == NULL)
		return NULL;

	playbuf[playbufsize-1] = 0;

	if (searchmask & ARCAN_RESOURCE_THEME) {
		snprintf(playbuf, playbufsize-2, "%s/%s/%s/%s", arcan_themepath, arcan_themename, path, label);
		strip_traverse(playbuf);

		if (file_exists(playbuf))
			return strdup(playbuf);
	}

	if (searchmask & ARCAN_RESOURCE_SHARED) {
		snprintf(playbuf, playbufsize-2, "%s/%s/%s", arcan_resourcepath, path, label);
		strip_traverse(playbuf);

		if (file_exists(playbuf))
			return strdup(playbuf);

	}

	return NULL;
}

#ifdef __UNIX

void arcan_warning(const char* msg, ...)
{
	va_list args;
	va_start( args, msg );
		vfprintf(stderr,  msg, args );
	va_end( args);
}

void arcan_fatal(const char* msg, ...)
{
	va_list args;
	va_start( args, msg );
		vfprintf(stderr,  msg, args );
	va_end( args);

#ifdef _DEBUG
	abort();
#else
	exit(1);
#endif
}

static char* unix_find(const char* fname){
	char* res = NULL;
	char* pathtbl[] = {
		".",
		NULL,
		"/usr/local/share/arcan",
		"/usr/share/arcan",
		NULL
	};

	if (getenv("HOME")){
		size_t len = strlen( getenv("HOME") ) + 9;
		pathtbl[1] = malloc(len);
		snprintf(pathtbl[1], len, "%s/.arcan", getenv("HOME") );
	}
	else
		pathtbl[1] = strdup("");

	for (char** base = pathtbl; *base != NULL; base++){
		snprintf(playbuf, playbufsize, "%s/%s", *base, fname );

		if (is_dir(playbuf)){
			res = strdup(playbuf);
			break;
		}
	}

cleanup:
	free(pathtbl[1]);
	return res;
}

static void setpaths_unix()
{
	if (arcan_binpath == NULL){
		if (file_exists( getenv("ARCAN_FRAMESERVER") ) )
			arcan_binpath = strdup( getenv("ARCAN_FRAMESERVER") );
		else if (file_exists( "./arcan_frameserver") )
			arcan_binpath = strdup("./arcan_frameserver" );
		else if (file_exists( "/usr/local/bin/arcan_frameserver"))
			arcan_binpath = strdup("/usr/local/bin/arcan_frameserver");
		else if (file_exists( "/usr/bin/arcan_frameserver" ))
			arcan_binpath = strdup("/usr/bin/arcan_frameserver");
		else ;
	}

	/* thereafter, the hijack-  lib */
	if (arcan_libpath == NULL){
		if (file_exists( getenv("ARCAN_HIJACK") ) )
			arcan_libpath = strdup( getenv("ARCAN_HIJACK") );
		else if (file_exists( "./" LIBNAME ) )
			arcan_libpath = realpath( "./", NULL );
		else if (file_exists( "/usr/local/lib/" LIBNAME) )
			arcan_libpath = strdup( "/usr/local/lib/");
		else if (file_exists( "/usr/lib/" LIBNAME) )
			arcan_libpath = strdup( "/usr/lib/");
	}

	if (arcan_resourcepath == NULL){
		if ( file_exists(getenv("ARCAN_RESOURCEPATH")) )
			arcan_resourcepath = strdup( getenv("ARCAN_RESOURCEPATH") );
		else
			arcan_resourcepath = unix_find("resources");
	}

	if (arcan_themepath == NULL){
		if ( file_exists(getenv("ARCAN_THEMEPATH")) )
			arcan_themepath = strdup( getenv("ARCAN_THEMEPATH") );
		else
			arcan_themepath = unix_find("themes");
	}
}

#include <glob.h>
unsigned arcan_glob(char* basename, int searchmask, void (*cb)(char*, void*), void* tag){
	unsigned count = 0;
	char* basepath;

	if ((searchmask & ARCAN_RESOURCE_THEME) > 0){
		snprintf(playbuf, playbufsize, "%s/%s/%s", arcan_themepath, arcan_themename, strip_traverse(basename));
		glob_t res = {0};
		if ( glob(playbuf, 0, NULL, &res) == 0 ){
			char** beg = res.gl_pathv;
			while(*beg){
				cb(strrchr(*beg, '/') ? strrchr(*beg, '/')+1 : *beg, tag);
				beg++;
				count++;
			}
		}
		globfree(&res);
	}

	if ((searchmask & ARCAN_RESOURCE_SHARED) > 0){
		snprintf(playbuf, playbufsize, "%s/%s", arcan_resourcepath, strip_traverse(basename));
		glob_t res = {0};

		if ( glob(playbuf, 0, NULL, &res) == 0 ){
			char** beg = res.gl_pathv;
			while(*beg){
				cb(strrchr(*beg, '/') ? strrchr(*beg, '/')+1 : *beg, tag);
				beg++;
				count++;
			}
		}
		globfree(&res);
	}

	return count;
}

#ifdef __APPLE__

const char* internal_launch_support(){
	return arcan_libpath ? "FULL SUPPORT" : "PARTIAL SUPPORT";
}

bool arcan_setpaths()
{
	char* prefix = "";

/* apparently, some launching conditions means that you cannot rely on CWD,
 * so try and figure it out, from a bundle. This is more than a little hackish. */
	char path[1024] = {0};
    CFBundleRef bundle  = CFBundleGetMainBundle();

/*  command-line launch that cannot be "mapped" to a bundle, so treat as UNIX */
	if (!bundle){
		setpaths_unix();
		return check_paths();
	}

	CFURLRef bundle_url  = CFBundleCopyBundleURL(bundle);
	CFStringRef string_ref = CFURLCopyFileSystemPath( bundle_url, kCFURLPOSIXPathStyle);
	CFStringGetCString(string_ref, path, sizeof(path) - 1, kCFStringEncodingASCII);
	CFRelease(bundle_url);
	CFRelease(string_ref);

	char* bundlepath = strdup(path);
	snprintf(path, sizeof(path) - 1, "%s/Contents/MacOS/arcan_frameserver", bundlepath);
	if (file_exists(path))
		arcan_binpath = strdup(path);

	snprintf(path, sizeof(path) - 1, "%s/Contents/MacOS/libarcan_hijack.dylib", bundlepath);
	if (file_exists(path))
		arcan_libpath = strdup(path);

	snprintf(path, sizeof(path) - 1, "%s/Contents/Resources", bundlepath);
	free(bundlepath);

/*  priority on the "UNIX-y" approach to setting paths" for themes and resources */
	setpaths_unix();

/* and if that doesn't work, use the one from the bundle */
	if (!arcan_themepath){
		snprintf(path, sizeof(path) - 1, "%s/Contents/Resources/themes", bundlepath);
		arcan_themepath = strdup(path);
	}

	if (!arcan_resourcepath){
		snprintf(path, sizeof(path) - 1, "%s/Contents/Resources/resources", bundlepath);
		arcan_resourcepath = strdup(path);
	}

	return check_paths();
}

#else

bool arcan_setpaths()
{
	setpaths_unix();
	return check_paths();
}

const char* internal_launch_support(){
	return arcan_libpath ? "FULL SUPPORT" : "PARTIAL SUPPORT";
}

#endif

/*
 * simple "buffer (ntr) and only (ntr) bytes blocking from fd" wrap around read.
 * expects (dofs) to point to a preallocated buffer, sufficient to hold (ntr) bytes. 
 */
static inline bool read_safe(int fd, size_t ntr, int bs, char* dofs)
{
	char* dbuf = dofs;

	while (ntr > 0){
		int nr = read(fd, dbuf, bs > ntr ? ntr : bs);

		if (nr > 0)
			ntr -= nr;
		else 
			if (errno == EINTR);
		else 
			break;

		if (dofs)
			dbuf += nr;
	}

	return ntr == 0;
}

#include <sys/mman.h>
/*
 * flow cases:
 *  (1) too large region to map
 *  (2) mapping at an unaligned offset
 *  (3) mapping a pipe at offset
 */
map_region arcan_map_resource(data_source* source, bool allowwrite)
{
	map_region rv = {0};
	struct stat sbuf;

/* 
 * if additional properties (size, ...) has not yet been resolved,
 * try and figure things out manually 
 */
	if (0 == source->len && -1 != fstat(source->fd, &sbuf)){
		source->len = sbuf.st_size;
		source->start = 0;
	}

/* bad resource */
	if (!source->len)
		return rv;

/* 
 * for unaligned reads (or in-place modifiable memory) 
 * we manually read the file into a buffer 
 */
	if (source->start % sysconf(_SC_PAGE_SIZE) != 0 || allowwrite)
		goto memread;

/* 
 * The use-cases for most resources mapped in this manner relies on
 * mapping reasonably small buffer lengths for decoding. Reasonably
 * is here defined by MAX_RESMAP_SIZE 
 */
	if (0 < source->len && MAX_RESMAP_SIZE > source->len){
		rv.sz  = source->len;
		rv.ptr = mmap(NULL, rv.sz, PROT_READ,
			MAP_FILE | MAP_PRIVATE, source->fd, source->start);

		if (rv.ptr == MAP_FAILED){
			char errbuf[64];
			strerror_r(errno, errbuf, 64);
			arcan_warning("arcan_map_resource() failed, reason(%d): %s\n\t"
				"(length)%d, (fd)%d, (offset)%d\n", errno, errbuf, 
				rv.sz, source->fd, source->start);

			rv.ptr = NULL;
			rv.sz  = 0;
		} 
		else 
			rv.mmap = true;
	}
	return rv;

memread:
	rv.ptr  = malloc(source->len);
	rv.sz   = source->len;
	rv.mmap = false;
/*
 * there are several devices where we can assume that seeking is not possible,
 * then we automatically convert seeking to "skipping"
 */
		bool rstatus = true;
		if (source->start > 0 && -1 == lseek(source->fd, SEEK_SET, source->start)){
			rstatus = read_safe(source->fd, source->start, 8192, NULL);
		}
		
		if (rstatus){
			rstatus = read_safe(source->fd, source->len, 8192, rv.ptr);	
		}

		if (!rstatus){
			free(rv.ptr);
			rv.ptr = NULL;
			rv.sz  = 0;
		}

	return rv;
}

bool arcan_release_map(map_region region)
{
	int rv = -1;

	if (region.sz > 0 && region.ptr)
		rv = region.mmap ? munmap(region.ptr, region.sz) : (free(region.ptr), 0);

	return rv != -1;
}

#endif /* unix */

#if _WIN32

/* sigh, we don't know where we come from so we have to have a separate buffer here */
extern bool stdout_redirected;
static char winplaybuf[64 * 1024] = {0};
static bool winnolog = false;

void arcan_warning(const char* msg, ...)
{
	if (winnolog)
		return;

/* redirection needed for win (SDL etc. also tries to, but we need to handle things)
 * differently, especially for Win/UAC and permissions, thus we can assume resource/theme
 * folder is r/w but nothing else .. */
	if (!stdout_redirected && arcan_resourcepath != NULL){
		sprintf(winplaybuf, "%s/logs/arcan_warning.txt", arcan_resourcepath);
	/* even if this fail, we will not try again */
		winnolog = freopen(winplaybuf, "a", stdout) == NULL;
		stdout_redirected = true;
	}

	va_list args;
	va_start( args, msg );
	vfprintf(stdout,  msg, args );
	va_end(args);
	fflush(stdout);
}

#include "win32/realpath.c"

extern bool stderr_redirected;
void arcan_fatal(const char* msg, ...)
{
	char buf[256] = {0};
	if (!stderr_redirected && arcan_resourcepath != NULL){
		sprintf(winplaybuf, "%s/logs/arcan_fatal.txt", arcan_resourcepath);
		winnolog = freopen(winplaybuf, "a", stderr) == NULL;
		stderr_redirected = true;
	}

	va_list args;
	va_start(args, msg );
	vsnprintf(buf, 255, msg, args);
	va_end(args);

	fprintf(stderr, "%s\n", buf);
	fflush(stderr);
	MessageBox(NULL, buf, NULL, MB_OK | MB_ICONERROR | MB_APPLMODAL );
	exit(1);
}

double round(double x)
{
	return floor(x + 0.5);
}

bool arcan_setpaths()
{
/* could add a check of the users path cleanup (that turned out to be a worse mess than before)
 * with AppData etc. from Vista and friends */

	if (!arcan_resourcepath)
		arcan_resourcepath = strdup("./resources");

	arcan_libpath = NULL;

	if (!arcan_themepath)
		arcan_themepath = strdup("./themes");

	if (!arcan_binpath)
		arcan_binpath = strdup("./arcan_frameserver");

	return true;
}

int arcan_sem_post(sem_handle sem)
{
	return ReleaseSemaphore(sem, 1, 0);
}

int arcan_sem_unlink(sem_handle sem, char* key)
{
	return CloseHandle(sem);
}

int arcan_sem_timedwait(sem_handle sem, int msecs)
{
	if (msecs == -1)
		msecs = INFINITE;

	DWORD rc = WaitForSingleObject(sem, msecs);
	int rv = 0;

	switch (rc){
		case WAIT_ABANDONED:
			rv = -1;
			errno = EINVAL;
		break;

		case WAIT_TIMEOUT:
			rv = -1;
			errno = EAGAIN;
		break;

		case WAIT_FAILED:
			rv = -1;
			errno = EINVAL;
		break;

		case WAIT_OBJECT_0:
		break; /* default returnpath */

	default:
		arcan_warning("Warning: arcan_sem_timedwait(win32) -- unknown result on WaitForSingleObject (%i)\n", rc);
	}

	return rv;
}

unsigned arcan_glob(char* basename, int searchmask, void (*cb)(char*, void*), void* tag){
	HANDLE findh;
	WIN32_FIND_DATA finddata;

	unsigned count = 0;
	char* basepath;

	if ((searchmask & ARCAN_RESOURCE_THEME) > 0){
		snprintf(playbuf, playbufsize, "%s/%s/%s", arcan_themepath, arcan_themename, strip_traverse(basename));

		findh = FindFirstFile(playbuf, &finddata);
		if (findh != INVALID_HANDLE_VALUE)
			do{
				snprintf(playbuf, playbufsize, "%s", finddata.cFileName);
				if (strcmp(playbuf, ".") == 0 || strcmp(playbuf, "..") == 0)
					continue;

				cb(playbuf, tag);
				count++;
			} while (FindNextFile(findh, &finddata));

		FindClose(findh);
	}

	if ((searchmask & ARCAN_RESOURCE_SHARED) > 0){
		snprintf(playbuf, playbufsize, "%s/%s", arcan_resourcepath, strip_traverse(basename));

		findh = FindFirstFile(playbuf, &finddata);
		if (findh != INVALID_HANDLE_VALUE)
		do{
			snprintf(playbuf, playbufsize, "%s", finddata.cFileName);
			if (strcmp(playbuf, ".") == 0 || strcmp(playbuf, "..") == 0)
					continue;

			cb(playbuf, tag);
			count++;
		} while (FindNextFile(findh, &finddata));

		FindClose(findh);
	}

	return count;
}

const char* internal_launch_support(){
	return "PARTIAL SUPPORT";
}

/* ... cough ... */
char* arcan_findshmkey(int* dfd, bool semalloc)
{
	return NULL;
	/* unused for win32, we inherit */
}

long long int arcan_timemillis()
{
	static LARGE_INTEGER ticks_pers;
	static LARGE_INTEGER start_ticks;
	static bool seeded = false;

	if (!seeded){
/* seed monotonic timing */
		QueryPerformanceFrequency(&ticks_pers);
		QueryPerformanceCounter(&start_ticks);
        seeded = true;
	}

	LARGE_INTEGER ticksnow;
	QueryPerformanceCounter(&ticksnow);

	ticksnow.QuadPart -= start_ticks.QuadPart;
	ticksnow.QuadPart *= 1000;
	ticksnow.QuadPart /= ticks_pers.QuadPart;

	return ticksnow.QuadPart;
}

void arcan_timesleep(unsigned long val)
{
	static bool sleepSeed = false;
	static bool spinLock = false;

/* try to force sleep timer resolution to 1 ms, should possible
 * be reset upon exit, doubt windows still enforces that though */
	if (sleepSeed == false){
		spinLock = !(timeBeginPeriod(1) == TIMERR_NOERROR);
		sleepSeed = true;
	}

	unsigned long int start = arcan_timemillis();

	while (val > (arcan_timemillis() - start)){
        Sleep( spinLock ? 0 : val );
	}
}

#else
#include <assert.h>

long long int arcan_timemillis()
{
	struct timespec tp;
#if _POSIX_TIMERS > 0
	clock_gettime(CLOCK_MONOTONIC, &tp);
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	tp.tv_sec = tp.tv_sec;
	tp.tv_nsec = tv.tv_usec * 1000;
#endif

	return (tp.tv_sec * 1000) + (tp.tv_nsec / 1000000);
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

int arcan_sem_post(sem_handle sem)
{
	return sem_post(sem);
}

int arcan_sem_unlink(sem_handle sem, char* key)
{
	return sem_unlink(key);
}

/* this little stinker is a temporary workaround
 * for the problem that depending on OS, kernel version,
 * alignment of the moons etc. local implementations aren't likely to
 * work as per POSIX :-/ ... */
#include <time.h>

static int sem_timedwaithack(sem_handle semaphore, int msecs)
{
	struct timespec st = {.tv_sec  = 0, .tv_nsec = 1000000L}, rem;

	if (msecs == 0)
		return sem_trywait( semaphore );

	if (msecs == -1){
		int rv;
		while ( -1 == (rv = sem_wait( semaphore )) && errno == EINTR);
		return rv;
	}

	int rc = -1;
	while ( (rc = sem_trywait(semaphore) != 0) && msecs && errno != EINVAL){
		struct timespec rem;
	//	nanosleep(&st, &rem);
		msecs -= 1;
	}

	return rc;
}

int arcan_sem_timedwait(sem_handle semaphore, int msecs)
{
	return sem_timedwaithack(semaphore, msecs);
}

/* try to allocate a shared memory page and two semaphores (vid / aud) is specififed,
 * return a pointer to the shared key (this will keep the resources allocated) or NULL on fail */
#include <sys/mman.h>
char* arcan_findshmkey(int* dfd, bool semalloc){
	int fd = -1;
	pid_t selfpid = getpid();
	int retrycount = 10;

	while (1){
		snprintf(playbuf, playbufsize, "/arcan_%i_%im", selfpid, rand());
		fd = shm_open(playbuf, O_CREAT | O_RDWR | O_EXCL, 0700);

	/* with EEXIST, we happened to have a name collision, it is unlikely, but may happen.
	 * for the others however, there is something else going on and there's no point retrying */
		if (-1 == fd && errno != EEXIST){
			arcan_warning("arcan_findshmkey(), allocating shared memory, reason: %d\n", errno);
			return NULL;
		}

		if (fd > 0){
			if (!semalloc)
				break;

			char* work = strdup(playbuf);
			work[strlen(work) - 1] = 'v';
			sem_t* vid = sem_open(work, O_CREAT | O_EXCL, 0700, 1);

			if (SEM_FAILED != vid){
				work[strlen(work) - 1] = 'a';

				sem_t* aud = sem_open(work, O_CREAT | O_EXCL, 0700, 1);
				if (SEM_FAILED != aud){

					work[strlen(work) -1] = 'e';
					sem_t* ev = sem_open(work, O_CREAT | O_EXCL, 0700, 1);

					if (SEM_FAILED != ev){
						free(work);
						break;
					}

					work[strlen(work) -1] = 'a';
					sem_unlink(work);
				}

				work[strlen(work) - 1] = 'v';
				sem_unlink(work);
			}

		/* semaphores couldn't be created, retry */
			shm_unlink(playbuf);
			fd = -1;
			free(work);

			if (retrycount-- == 0){
				arcan_warning("arcan_findshmkey(), allocating named semaphores failed, reason: %d, aborting.\n", errno);
				return NULL;
			}
		}
	}

	if (dfd)
		*dfd = fd;

	return strdup(playbuf);
}

#endif
