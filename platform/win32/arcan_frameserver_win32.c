/* Arcan-fe (OS/device platform), scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the platform/LICENSE file distributed with this source distribution
 * for licensing terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>

#include <fcntl.h>
#include <assert.h>
#include <Windows.h>
#include <tchar.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>

#include <arcan_shmif.h>

#include "../frameserver/frameserver.h"

void arcan_frameserver_decode_run(
	const char* resource, const char* keyfile);
void arcan_frameserver_libretro_run(
	const char* resource, const char* keyfile);
void arcan_frameserver_encode_run(
	const char* resource, const char* keyfile);
void arcan_frameserver_net_run(
	const char* resource, const char* keyfile);
void arcan_frameserver_avfeed_run(
	const char* resource, const char* keyfile);

#define DST_SAMPLERATE 44100
#define DST_AUDIOCHAN  2
#define DST_VIDEOCHAN  4

const int audio_samplerate = DST_SAMPLERATE;
const int audio_channels   = DST_AUDIOCHAN;
const int video_channels   = DST_VIDEOCHAN; 

FILE* logdev;

/*
 * arcan_shmif_acquire actually uses these 
 */
HWND parent = 0;
sem_handle async, vsync, esync;

bool stdout_redirected;
bool stderr_redirected;

char* arcan_resourcepath;
char* arcan_libpath;
char* arcan_themepath;
char* arcan_binpath;
char* arcan_themename;

/*void inval_param_handler(const wchar_t* expression,
   const wchar_t* function,
   const wchar_t* file,
   unsigned int line,
   uintptr_t pReserved)
{
   wprintf(L"Invalid parameter detected in function %s."
            L" File: %s Line: %d\n", function, file, line);
   wprintf(L"Expression: %s\n", expression);
   abort();
}*/

void* frameserver_getrawfile_handle(file_handle fh, ssize_t* ressize)
{
	void* retb = NULL;

	*ressize = GetFileSize(fh, NULL);

	if (*ressize > 0 /* && sz < THRESHOLD */ )
	{
		retb = malloc(*ressize);
		if (!retb)
			return retb;

		memset(retb, 0, *ressize);
		OVERLAPPED ov = {0};
		DWORD retc;
		ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (!ReadFile(fh, retb, *ressize, &retc, &ov) 
			&& GetLastError() == ERROR_IO_PENDING){
			if (!GetOverlappedResult(fh, &ov, &retc, TRUE)){
				free(retb);
				retb = NULL;
				*ressize = -1;
			}
		}

		CloseHandle(ov.hEvent);
	}

	CloseHandle(fh);

	return retb;
}

/* always close handle */
bool frameserver_dumprawfile_handle(const void* const buf, 
	size_t bufs, file_handle fh, bool finalize)
{
	bool rv = false;

/* facepalm awarded for this function .. */
	OVERLAPPED ov = {0};
	DWORD retc;

	if (INVALID_HANDLE_VALUE != fh){
		ov.Offset = 0xFFFFFFFF;
		ov.OffsetHigh = 0xFFFFFFFF;
		ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (!WriteFile(fh, buf, bufs, &retc, &ov) 
			&& GetLastError() == ERROR_IO_PENDING){
			if (!GetOverlappedResult(fh, &ov, &retc, TRUE)){
				LOG("frameserver(win32)_dumprawfile : "
					"failed, %ld\n", GetLastError());
			}
		}

		CloseHandle(ov.hEvent);
		if (finalize)
			CloseHandle(fh);
	}

	return rv;
}

/*
 * assumed to live as long as the frameserver is alive, 
 * and killed / closed alongside process 
 */
void* frameserver_getrawfile(const char* resource, ssize_t* ressize)
{
	HANDLE fh = CreateFile( resource, GENERIC_READ, 
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 
			FILE_FLAG_SEQUENTIAL_SCAN, NULL );
	if (fh == INVALID_HANDLE_VALUE)
		return NULL;

	HANDLE fmh = CreateFileMapping(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (fmh == INVALID_HANDLE_VALUE)
		return NULL;

	void* res = (void*) MapViewOfFile(fmh, FILE_MAP_READ, 0, 0, 0);
	if (ressize)
		*ressize = (ssize_t) GetFileSize(fh, NULL);

	return res;
}

file_handle frameserver_readhandle(arcan_event* src)
{
	return src->data.target.fh;
}

static HMODULE lastlib = NULL;
bool frameserver_loadlib(const char* const name)
{
	lastlib = LoadLibrary(name);
	return lastlib != NULL;
}

void* frameserver_requirefun(const char* const name, bool global)
{
	void* addr = GetProcAddress(lastlib, name);
	if (addr)
		return addr;
}

/* by default, we only do this for libretro where it might help
 * with external troubleshooting */
static void toggle_logdev(const char* prefix)
{
	const char* logdir = getenv("ARCAN_FRAMESERVER_LOGDIR");
	
	if (!logdir)
		logdir = "./resources/logs";

	if (logdir){
		char timeb[16];
		time_t t = time(NULL);
		struct tm* basetime = localtime(&t);
		strftime(timeb, sizeof(timeb)-1, "%y%m%d_%H%M", basetime);

		size_t logbuf_sz = strlen(logdir) + 
			sizeof("/fsrv__yymmddhhss.txt") + strlen(prefix);

		char* logbuf = malloc(logbuf_sz + 1);

		snprintf(logbuf, logbuf_sz+1, 
			"%s/fsrv_%s_%s.txt", logdir, prefix, timeb);
		logdev = freopen(logbuf, "a", stderr);
	}
	else
		logdev = fopen("NUL", "a");
}

int main(int argc, char* argv[])
{

#ifndef _DEBUG
/*	_set_invalid_parameter_handler(inval_param_handler) */
	DWORD dwMode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
	SetErrorMode(dwMode | SEM_NOGPFAULTERRORBOX);

#else
/*
 * set this env whenever you want to step through the
 * frameserver as launched from the parent 
 */
	toggle_logdev("main");
	LOG("arcan_frameserver(win32) -- launched with %d args.\n", argc);
#endif

	if (getenv("ARCAN_FRAMESERVER_DEBUGSTALL")){
		LOG("frameserver_debugstall, attach and unset "
			"volatile on pid: %d\n", (int) getpid());
        volatile bool a = false;
        while (!a){};
	}

/*
 * the convention on windows doesn't include 
 * the program name as first argument,
 * but some execution contexts may use it, 
 * e.g. ruby / cygwin / ... so skew the arguments 
 */
 	if (7 == argc){
		argv++;
		argc--;
	}

/* map cmdline arguments (resource, shmkey, vsem, asem, esem, mode),
 * parent is retrieved from shmpage */
	if (6 != argc){
		LOG("arcan_frameserver(win32, parsecmd) -- "
			"unexpected number of arguments, giving up.\n");
		return 1;
	}

	vsync = (HANDLE) strtoul(argv[2], NULL, 10);
	async = (HANDLE) strtoul(argv[3], NULL, 10);
	esync = (HANDLE) strtoul(argv[4], NULL, 10);

	char* resource = argv[0];
	char* fsrvmode = argv[5];
	char* keyfile  = argv[1];

#ifdef ENABLE_FSRV_DECODE
	if (strcmp(fsrvmode, "movie") == 0 
		|| strcmp(fsrvmode, "audio") == 0){
		toggle_logdev("decode");
		LOG("decode(%s:%s) : %s\n", fsrvmode, keyfile, resource);
		arcan_frameserver_decode_run(resource, keyfile);
		return 0;
	}
#endif

#ifdef ENABLE_FSRV_NET
	if (strcmp(fsrvmode, "net-cl") == 0 
		|| strcmp(fsrvmode, "net-srv") == 0){
		toggle_logdev("net");
		LOG("net(%s) : %s\n", keyfile, resource);
		arcan_frameserver_net_run(resource, keyfile);
		return 0;
	}
#endif

#ifdef ENABLE_FSRV_LIBRETRO
	if (strcmp(fsrvmode, "libretro") == 0){
		toggle_logdev("retro");
		LOG("retro(%s) : %s\n", keyfile, resource);
		arcan_frameserver_libretro_run(resource, keyfile);
		return 0;
	}
#endif

#ifdef ENABLE_FSRV_ENCODE
	if (strcmp(fsrvmode, "record") == 0){
		toggle_logdev("record");
		LOG("record(%s) : %s\n", keyfile, resource);
		arcan_frameserver_encode_run(resource, keyfile);
		return 0;
	}
#endif

#ifdef ENABLE_FSRV_AVFEED
	if (strcmp(fsrvmode, "avfeed") == 0){
		toggle_logdev("record");
		LOG("avfeed(%s) : %s\n", keyfile, resource);
		arcan_frameserver_avfeed_run(resource, keyfile);
		return 0;
	}
#endif

	LOG("arcan_frameserver(win32) unknown mode, %s\n", fsrvmode);

return 0;
}
