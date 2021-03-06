#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>

#include <arcan_math.h>
#include <arcan_general.h>
#include <arcan_event.h>

#include "arcan_shmif.h"

/* This little function tries to get around all the insane problems
 * that occur with the fundamentally broken sem_timedwait with named
 * semaphores and a parent<->child circular dependency (like we have here).
 *
 * Sleep a fixed amount of seconds, wake up and check if parent is alive.
 * If that's true, go back to sleep -- otherwise -- wake up, pop open 
 * all semaphores set the disengage flag and go back to a longer sleep
 * that it shouldn't wake up from. Show this sleep be engaged anyhow, 
 * shut down forcefully. */

struct guard_struct {
	sem_handle semset[3];
	int parent;
	volatile uintptr_t* dms; /* dead man's switch */
};
static void* guard_thread(void* gstruct);

static void spawn_guardthread(struct guard_struct gs)
{
	struct guard_struct* hgs = malloc(sizeof(struct guard_struct));
	*hgs = gs;

	pthread_t pth;
	pthread_attr_t pthattr;
	pthread_attr_init(&pthattr);
	pthread_attr_setdetachstate(&pthattr, PTHREAD_CREATE_DETACHED);

	pthread_create(&pth, &pthattr, guard_thread, hgs);
}

/* Dislike pulling stunts like this,
 * but it saved a lot of bad codepaths */
#if _WIN32

#define sleep(n) Sleep(1000 * n)

extern sem_handle async, vsync, esync;
extern HANDLE parent;

static inline bool parent_alive()
{
	return IsWindow(parent);
}

/* force_unlink isn't used here as the semaphores are 
 * passed as inherited handles */
struct arcan_shmif_cont arcan_shmif_acquire(
	const char* shmkey, int shmif_type, char force_unlink, char noguard)
{
	struct arcan_shmif_cont res = {0};
	assert(shmkey);

	HANDLE shmh = (HANDLE) strtoul(shmkey, NULL, 10);

	res.addr = (struct arcan_shmif_page*) MapViewOfFile(shmh, 
		FILE_MAP_ALL_ACCESS, 0, 0, ARCAN_SHMPAGE_MAX_SZ);

	if ( res.addr == NULL ) {
		arcan_warning("fatal: Couldn't map the allocated shared "
			"memory buffer (%i) => error: %i\n", shmkey, GetLastError());
		CloseHandle(shmh);
		return res;
	}

	res.asem = async;
	res.vsem = vsync;
	res.esem = esync;

	parent = res.addr->parent;

	struct guard_struct gs = {
		.dms = &res.addr->dms,
		.semset = { async, vsync, esync }
	};

	if (!noguard)
		spawn_guardthread(gs);

/*
 * Type-specific handling if necessary here
 */ 

	arcan_warning("arcan_frameserver() -- shmpage configured and filled.\n");
	return res;
}

/*
 * No implementation on windows currently (or planned)
 */
char* arcan_shmif_connect(const char* connpath, const char* connkey)
{
	return NULL;
}

#else
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

struct arcan_shmif_cont arcan_shmif_acquire(
	const char* shmkey, int shmif_type, char force_unlink, char noguard){
	struct arcan_shmif_cont res = {0};

	unsigned bufsize = ARCAN_SHMPAGE_MAX_SZ;
	int fd = -1;

	fd = shm_open(shmkey, O_RDWR, 0700);

	if (-1 == fd){
		arcan_warning("arcan_frameserver(getshm) -- couldn't open "
			"keyfile (%s), reason: %s\n", shmkey, strerror(errno));
		return res;
	}

/* map up the shared key- file */
	res.addr = (struct arcan_shmif_page*) mmap(NULL,
		bufsize,
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		fd,
	0);

	close(fd);

	if (force_unlink) 
		shm_unlink(shmkey);

	if (res.addr == MAP_FAILED){
		arcan_warning("arcan_frameserver(getshm) -- couldn't map keyfile"
			"	(%s), reason: %s\n", shmkey, strerror(errno));
		return res;
	}

	arcan_warning("arcan_frameserver(getshm) -- mapped to %" PRIxPTR
		" \n", (uintptr_t) res.addr);

/* step 2, semaphore handles */
	char* work = strdup(shmkey);
	work[strlen(work) - 1] = 'v';
	res.vsem = sem_open(work, 0);
	if (force_unlink) 
		sem_unlink(work);

	work[strlen(work) - 1] = 'a';
	res.asem = sem_open(work, 0);
	if (force_unlink) 
		sem_unlink(work);

	work[strlen(work) - 1] = 'e';
	res.esem = sem_open(work, 0);
	if (force_unlink) 
		sem_unlink(work);
	free(work);

	if (res.asem == 0x0 ||
		res.esem == 0x0 ||
		res.vsem == 0x0 ){
		arcan_warning("arcan_shmif_control(getshm) -- couldn't "
			"map semaphores (basekey: %s), giving up.\n", shmkey);
		free(res.addr);
		res.addr = MAP_FAILED;
		return res;
	}

	struct guard_struct gs = {
		.dms = &res.addr->dms,
		.semset = { res.asem, res.vsem, res.esem },
		.parent = res.addr->parent
	};

	if (!noguard)
		spawn_guardthread(gs);

	return res;
}

char* arcan_shmif_connect(const char* connpath, const char* connkey)
{
	if (!connpath){
		arcan_warning("arcan_shmif_connect(), missing connpath, giving up.\n");
		return NULL;
	}

	char* res = NULL;	
	char* workbuf = NULL;
	size_t conn_sz;

/* the rules for resolving the connection socket namespace are 
 * somewhat complex, i.e. on linux we have the atrocious \0 prefix
 * that defines a separate socket namespace, if we don't specify
 * an absolute path, the key will resolve to be relative your 
 * HOME environment (BUT we also have an odd size limitation to
 * sun_path to take into consideration). */
#ifdef __linux
	if (ARCAN_SHM_PREFIX[0] == '\0'){
		conn_sz = strlen(connpath) + sizeof(ARCAN_SHM_PREFIX);
		workbuf = malloc(conn_sz);
		snprintf(workbuf+1, conn_sz-1, "%s%s", &ARCAN_SHM_PREFIX[1], connpath);
		workbuf[0] = '\0';
	}
	else
#endif
	if (ARCAN_SHM_PREFIX[0] != '/'){
		const char* auxp = getenv("HOME");
		conn_sz = strlen(connpath) + strlen(auxp) + sizeof(ARCAN_SHM_PREFIX) + 1;
		workbuf = malloc(conn_sz);
		snprintf(workbuf, conn_sz, "%s/%s%s", auxp, ARCAN_SHM_PREFIX, connpath);
	} 
	else {
		conn_sz = strlen(connpath) + sizeof(ARCAN_SHM_PREFIX);
		workbuf = malloc(conn_sz);
		snprintf(workbuf, conn_sz, "%s%s", ARCAN_SHM_PREFIX, connpath);
	}

/* 1. treat connpath as socket and connect */
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un dst = {
		.sun_family = AF_UNIX
	};

	if (-1 == sock){
		arcan_warning("arcan_shmif_connect(), "
			"couldn't allocate socket, reason: %s\n", strerror(errno));
		goto end;
	}

	size_t lim = sizeof(dst.sun_path) / sizeof(dst.sun_path[0]);
	if (lim < conn_sz){
		arcan_warning("arcan_shmif_connect(), "
			"specified connection path exceeds limits (%d)\n", lim);
		goto end;
	}
	memcpy(dst.sun_path, workbuf, conn_sz);

/* connection or not, unlink the connection path */
	if (connect(sock, (struct sockaddr*) &dst, sizeof(struct sockaddr_un)) < 0){
		arcan_warning("arcan_shmif_connect(%s), "
			"couldn't connect to server, reason: %s.\n", 
			dst.sun_path, strerror(errno)
		);
		close(sock);
		unlink(workbuf);
		goto end;
	}
	unlink(workbuf);

/* 2. send (optional) connection key, we send that first (keylen + linefeed) */
	char wbuf[PP_SHMPAGE_SHMKEYLIM+1];
	if (connkey){
		size_t nw = snprintf(wbuf, PP_SHMPAGE_SHMKEYLIM, "%s\n", connkey);
		if (nw >= PP_SHMPAGE_SHMKEYLIM){
			arcan_warning("arcan_shmif_connect(%s), "
				"ident string (%s) exceeds limit (%d).\n", 
				workbuf, connkey, PP_SHMPAGE_SHMKEYLIM
			);
			close(sock);
			goto end;
		}

		if (write(sock, wbuf, nw) < nw){
			arcan_warning("arcan_shmif_connect(%s), "
				"error sending connection string, reason: %s\n", 
				workbuf, strerror(errno)
			);
			close(sock);
			goto end;
		}
	}

/* 3. wait for key response (or broken socket) */
	size_t ofs = 0;
	do {
		if (-1 == read(sock, wbuf + ofs, 1)){
			arcan_warning("arcan_shmif_connect(%s), "
				"invalid response received during shmpage negotiation.\n", workbuf);
			close(sock);
			goto end;
		}
	} 
	while(wbuf[ofs++] != '\n' && ofs < PP_SHMPAGE_SHMKEYLIM);
	wbuf[ofs-1] = '\0';

/* 4. omitted, just return a copy of the key and let someone else
 * perform the arcan_shmif_acquire call. Just set the env. */
	res = strdup(wbuf); 
	snprintf(wbuf, PP_SHMPAGE_SHMKEYLIM, "%d", sock);
	setenv("ARCAN_SOCKIN_FD", wbuf, true);

end:
	free(workbuf);
	return res;
}

#include <signal.h>
static inline bool parent_alive(struct guard_struct* gs)
{
/* based on the idea that init inherits an orphaned process,
 * return getppid() != 1; won't work for hijack targets that fork() fork() */
	return kill(gs->parent, 0) != -1;
}
#endif

static void* guard_thread(void* gs)
{
	struct guard_struct* gstr = (struct guard_struct*) gs;
	*(gstr->dms) = true;

	while (true){
		if (!parent_alive(gstr)){
			*(gstr->dms) = false;

			for (int i = 0; i < sizeof(gstr->semset) / sizeof(gstr->semset[0]); i++)
				if (gstr->semset[i])
					arcan_sem_post(gstr->semset[i]);

			sleep(5);
			arcan_warning("frameserver::guard_thread -- couldn't shut"
				"	down gracefully, exiting.\n");
			exit(EXIT_FAILURE);
		}

		sleep(5);
	}

	return NULL;
}

bool arcan_shmif_integrity_check(struct arcan_shmif_page* shmp)
{
	if (shmp->major != ARCAN_VERSION_MAJOR ||
		shmp->minor != ARCAN_VERSION_MINOR){
		arcan_warning("frameserver::shmif integrity check failed\n");
		return false;
	}
	return true;
}

void arcan_shmif_setevqs(struct arcan_shmif_page* dst, 
	sem_handle esem, arcan_evctx* inq, arcan_evctx* outq, bool parent)
{
	if (parent){
		arcan_evctx* tmp = inq;
		inq = outq;
		outq = tmp;

		outq->synch.handle = esem;
		inq->synch.handle = esem;

		inq->synch.killswitch = NULL;
		outq->synch.killswitch = NULL;
	}
	else {
		inq->synch.handle = esem;
		inq->synch.killswitch = &dst->dms;
		outq->synch.handle = esem;
		outq->synch.killswitch = &dst->dms;
	}

	inq->local = false;
	inq->eventbuf = dst->childdevq.evqueue;
	inq->front = &dst->childdevq.front;
	inq->back  = &dst->childdevq.back;
	inq->eventbuf_sz = ARCAN_SHMPAGE_QUEUE_SZ; 

	outq->local =false;
	outq->eventbuf = dst->parentdevq.evqueue;
	outq->front = &dst->parentdevq.front;
	outq->back  = &dst->parentdevq.back;
	outq->eventbuf_sz = ARCAN_SHMPAGE_QUEUE_SZ; 
}

#include <assert.h>
void arcan_shmif_signal(struct arcan_shmif_cont* ctx, int mask)
{
	if (mask == SHMIF_SIGVID){
		ctx->addr->vready = true;
		arcan_sem_wait(ctx->vsem);
		assert(ctx->addr->vready == false);
	}
	else if (mask == SHMIF_SIGAUD){ 
		ctx->addr->aready = true;
		arcan_sem_wait(ctx->asem);
		assert(ctx->addr->aready == false);
	}
	else if (mask == (SHMIF_SIGVID | SHMIF_SIGAUD)){
		ctx->addr->vready = ctx->addr->aready = true;
		arcan_sem_wait(ctx->vsem);
		arcan_sem_wait(ctx->asem);
		assert(ctx->addr->aready == false && ctx->addr->vready == false);
	}
	else 
		;
}

void arcan_shmif_forceofs(struct arcan_shmif_page* shmp, 
	uint8_t** dstvidptr, uint8_t** dstaudptr, unsigned width, 
	unsigned height, unsigned bpp)
{
	uint8_t* base = (uint8_t*) shmp;
	uint8_t* vidaddr = base + sizeof(struct arcan_shmif_page);
	uint8_t* audaddr;

	const int memalign = 64;

	if ( (uintptr_t)vidaddr % memalign != 0)
		vidaddr += memalign - ( (uintptr_t)vidaddr % memalign);

	audaddr = vidaddr + abs(width * height * bpp);
	if ( (uintptr_t) audaddr % memalign != 0)
		audaddr += memalign - ( (uintptr_t) audaddr % memalign);

	if (audaddr < base || vidaddr < base){
		*dstvidptr = *dstaudptr = NULL;
	}
	else {
		*dstvidptr = (uint8_t*) vidaddr;
		*dstaudptr = (uint8_t*) audaddr;
	}
}

void arcan_shmif_calcofs(struct arcan_shmif_page* shmp, 
	uint8_t** dstvidptr, uint8_t** dstaudptr)
{
	arcan_shmif_forceofs(shmp, dstvidptr, dstaudptr, 
		shmp->w, shmp->h, ARCAN_SHMPAGE_VCHANNELS);
}

void arcan_shmif_drop(struct arcan_shmif_cont* inctx)
{
#if _WIN32
#else
	munmap(inctx->addr, ARCAN_SHMPAGE_MAX_SZ);
	memset(inctx, '\0', sizeof(struct arcan_shmif_cont));
#endif
}

bool arcan_shmif_resize(struct arcan_shmif_cont* arg, 
	unsigned width, unsigned height)
{
	if (arg->addr){
		arg->addr->w = width;
		arg->addr->h = height;

		if (arcan_shmif_integrity_check(arg->addr)){
			arg->addr->resized = true;

/* spinlock until acknowledged */
			while(arg->addr->resized && arg->addr->dms);

			return true;
		}
	}

	return false;
}

static char* strrep(char* dst, char key, char repl)
{
	char* src = dst;

	if (dst)
		while (*dst){
			if (*dst == key)
				*dst = repl;
			dst++;
		}

		return src;
}

struct arg_arr* arg_unpack(const char* resource)
{
	int argc = 1;
	const char* rsstr = resource;

/* unless an empty string, we'll always have 1 */
	if (!resource)
		return NULL;

/* figure out the number of additional arguments we have */
	do{
		if (rsstr[argc] == ':')
			argc++;
		rsstr++;
	} while(*rsstr);

/* prepare space */
	struct arg_arr* argv = malloc( (argc+1) * sizeof(struct arg_arr) );
	if (!argv)
		return NULL;

	int curarg = 0;
	argv[argc].key = argv[argc].value = NULL;

	char* base    = strdup(resource);
	char* workstr = base;

/* sweep for key=val:key:key style packed arguments, 
 * since this is used in such a limited fashion (RFC 3986 at worst),
 * we use a replacement token rather than an escape one, 
 * so \t becomes : post-process 
 */
	while (curarg < argc){
		char* endp  = workstr;
		argv[curarg].key = argv[curarg].value = NULL;

		while (*endp && *endp != ':'){
/* a==:=a=:a=dd= are disallowed */
			if (*endp == '='){
				if (!argv[curarg].key){
					*endp = 0;
					argv[curarg].key = strrep(strdup(workstr), '\t', ':');
					argv[curarg].value = NULL;
					workstr = endp + 1;
				}
				else{
					free(argv);
					argv = NULL;
					goto cleanup;
				}
			}

			endp++;
		}

		if (*endp == ':')
			*endp = '\0';

		if (argv[curarg].key)
			argv[curarg].value = strrep(strdup( workstr ), '\t', ':');
		else
			argv[curarg].key = strrep(strdup( workstr ), '\t', ':');

		workstr = (++endp);
		curarg++;
	}

cleanup:
	free(base);

	return argv;
}

void arg_cleanup(struct arg_arr* arr)
{
	if (!arr)
		return;

	while (arr->key){
		free(arr->key);
		free(arr->value);
		arr++;
	}
}

bool arg_lookup(struct arg_arr* arr, const char* val, 
	unsigned short ind, const char** found)
{
	int pos = 0;

	while (arr[pos].key != NULL){
/* return only the 'ind'th match */
		if (strcmp(arr[pos].key, val) == 0)
			if (ind-- == 0){
				if (found)
					*found = arr[pos].value;

				return true;
			}

		pos++;
	}

	return false;
}
