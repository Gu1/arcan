/*
 * Arcan Terminal (AT)
 * ----------------------
 *
 * Derived from ST (suckless terminal), http://st.suckless.org
 * The UTF8 routines, terminal management and sequence parsing
 * could mostly be lifted, while-as everything graphics and input
 * related had to be rewritten.
 *
 * The basic design works around re-using the format string
 * renderfunctions from the main engine. With that, we get TTF
 * caching and most visual features needed. Thus, the history
 * buffer contains lines in their original form, then a parse
 * routine emits format strings, which gets rendered into the
 * shmpage directly. 
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arcan_shmif.h>
#include "arcan_ttf.h"
#include "arcan_renderfun.h"
#include "frameserver.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pwd.h>

#ifdef _LINUX
	#include <pty.h>
#elif __APPLE__
	#include <util.h>
#elif __FreeBSD
	#include <libutil.h>
#endif

static struct {
	pid_t pid;

/* shmif members */
	struct arcan_shmif_cont shmcont;
	struct arcan_evctx inevq;
	struct arcan_evctx outevq;
	uint8_t* vidp, (* audp);
} term_ctx;

void setup_shell(const char* type, char** opt_cmd)
{
	char** args;
	char *envshell = getenv("SHELL");
	const struct passwd *pass = getpwuid(getuid());
//	char buf[sizeof(long) * 8 + 1];

	unsetenv("COLUMNS");
	unsetenv("LINES");
	unsetenv("TERMCAP");

	if(pass) {
		setenv("LOGNAME", pass->pw_name, 1);
		setenv("USER", pass->pw_name, 1);
		setenv("SHELL", pass->pw_shell, 0);
		setenv("HOME", pass->pw_dir, 0);
	}

/* WINDOWID?
	setenv("WINDOWID", buf, 1);
*/

	signal(SIGCHLD, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGALRM, SIG_DFL);

	setenv("TERM", strdup(type), 1);
	args = opt_cmd ? opt_cmd : (char *[]){envshell, "-i", NULL}; 
	execvp(args[0], args); 
	exit(EXIT_FAILURE);
}

void sigchld(int a)
{
	int stat = 0;
	LOG("sigchild\n");
	if (waitpid(term_ctx.pid, &stat, 0) < 0)
		exit(EXIT_FAILURE);

	if (WIFEXITED(stat))
		exit(WEXITSTATUS(stat));
	else
		exit(EXIT_FAILURE);
}

void setup_shmterm(struct arg_arr* inargs, const char* keyfile)
{
	int desw = 320;
	int desh = 200;

	term_ctx.shmcont = arcan_shmif_acquire(keyfile,SHMIF_INPUT, true);

	arcan_shmif_setevqs(term_ctx.shmcont.addr, term_ctx.shmcont.esem, 
		&(term_ctx.inevq), &(term_ctx.outevq), false);

	if (!arcan_shmif_resize(&term_ctx.shmcont, desw, desh)){
		LOG("failed to setup shmpage rendering, requested: %d, %d\n",
			desw, desh);
	}

	TTF_Init();

	arcan_shmif_calcofs(term_ctx.shmcont.addr,&(term_ctx.vidp),&(term_ctx.audp));	

	unsigned int n_lines;
	unsigned short dw, dh;
	int maxw, maxh;
	uint32_t dsz;
	char* srcbuf = arcan_renderfun_renderfmtstr(
		"\\fdefault.ttf,18 Hello (terminal) World", 4, 8, NULL,
		false, &n_lines, NULL, &dw, &dh, &dsz, &maxw, &maxh);

#define RGBA(R, G, B, A) ((A << 24) || (B << 16) || (G << 8) || R);
	uint32_t* cur = (uint32_t*) term_ctx.vidp;
	for (int row = 0; row < desh; row++)
		for (int col = 0; col < desw; col++)
			*cur++ = RGBA(0xaa, 0xbb, 0, 0xff);

	arcan_shmif_signal(&term_ctx.shmcont, SHMIF_SIGVID);
/*
 * default resolution, font etc. as possible args 
 */ 
}

void process_inevq()
{
	arcan_event ev;

	while(arcan_event_poll(&term_ctx.inevq, &ev) == 1){
		LOG("event\n");
		switch(ev.category){
		case EVENT_IO:
		break;

		case EVENT_TARGET:
		break;
		}
	}
}

void arcan_frameserver_avfeed_run(const char* resource, const char* keyfile)
{
/* allocate tty */
	struct arg_arr* args = arg_unpack(resource);
	const char* shell;
	if (!arg_lookup(args, "shell", 0, &shell))
		shell = "/bin/sh";

	struct winsize wnd_sz = {80, 25, 0, 0};
	struct timeval* tv = NULL;
	int master, slave;

	if (openpty(&master, &slave, NULL, NULL, &wnd_sz) < 0){
		LOG("couldn't open shell\n");
		return;
	}

/*
 * clone shell, forward STDIN/STDOUT/STDERR
 */
	switch(term_ctx.pid = fork()){
	case -1:
		LOG("spawning new shell failed (fork)\n");
		return;
	
	case 0:
		setsid();
		dup2(slave, STDIN_FILENO);
		dup2(slave, STDOUT_FILENO);
		dup2(slave, STDERR_FILENO);

		if (ioctl(slave, TIOCSCTTY, NULL) < 0){
			LOG("(child) failed setting TIOCSCTTY: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		close(slave);
		close(master);
		setup_shell(shell, NULL);
	break;
	default:
		close(slave);
		signal(SIGCHLD, sigchld);
		setup_shmterm(args, keyfile);
	}

/* 
 * the sockin is a stream socket that (for now) is only used
 * to transfer file descriptors and as a select target that there are 
 * events pending in the event queue (as multiplexing with 
 * futexes etc. becomes messy quick)
 */
	int sockin_fd = strtol( getenv("ARCAN_SOCKIN_FD"), NULL, 10 );
	fd_set rfd;
	while(1){
		FD_ZERO(&rfd);
		FD_SET(master, &rfd);
		FD_SET(sockin_fd, &rfd);

		LOG("selecting\n");
		if (select(1, &rfd, NULL, NULL, tv) < 0){
			if (errno == EINTR)
				continue;
			LOG("select failed\n");
			break;
		}
		
		if (FD_ISSET(master, &rfd)){
			LOG("event in shell\n");	
		}

		if (FD_ISSET(sockin_fd, &rfd))
			process_inevq();	
	}	
}
