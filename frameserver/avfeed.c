/*
 * Arcan Terminal
 * Derived from ST (suckless terminal), http://st.suckless.org 
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

#ifdef _LINUX
	#include <pty.h>
#elif __APPLE__
	#include <util.h>
#else
	#include <libutil.h>
#endif

#include <util.h>

static struct {
	pid_t pid;
} shell_ctx;

void setup_shell(char* type, char** opt_cmd)
{
	char** args;
	char *envshell = getenv("SHELL");
	const struct passwd *pass = getpwuid(getuid());
	char buf[sizeof(long) * 8 + 1];

	unsetenv("COLUMNS");
	unsetenv("LINES");
	unsetenv("TERMCAP");

	if(pass) {
		printf("got pass, shell: %s\n", pass->pw_shell);
		setenv("LOGNAME", pass->pw_name, 1);
		setenv("USER", pass->pw_name, 1);
		setenv("SHELL", pass->pw_shell, 0);
		setenv("HOME", pass->pw_dir, 0);
	}
	printf("envshell? %s\n", envshell);

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
	printf("sigchild\n");
	if (waitpid(shell_ctx.pid, &stat, 0) < 0)
		exit(EXIT_FAILURE);

	if (WIFEXITED(stat))
		exit(WEXITSTATUS(stat));
	else
		exit(EXIT_FAILURE);
}

#ifdef TERM_STANDALONE
int main(int argc, char** argv)
#else
void arcan_frameserver_avfeed_run(const char* resource, const char* keyfike) 
#endif
{
/* allocate tty */
	struct winsize w = {80, 25, 0, 0};
	struct timeval* tv;
	int m, s;

	if (openpty(&m, &s, NULL, NULL, &w) < 0)
		goto error;

/*
 * clone shell, forward STDIN/STDOUT/STDERR
 */
	printf("forking\n");
	switch(shell_ctx.pid = fork()){
	case -1:
		goto error;
	break;
	case 0:
		printf("setup shell\n");
		dup2(s, STDIN_FILENO);
		dup2(s, STDOUT_FILENO);
		dup2(s, STDERR_FILENO);
		if (ioctl(s, TIOCSCTTY, NULL) < 0)
			exit(EXIT_FAILURE);
		close(s);
		close(m);
		setup_shell("/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
									, NULL);
	break;
	default:
		close(s);
		signal(SIGCHLD, sigchld);
	}

/*
 * use the parent socket as a trigger for sweeping
 * the event queue, 
 */	
	fd_set rfd;
	while(1){
		FD_ZERO(&rfd);
		FD_SET(m, &rfd);

		printf("selecting\n");
		if (select(1, &rfd, NULL, NULL, tv) < 0){
			if (errno == EINTR)
				continue;
			printf("select failed\n");
			break;
		}
		
		if (FD_ISSET(m, &rfd)){
/* ttyread */
		}
	}

error:
	m = 1;
#ifdef TERM_STANDALONE
	return 0;
#else
#endif
}
