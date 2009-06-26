#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include "sig.h"
#include "exit.h"
#include "sgetopt.h"
#include "str.h"
#include "ipc.h"
#include "ipcpath.h"
#include "fd.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "pathexec.h"

#define FATAL "ipcclient: fatal: "
#define CONNECT "ipcclient: unable to connect to "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void usage(void)
{
  strerr_die1x(100,"ipcclient: usage: ipcclient \
[ -qQv ] \
[ -p localpath ] \
[ -l localname ] \
path program");
}

int verbosity = 1;
const char *bindpath = 0;
const char *forcelocal = 0;
char localpath[IPCPATH_MAX + 1];

int main(int argc,char * const *argv) {
  int opt;
  const char *x;
  int s;
  int trunc;

  close(6);
  close(7);
  sig_ignore(sig_pipe);
 
  while ((opt = getopt(argc,argv,"vqQp:l:")) != opteof)
    switch(opt) {
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'p': bindpath = optarg; break;
      case 'l': forcelocal = optarg; break;
      default: usage();
    }
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;

  x = *argv++;
  if (!x) usage();

  if (!*argv) usage();

  s = ipc_stream();
  if (s == -1)
    strerr_die2sys(111,FATAL,"unable to create socket: ");
  if (bindpath)
    if (ipc_bind(s,bindpath) == -1)
      strerr_die2sys(111,FATAL,"unable to bind: ");
  if (ipc_connect(s,x) == -1) {
    strerr_warn3(CONNECT,x,": ",&strerr_sys);
    _exit(111);
  }
  if (verbosity >= 2)
    strerr_warn2("ipcclient: connected to ",x,0);

  if (!pathexec_env("PROTO","IPC")) nomem();

  x = forcelocal;
  if (!x)
    if (ipc_local(s,localpath,sizeof(localpath),&trunc) == 0) {
      x = localpath;
    }
  if (!pathexec_env("IPCLOCALPATH",x)) nomem();

  if (fd_move(6,s) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 6: ");
  if (fd_copy(7,6) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 7: ");
  sig_uncatch(sig_pipe);

  pathexec(argv);
  strerr_die4sys(111,FATAL,"unable to run ",*argv,": ");
}
