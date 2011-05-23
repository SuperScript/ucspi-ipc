#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "sgetopt.h"
#include "pathexec.h"
#include "ipc.h"
#include "ipcpath.h"
#include "rules.h"
#include "sig.h"
#include "ndelay.h"
#include "fork.h"

int verbosity = 1;
const char *banner = "";

char remotepath[IPCPATH_MAX + 1];
char localname[IPCPATH_MAX + 1];
const char *forcelocal = 0;
const char *localpath = 0;

char remoteeuidstr[FMT_ULONG];
char remoteegidstr[FMT_ULONG];
int remoteeuid;
int remoteegid;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];


stralloc tmp = {0};

char bspace[16];
buffer b;



/* ---------------------------- child */

#define DROP "ipcserver: warning: dropping connection, "

int flagdelete = 1;
int flagdeny = 0;
int flagallownorules = 0;
int flagpeereid = 1;
const char *fnrules = 0;

void drop_nomem(void)
{
  strerr_die2x(111,DROP,"out of memory");
}
void drop_eid(void)
{
  strerr_die2sys(111,DROP,"unable to obtain client eid: ");
}
void cats(const char *s)
{
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(const char *ch)
{
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(const char *s)
{
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t)
{
  if (!pathexec_env(s,t)) drop_nomem();
}
void drop_rules(void)
{
  strerr_die4sys(111,DROP,"unable to read ",fnrules,": ");
}

void found(char *data,unsigned int datalen)
{
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	flagdeny = 1;
	break;
      case '+':
	split = str_chr(data + 1,'=');
	if (data[1 + split] == '=') {
	  data[1 + split] = 0;
	  env(data + 1,data + 1 + split + 1);
	}
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit(int t)
{
  int trunc;

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn4("ipcserver: pid ",strnum," from ",remotepath,0);
  }

  if (*banner) {
    buffer_init(&b,buffer_unixwrite,t,bspace,sizeof bspace);
    if (buffer_putsflush(&b,banner) == -1)
      strerr_die2sys(111,DROP,"unable to print banner: ");
  }

  localpath = forcelocal;
  if (!localpath)
    if (ipc_local(t,localname,sizeof(localname),&trunc) == 0) {
      localpath = localname;
    }
  env("PROTO","IPC");
  env("IPCLOCALPATH",localpath);
  env("IPCREMOTEPATH",remotepath);

  if (flagpeereid) {
    if (ipc_eid(t,&remoteeuid,&remoteegid) == -1)
      drop_eid();
    remoteeuidstr[fmt_ulong(remoteeuidstr,remoteeuid)] = 0;
    remoteegidstr[fmt_ulong(remoteegidstr,remoteegid)] = 0;
    env("IPCREMOTEEUID",remoteeuidstr);
    env("IPCREMOTEEGID",remoteegidstr);
  }
  else {
    remoteeuid = geteuid();
    remoteegid = getegid();
    remoteeuidstr[fmt_ulong(remoteeuidstr,remoteeuid)] = 0;
    remoteegidstr[fmt_ulong(remoteegidstr,remoteegid)] = 0;
    env("IPCREMOTEEUID",0);
    env("IPCREMOTEEGID",0);
  }

  if (fnrules) {
    int fdrules;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != error_noent) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,remoteeuidstr,remoteegidstr) == -1) drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,"ipcserver: ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); safecats(localpath);
    cats(" "); safecats(remotepath);
    cats(":"); safecats(remoteeuidstr);
    cats(","); safecats(remoteegidstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) _exit(100);
}



/* ---------------------------- parent */

#define FATAL "ipcserver: fatal: "

void usage()
{
  strerr_warn1("\
ipcserver: usage: ipcserver \
[ -UXoOdDqQvpP ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
path program",0);
  _exit(100);
}

unsigned long limit = 40;
unsigned long numchildren = 0;

unsigned long backlog = 20;
unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void)
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strerr_warn4("ipcserver: status: ",strnum,"/",strnum2,0);
}

void sigterm()
{
  _exit(0);
}

void sigchld()
{
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      strerr_warn4("ipcserver: end ",strnum," status ",strnum2,0);
    }
    if (numchildren) --numchildren; printstatus();
  }
}

int main(int argc,char * const *argv)
{
  const char *path;
  int opt;
  const char *x;
  int s;
  int t;
  mode_t m;
  int trunc;

  while ((opt = getopt(argc,argv,"vqQdDUXx:u:g:l:b:B:c:pP")) != opteof)
    switch(opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'B': banner = optarg; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'd': flagdelete = 1; break;
      case 'D': flagdelete = 0; break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
		x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case 'l': forcelocal = optarg; break;
      case 'p': flagpeereid = 1; break;
      case 'P': flagpeereid = 0; break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  path = *argv++;
  if (!path) usage();
  if (str_equal(path,"")) usage();

  if (!*argv) usage();

  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);

  s = ipc_stream();
  if (s == -1)
    strerr_die2sys(111,FATAL,"unable to create socket: ");
  m = umask(0);
  if (flagdelete) {
    if (ipc_bind_reuse(s,path) == -1)
      strerr_die2sys(111,FATAL,"unable to bind: ");
  }
  else {
    if (ipc_bind(s,path) == -1)
      strerr_die2sys(111,FATAL,"unable to bind: ");
  }
  umask(m);
  if (ipc_local(s,0,0,&trunc) == -1)
    strerr_die2sys(111,FATAL,"unable to get local address: ");
  if (ipc_listen(s,backlog) == -1)
    strerr_die2sys(111,FATAL,"unable to listen: ");
  ndelay_off(s);

  if (gid) if (prot_gid(gid) == -1)
    strerr_die2sys(111,FATAL,"unable to set gid: ");
  if (uid) if (prot_uid(uid) == -1)
    strerr_die2sys(111,FATAL,"unable to set uid: ");

  close(0);
  close(1);
  printstatus();

  for (;;) {
    while (numchildren >= limit) sig_pause();

    sig_unblock(sig_child);
    
    t = ipc_accept(s,remotepath,sizeof(remotepath),&trunc);
    sig_block(sig_child);

    if (t == -1) continue;
    ++numchildren; printstatus();

    switch(fork()) {
      case 0:
        close(s);
        doit(t);
        if ((fd_move(0,t) == -1) || (fd_copy(1,0) == -1))
	  strerr_die2sys(111,DROP,"unable to set up descriptors: ");
        sig_uncatch(sig_child);
        sig_unblock(sig_child);
        sig_uncatch(sig_term);
        sig_uncatch(sig_pipe);
        pathexec(argv);
	strerr_die4sys(111,DROP,"unable to run ",*argv,": ");
      case -1:
        strerr_warn2(DROP,"unable to fork: ",&strerr_sys);
        --numchildren; printstatus();
    }
    close(t);
  }
}
