#include <sys/types.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <pwd.h>
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "exit.h"
#include "prot.h"
#include "open.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "env.h"
#include "pathexec.h"
#include "rules.h"
#include "fd.h"

int uid;
int gid;
char **args;
const char *remoteeuidstr;
const char *remoteegidstr;
unsigned int flagerrout = 1;
char *ipccommand = 0;
const char *temp;

struct passwd *pw;

char strnum[FMT_ULONG];

stralloc tmp = {0};
stralloc arg = {0};

int flagdeny = 0;
int verbosity = 1;
const char *fnrules;

#define FATAL "ipcserver: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

void badns(void)
{
  errno = error_proto;
  strerr_die2sys(111,FATAL,"bad ipc request: ");
}

void cats(const char *s)
{
  if (!stralloc_cats(&tmp,s)) nomem();
}

void append(const char *ch)
{
  if (!stralloc_append(&tmp,ch)) nomem();
}

void safecat(const char *s,int len)
{
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    if (!len) return;
    ch = s[i];
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
    --len;
  }
  cats("...");
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
  if (!pathexec_env(s,t)) nomem();
}

void norules(void)
{
  strerr_die4sys(111,FATAL,"unable to read ",fnrules,": ");
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
	if (str_equal(data + 1,"IPCUID"))
	  scan_uint(data + 1 + split + 1,&uid);
	if (str_equal(data + 1,"IPCGID"))
	  scan_uint(data + 1 + split + 1,&gid);
	if (str_equal(data + 1,"IPCERROUT"))
	  scan_uint(data + 1 + split + 1,&flagerrout);
	break;
      case '=':
	ipccommand = data + 1;
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit()
{
  int fdrules;

  remoteeuidstr = env_get("IPCREMOTEEUID");
  if (!remoteeuidstr) remoteeuidstr = "";
  remoteegidstr = env_get("IPCREMOTEEGID");
  if (!remoteegidstr) remoteegidstr = "";

  temp = env_get("IPCERROUT");
  if (temp) scan_uint(temp,&flagerrout);

  temp = env_get("IPCUID");
  if (temp) scan_uint(temp,&uid);

  temp = env_get("IPCGID");
  if (temp) scan_uint(temp,&gid);

  fdrules = open_read(fnrules);
  if (fdrules == -1) norules();
  if (rules_exec(found,fdrules,remoteeuidstr,remoteegidstr,arg.s) == -1) norules();
  close(fdrules);

  strnum[fmt_ulong(strnum,getpid())] = 0;
  if (!stralloc_copys(&tmp,"ipcexec: ")) nomem();
  safecats(flagdeny ? "deny" : "ok");
  cats(" "); safecats(remoteeuidstr);
  cats("."); safecats(remoteegidstr);
  cats(","); safecat(arg.s,byte_chr(arg.s,arg.len,0));
  cats("\n");
  buffer_putflush(buffer_2,tmp.s,tmp.len);

  if (flagdeny) _exit(100);
  if (ipccommand) args[0] = ipccommand;
}

void usage()
{
  strerr_warn1("\
ipcserver: usage: ipcexec \
rules.cdb \
",0);
  _exit(100);
}

unsigned long get_len()
{
  unsigned long len;
  unsigned char ch;

  len = 0;
  if (!buffer_get(buffer_0,&ch,1)) badns();
  for (;;) {
    if (ch == ':') return len;
    ch = ch - '0';
    if (ch > 9) badns();
    if (len > 999999999) badns();
    len = 10 * len + ch;
    if (!buffer_get(buffer_0,&ch,1)) badns();
  }
}

unsigned long get_ulong() {
  unsigned long len;
  unsigned long val;
  unsigned char ch;
  int i;

  len = get_len();
  val = 0;
  for (i = len;i;--i) {
    if (!buffer_get(buffer_0,&ch,1)) badns();
    ch = ch - '0';
    if (ch > 9) badns();
    val = 10 * val + ch;
  }
  if (!buffer_get(buffer_0,&ch,1)) badns();
  if (ch != ',') badns();
  return(val);
}

void get_args() {
  int argc;
  int len;
  int i;
  int j;
  char *str;
  unsigned char ch;

  uid = get_ulong();
  pw = getpwuid(uid);
  strnum[fmt_ulong(strnum,uid)] = 0;
  if (!pw) strerr_die3x(111,FATAL,"unknown uid ",strnum);
  gid = pw->pw_gid;

  if (!stralloc_copys(&arg,strnum)) nomem();
  if (!stralloc_cats(&arg,".")) nomem();

  argc = get_ulong();
  len = get_len();
  if (!len) badns();
  if (!stralloc_readyplus(&arg,len)) nomem();
  str = arg.s + arg.len;
  arg.len += len;
  if (buffer_get(buffer_0,str,len) != len) badns();
  if (arg.s[arg.len - 1]) badns();

  args = (char **) alloc((argc + 1) * sizeof(char *));
  
  for (i = 0;i < argc;++i) {
    args[i] = str;
    j = byte_chr(str,len,0) + 1;
    str += j; len -= j;
    if (len < 0) badns();
  }
  if (len) badns();
  if (!buffer_get(buffer_0,&ch,1)) badns();
  if (ch != ',') badns();

  args[argc] = 0;
}

int main(int argc,const char * const *argv)
{
  if (!*++argv) usage();

  fnrules = *argv;
  get_args();

  doit();

  if (gid) if (prot_gid(gid) == -1)
    strerr_die2sys(111,FATAL,"unable to set gid: ");
  if (uid) if (prot_uid(uid) == -1)
    strerr_die2sys(111,FATAL,"unable to set uid: ");

  if (flagerrout)
    if (fd_copy(2,1) == -1)
      strerr_die2sys(111,FATAL,"unable to copy fd: ");

  pathexec(args);
  strerr_die4sys(111,FATAL,"unable to run ",*args,": ");
}
