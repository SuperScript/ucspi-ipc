#include "byte.h"
#include "buffer.h"
#include "strerr.h"
#include "env.h"
#include "rules.h"
#include "stralloc.h"
#include "open.h"
#include "exit.h"

stralloc prog = {0};

#define FATAL "ipcexecrulescheck: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

void found(char *data,unsigned int datalen)
{
  unsigned int next0;

  buffer_puts(buffer_1,"rule ");
  buffer_put(buffer_1,rules_name.s,rules_name.len);
  buffer_puts(buffer_1,":\n");
  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	buffer_puts(buffer_1,"deny connection\n");
	buffer_flush(buffer_1);
	_exit(0);
      case '+':
	buffer_puts(buffer_1,"set environment variable ");
	buffer_puts(buffer_1,data + 1);
	buffer_puts(buffer_1,"\n");
	break;
      case '=':
	buffer_puts(buffer_1,"execute ");
	buffer_puts(buffer_1,data + 1);
	buffer_puts(buffer_1,"\n");
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
  buffer_puts(buffer_1,"allow connection\n");
  buffer_flush(buffer_1);
  _exit(0);
}

int main(int argc,const char * const *argv)
{
  const char *fnrules;
  int fd;
  char *ruid;
  char *rgid;
  char *uid;
  char *command;

  fnrules = argv[1];
  if (!fnrules)
    strerr_die1x(100,"ipcexecrulescheck: usage: ipcexecrulescheck rules.cdb");

  ruid = env_get("IPCREMOTEEUID");
  rgid = env_get("IPCREMOTEEGID");
  uid  = env_get("IPCUID");
  command = env_get("IPCCOMMAND");

  if (!command)
    strerr_die2x(111,FATAL,"IPCCOMMAND not set");

  if (!stralloc_copys(&prog,uid ? uid : "0")) nomem();
  if (!stralloc_cats(&prog,".")) nomem();
  if (!stralloc_cats(&prog,command)) nomem();
  if (!stralloc_0(&prog)) nomem();

  fd = open_read(fnrules);
  if ((fd == -1) || (rules_exec(found,fd,ruid,rgid,prog.s) == -1))
    strerr_die4sys(111,FATAL,"unable to read ",fnrules,": ");

  buffer_putsflush(buffer_1,"default:\nallow connection\n");
  _exit(0);
}
