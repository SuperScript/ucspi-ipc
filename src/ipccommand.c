#include <unistd.h>
#include <signal.h>
#include "sig.h"
#include "wait.h"
#include "fork.h"
#include "fmt.h"
#include "scan.h"
#include "buffer.h"
#include "strerr.h"
#include "str.h"
#include "exit.h"

char outbuf[512];
buffer bout;

char inbuf[512];
buffer bin;

int myread(int fd,char *buf,int len)
{
  buffer_flush(&bout);
  return buffer_unixread(fd,buf,len);
}

unsigned long uid = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

void usage()
{
  strerr_warn1("ipccommand: usage: ipccommand uid program",0);
  _exit(100);
}


int main(int argc,const char * const *argv)
{
  int pid;
  int wstat;
  char ch;
  unsigned int len;
  const char * const *arg;

  if (argc < 3) usage();

  scan_ulong(argv[1],&uid);
  argc -= 2;
  argv += 2;

  sig_ignore(sig_pipe);

  pid = fork();
  if (pid == -1) strerr_die2sys(111,"ipccommand: fatal: ","unable to fork: ");

  if (!pid) {
    buffer_init(&bin,myread,0,inbuf,sizeof inbuf);
    buffer_init(&bout,buffer_unixwrite,7,outbuf,sizeof outbuf);

    len = fmt_ulong(strnum,uid);
    buffer_put(&bout,strnum2,fmt_ulong(strnum2,len));
    buffer_puts(&bout,":");
    buffer_put(&bout,strnum,len);
    buffer_puts(&bout,",");

    len = fmt_ulong(strnum,argc);
    buffer_put(&bout,strnum2,fmt_ulong(strnum2,len));
    buffer_puts(&bout,":");
    buffer_put(&bout,strnum,len);
    buffer_puts(&bout,",");

    arg = argv;
    len = 0;
    while (*arg) {
      len += str_len(*arg);
      ++arg;
    }
    
    len += argc;

    buffer_put(&bout,strnum,fmt_ulong(strnum,len));
    buffer_puts(&bout,":");
    arg = argv;
    ch = 0;
    while (*arg) {
      buffer_puts(&bout,*arg);
      buffer_put(&bout,&ch,1);
      ++arg;
    }
    buffer_putsflush(&bout,",");

    while (buffer_get(&bin,&ch,1) == 1)
      buffer_put(&bout,&ch,1);
    _exit(0);
  }

  buffer_init(&bin,myread,6,inbuf,sizeof inbuf);
  buffer_init(&bout,buffer_unixwrite,1,outbuf,sizeof outbuf);

  while (buffer_get(&bin,&ch,1) == 1)
    buffer_put(&bout,&ch,1);

  kill(pid,sig_term);
  wait_pid(&wstat,pid);

  _exit(0);
}
