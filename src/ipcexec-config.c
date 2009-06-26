#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "strerr.h"
#include "exit.h"
#include "auto_home.h"
#include "generic-conf.h"
#include "fmt.h"

#define FATAL "ipcexec-config: fatal: "

char strnum[FMT_ULONG];

void usage(void)
{
  strerr_die1x(100,"ipcexec-config: usage: ipcexec-config user loguser dir");
}

const char *dir;
const char *port;
const char *user;
const char *loguser;
struct passwd *pw;

int main(int argc,const char * const *argv)
{
  umask(022);
  
  user = argv[1];
  if (!user) usage();
  loguser = argv[2];
  if (!loguser) usage();
  dir = argv[3];
  if (!dir) usage();
  if (dir[0] != '/') usage();

  pw = getpwnam(loguser);
  if (!pw)
    strerr_die3x(111,FATAL,"unknown account ",loguser);

  init(dir,FATAL);
  makelog(loguser,pw->pw_uid,pw->pw_gid);

  pw = getpwnam(user);
  if (!pw)
    strerr_die3x(111,FATAL,"unknown account ",user);

  start("run");
  outs("#!/bin/sh\nexec 2>&1\nexec envdir "); outs(dir);
  outs("/env sh -c '\nexec envuidgid "); outs(user);
  outs(" ipcserver -v "); outs(dir); outs("/s \\\n");
  outs(auto_home); outs("/command/ipcexec \\\n");
  outs(dir); outs("/rules/data.cdb\n'\n");
  finish();
  perm(0755);

  makedir("env");
  perm(02755);

  start("env/IPCERROUT");
  outs("1");
  finish();
  perm(0644);

  makedir("rules");
  perm(02755);

  start("rules/data");
  outs(":deny\n");
  finish();
  perm(0644);

  start("rules/Makefile");
  outs("data.cdb: data\n\t"); outs("ipcexecrules data.cdb data.tmp <data\n");
  finish();
  perm(0644);

  _exit(0);
}
