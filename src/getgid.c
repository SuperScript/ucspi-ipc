#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include "strerr.h"
#include "fmt.h"
#include "buffer.h"
#include "exit.h"

#define FATAL "getgid: fatal: "

static char strnum[FMT_ULONG];

const char *account;
struct passwd *pw;

int main(int argc,const char *const *argv) {
  account = *++argv;
  if (account) {
    pw = getpwnam(account);
    if (!pw)
      strerr_die3x(111,FATAL,"unknown account ",account);

    strnum[fmt_ulong(strnum,pw->pw_uid)] = 0;
  }
  else {
    strnum[fmt_ulong(strnum,getgid())] = 0;
  }
  if (buffer_puts(buffer_1,strnum) == -1)
    strerr_die2sys(111,FATAL,"cannot write uid: ");
  if (buffer_putflush(buffer_1,"\n",1) == -1)
    strerr_die2sys(111,FATAL,"cannot write uid: ");
  _exit(0);
}
