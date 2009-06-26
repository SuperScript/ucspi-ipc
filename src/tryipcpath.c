#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include "fmt.h"

static struct sockaddr_un un = {0};
static char strnum[FMT_ULONG];

int main(void) {
  write(1,strnum,fmt_ulong(strnum,sizeof(un.sun_path)));
  write(1,"\n",1);
  _exit(0);
}
