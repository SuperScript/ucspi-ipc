#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "byte.h"
#include "ipc.h"

int ipc_accept(int s,char *p,int l,int *trunc)
{
  int fd;
  struct sockaddr_un sa;
  int dummy = sizeof sa;

  byte_zero((char *) &sa,sizeof sa);
  fd = accept(s,(struct sockaddr *) &sa,&dummy);
  if (fd == -1) return -1;

  dummy = byte_chr(sa.sun_path,dummy,0);

  *trunc = 1;
  if (!l) return fd;

  if (l < (dummy + 1))
    dummy = l - 1;
  else
    *trunc = 0;

  byte_copy(p,dummy,sa.sun_path);
  p[dummy] = 0;

  return fd;
}
