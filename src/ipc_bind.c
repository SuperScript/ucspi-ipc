#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "error.h"
#include "byte.h"
#include "str.h"
#include "ipc.h"
#include "ipcpath.h"

static int ipc_bindit(int s,const char *p,int del)
{
  struct sockaddr_un sa;
  unsigned int l;

  l = str_len(p);
  if (l > IPCPATH_MAX) {
    errno = error_proto;
    return -1;
  }
  byte_zero((char *) &sa,sizeof sa);
  sa.sun_family = AF_UNIX;
  byte_copy(sa.sun_path,l,p);
  if (del) unlink(sa.sun_path);
  return bind(s,(struct sockaddr *) &sa,sizeof sa);
}

int ipc_bind(int s,const char *p)
{
  return ipc_bindit(s,p,0);
}

int ipc_bind_reuse(int s,const char *p)
{
  return ipc_bindit(s,p,1);
}
