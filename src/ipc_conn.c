#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "error.h"
#include "byte.h"
#include "str.h"
#include "ndelay.h"
#include "ipc.h"
#include "ipcpath.h"

int ipc_connect(int s,const char *p)
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

  if (connect(s,(struct sockaddr *) &sa,sizeof sa) == -1) return -1;

  if (ndelay_off(s) == -1) return -1;
  return 0;
}
