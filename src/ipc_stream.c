#include <unistd.h>
#include <sys/socket.h>
#include "ndelay.h"
#include "ipc.h"

int ipc_stream(void)
{
  int s;

  s = socket(AF_UNIX,SOCK_STREAM,0);
  if (s == -1) return -1;
  if (ndelay_on(s) == -1) { close(s); return -1; }
  return s;
}
