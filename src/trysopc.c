#include <sys/types.h>
#include <sys/socket.h>
#include "getpeereid.h"

int main()
{
  int s;
  struct ucred dummy = {0};
  int len = sizeof(dummy);

  return getsockopt(s,SOL_SOCKET,SO_PEERCRED,&dummy,&len);
}
