#include <sys/types.h>
#include "getpeereid.h"
#include "ipc.h"

int ipc_eid(int s,int *u,int *g)
{
  uid_t dummyu;
  gid_t dummyg;

  if (getpeereid(s,&dummyu,&dummyg) == -1) return -1;

  *u = dummyu;
  *g = dummyg;

  return 0;
}
