#include "getpeereid.h"

int main()
{
  int euid;
  int egid;
  int so = 0;

  return getpeereid(so,&euid,&egid);
}
