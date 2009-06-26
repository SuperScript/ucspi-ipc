#include "buffer.h"
#include "env.h"

static char *e[] = {0};
static int n = 0;

void server(int argc,const char * const *argv) {
  char *x;

  buffer_puts(buffer_1,"\nPROTO=");
  x = env_get("PROTO");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nIPCLOCALPATH=");
  x = env_get("IPCLOCALPATH");
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nIPCREMOTEPATH=");
  x = env_get("IPCREMOTEPATH"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nIPCREMOTEEUID=");
  x = env_get("IPCREMOTEEUID"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_puts(buffer_1,"\nIPCREMOTEEGID=");
  x = env_get("IPCREMOTEEGID"); 
  buffer_puts(buffer_1,x ? x : "unset");

  buffer_putsflush(buffer_1,"\n");

  if (++n > 1) {
    environ = e;
  }
}
