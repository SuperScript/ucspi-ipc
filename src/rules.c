#include "alloc.h"
#include "stralloc.h"
#include "open.h"
#include "cdb.h"
#include "rules.h"

stralloc rules_name = {0};

static struct cdb c;

static int dorule(void (*callback)(char *,unsigned int))
{
  char *data;
  unsigned int datalen;

  switch(cdb_find(&c,rules_name.s,rules_name.len)) {
    case -1: return -1;
    case 0: return 0;
  }

  datalen = cdb_datalen(&c);
  data = alloc(datalen);
  if (!data) return -1;
  if (cdb_read(&c,data,datalen,cdb_datapos(&c)) == -1) {
    alloc_free(data);
    return -1;
  }

  callback(data,datalen);
  alloc_free(data);
  return 1;
}

static int doit(void (*callback)(char *,unsigned int),const char *euid,const char *egid)
{
  int r;

  if (euid && egid) {
    if (!stralloc_copys(&rules_name,euid)) return -1;
    if (!stralloc_cats(&rules_name,".")) return -1;
    if (!stralloc_cats(&rules_name,egid)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (euid) {
    if (!stralloc_copys(&rules_name,euid)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (egid) {
    if (!stralloc_copys(&rules_name,".")) return -1;
    if (!stralloc_cats(&rules_name,egid)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  rules_name.len = 0;
  return dorule(callback);
}

static int doit_exec(void (*callback)(char *,unsigned int),const char *euid,const char *egid,const char *prog)
{
  int r;

  if (euid && egid) {
    if (!stralloc_copys(&rules_name,euid)) return -1;
    if (!stralloc_cats(&rules_name,".")) return -1;
    if (!stralloc_cats(&rules_name,egid)) return -1;
    if (!stralloc_cats(&rules_name,",")) return -1;
    if (!stralloc_cats(&rules_name,prog)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (euid) {
    if (!stralloc_copys(&rules_name,euid)) return -1;
    if (!stralloc_cats(&rules_name,",")) return -1;
    if (!stralloc_cats(&rules_name,prog)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (egid) {
    if (!stralloc_copys(&rules_name,".")) return -1;
    if (!stralloc_cats(&rules_name,egid)) return -1;
    if (!stralloc_cats(&rules_name,",")) return -1;
    if (!stralloc_cats(&rules_name,prog)) return -1;
    r = dorule(callback);
    if (r) return r;
  }

  if (!stralloc_copys(&rules_name,",")) return -1;
  if (!stralloc_cats(&rules_name,prog)) return -1;
  r = dorule(callback);
  if (r) return r;

  rules_name.len = 0;
  return dorule(callback);
}

int rules(void (*callback)(char *,unsigned int),int fd,const char *euid,const char *egid)
{
  int r;
  cdb_init(&c,fd);
  r = doit(callback,euid,egid);
  cdb_free(&c);
  return r;
}

int rules_exec(void (*callback)(char *,unsigned int),int fd,const char *euid,const char *egid,const char *prog)
{
  int r;
  cdb_init(&c,fd);
  r = doit_exec(callback,euid,egid,prog);
  return r;
}

