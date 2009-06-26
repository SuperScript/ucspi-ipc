#ifndef IPC_H
#define IPC_H

extern int ipc_stream(void);
extern int ipc_datagram(void);

extern int ipc_connect(int,const char *);
extern int ipc_bind(int,const char *);
extern int ipc_bind_reuse(int,const char *);
extern int ipc_listen(int,int);
extern int ipc_accept(int,char *,int,int *);
extern int ipc_eid(int,int *,int *);

extern int ipc_send(int,const char *,int,char *);
extern int ipc_recv(int,char *,int,char *,int,int *);

extern int ipc_local(int,char *,int,int *);
extern int ipc_remote(int,char *,int,int *);

extern void ipc_tryreservein(int,int);

#endif
