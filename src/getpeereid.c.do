dependon systype compile load choosing \
trygpid.c trysopc.c getpeereid.so_peercred getpeereid.syscall \
getpeereid.oops
formake './choosing c trysopc getpeereid.so_peercred >getpeereid.c \'
formake '|| ./choosing cl trygpid getpeereid.syscall >getpeereid.c \'
formake '|| cat getpeereid.oops > getpeereid.c'
./choosing c trysopc getpeereid.so_peercred \
|| ./choosing cl trygpid getpeereid.syscall \
|| cat getpeereid.oops
