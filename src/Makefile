# Don't edit Makefile!  Use conf-* for configuration.

SHELL=/bin/sh

default: it

clean:
	rm -f alloc.o alloc_re.o auto-str auto-str.o auto_home.c auto_home.o \
	buffer.o buffer_0.o buffer_1.o buffer_2.o buffer_copy.o buffer_get.o \
	buffer_put.o buffer_read.o buffer_write.o byte_chr.o byte_copy.o \
	byte_cr.o byte_diff.o byte_zero.o ccperl cdb.o cdb_hash.o cdb_make.o \
	chkshsgr chkshsgr.o choose choosing coe.o compile connect-io \
	connect-io.o env.o error.o error_str.o fd_copy.o fd_move.o fd_shutdown.o \
	fmt_ulong.o fork.h generic-conf.o getgid getgid.o getln.o getln2.o \
	getpeereid.c getpeereid.o getuid getuid.o hasflock.h hassgact.h \
	hassgprm.h hasshsgr.h haswaitp.h iopause.h iopause.o iopause_proxy.o \
	ipc_accept.o ipc_bind.o ipc_conn.o ipc_eid.o ipc_listen.o ipc_local.o \
	ipc_stream.o ipccat ipcclient ipcclient.o ipccommand ipccommand.o \
	ipcconnect ipcdo ipcexec ipcexec-config ipcexec-config.o ipcexec.o \
	ipcexecrules ipcexecrules.o ipcexecrulescheck ipcexecrulescheck.o \
	ipchandle.o ipcpath.h ipcperl ipcperl.o ipcprint ipcprint.o ipcrules \
	ipcrules.o ipcrulescheck ipcrulescheck.o ipcrun ipcserver ipcserver.o it \
	load lock_ex.o lock_un.o makeinclude makelib makescrip ndelay_off.o \
	ndelay_on.o open_append.o open_read.o open_trunc.o pathexec_env.o \
	pathexec_run.o perlembed.lib prot.o rules.o scan_uint.o scan_ulong.o \
	seek_set.o select.h sgetopt.o sig.o sig_block.o sig_catch.o sig_pause.o \
	socket.lib str_chr.o str_diff.o str_len.o str_start.o stralloc_cat.o \
	stralloc_catb.o stralloc_cats.o stralloc_copy.o stralloc_eady.o \
	stralloc_opyb.o stralloc_opys.o stralloc_pend.o strerr_die.o \
	strerr_sys.o subgetopt.o sysdeps systype tai_pack.o taia_add.o \
	taia_approx.o taia_frac.o taia_less.o taia_now.o taia_pack.o taia_sub.o \
	taia_uint.o tryipcpath tryipcpath.o uint32.h uint32_pack.o \
	uint32_unpack.o uint64.h unix.a wait_nohang.o wait_pid.o

alloc.o: compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

auto-str: load auto-str.o unix.a
	./load auto-str unix.a 

auto-str.o: compile auto-str.c buffer.h exit.h
	./compile auto-str.c

auto_home.c: auto-str home
	./auto-str auto_home "`head -1 home`" > auto_home.c

auto_home.o: compile auto_home.c
	./compile auto_home.c

buffer.o: compile buffer.c buffer.h
	./compile buffer.c

buffer_0.o: compile buffer_0.c buffer.h
	./compile buffer_0.c

buffer_1.o: compile buffer_1.c buffer.h
	./compile buffer_1.c

buffer_2.o: compile buffer_2.c buffer.h
	./compile buffer_2.c

buffer_copy.o: compile buffer_copy.c buffer.h
	./compile buffer_copy.c

buffer_get.o: compile buffer_get.c buffer.h byte.h error.h
	./compile buffer_get.c

buffer_put.o: compile buffer_put.c buffer.h str.h byte.h error.h
	./compile buffer_put.c

buffer_read.o: compile buffer_read.c buffer.h
	./compile buffer_read.c

buffer_write.o: compile buffer_write.c buffer.h
	./compile buffer_write.c

byte_chr.o: compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: compile byte_diff.c byte.h
	./compile byte_diff.c

byte_zero.o: compile byte_zero.c byte.h
	./compile byte_zero.c

ccperl: conf-ccperl conf-perl print-ccperl.sh
	rm -f ccperl
	sh print-ccperl.sh > ccperl

cdb.o: compile cdb.c error.h seek.h byte.h cdb.h uint32.h
	./compile cdb.c

cdb_hash.o: compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_make.o: compile cdb_make.c seek.h error.h alloc.h cdb.h cdb_make.h \
uint32.h buffer.h uint32.h
	./compile cdb_make.c

chkshsgr: load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: compile chkshsgr.c exit.h
	./compile chkshsgr.c

choose: makeinclude makescrip warn-auto.sh choose.sh
	rm -f choose
	./makeinclude code warn-auto.sh choose.sh \
	| ./makescrip choose choose choose.tmp \
	> choose
	chmod 755 choose

choosing: makeinclude makescrip warn-auto.sh choosing.sh
	rm -f choosing
	./makeinclude code warn-auto.sh choosing.sh \
	| ./makescrip choosing choosing choosing.tmp \
	> choosing
	chmod 755 choosing

coe.o: compile coe.c coe.h
	./compile coe.c

compile: conf-cc print-cc.sh systype warn-auto.sh
	rm -f compile
	sh print-cc.sh > compile
	chmod 755 compile

connect-io: load connect-io.o unix.a
	./load connect-io unix.a 

connect-io.o: compile connect-io.c exit.h iopause.h strerr.h scan.h \
ndelay.h sig.h taia.h tai.h uint64.h
	./compile connect-io.c

env.o: compile env.c str.h env.h
	./compile env.c

error.o: compile error.c error.h
	./compile error.c

error_str.o: compile error_str.c error.h
	./compile error_str.c

fd_copy.o: compile fd_copy.c fd.h
	./compile fd_copy.c

fd_move.o: compile fd_move.c fd.h
	./compile fd_move.c

fd_shutdown.o: compile fd_shutdown.c fd.h error.h
	./compile fd_shutdown.c

fmt_ulong.o: compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

fork.h: choose compile load tryvfork.c fork.h1 fork.h2
	./choose cl tryvfork fork.h1 fork.h2 >fork.h

generic-conf.o: compile generic-conf.c strerr.h buffer.h open.h \
generic-conf.h buffer.h
	./compile generic-conf.c

getgid: load getgid.o unix.a
	./load getgid unix.a 

getgid.o: compile getgid.c strerr.h fmt.h buffer.h exit.h
	./compile getgid.c

getln.o: compile getln.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln.c

getln2.o: compile getln2.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln2.c

getpeereid.c: systype compile load choosing trygpid.c trysopc.c \
getpeereid.so_peercred getpeereid.syscall getpeereid.oops
	./choosing c trysopc getpeereid.so_peercred >getpeereid.c \
	|| ./choosing cl trygpid getpeereid.syscall >getpeereid.c \
	|| cat getpeereid.oops > getpeereid.c

getpeereid.o: compile getpeereid.c
	./compile getpeereid.c

getuid: load getuid.o unix.a
	./load getuid unix.a 

getuid.o: compile getuid.c strerr.h fmt.h buffer.h exit.h
	./compile getuid.c

hasflock.h: choose compile load tryflock.c hasflock.h1 hasflock.h2
	./choose cl tryflock hasflock.h1 hasflock.h2 > hasflock.h

hassgact.h: choose compile trysgact.c hassgact.h1 hassgact.h2
	./choose cl trysgact hassgact.h1 hassgact.h2 > hassgact.h

hassgprm.h: choose compile trysgprm.c hassgprm.h1 hassgprm.h2
	./choose cl trysgprm hassgprm.h1 hassgprm.h2 > hassgprm.h

hasshsgr.h: choose compile tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

haswaitp.h: choose compile load trywaitp.c haswaitp.h1 haswaitp.h2
	./choose cl trywaitp haswaitp.h1 haswaitp.h2 >haswaitp.h

iopause.h: choose compile load trypoll.c iopause.h1 iopause.h2
	./choose clr trypoll iopause.h1 iopause.h2 >iopause.h

iopause.o: compile iopause.c taia.h select.h iopause.h tai.h taia.h \
uint64.h tai.h uint64.h
	./compile iopause.c

iopause_proxy.o: compile iopause_proxy.c iopause.h buffer.h fd.h error.h \
taia.h tai.h uint64.h
	./compile iopause_proxy.c

ipc_accept.o: compile ipc_accept.c byte.h ipc.h
	./compile ipc_accept.c

ipc_bind.o: compile ipc_bind.c error.h byte.h str.h ipc.h ipcpath.h
	./compile ipc_bind.c

ipc_conn.o: compile ipc_conn.c error.h byte.h str.h ndelay.h ipc.h \
ipcpath.h
	./compile ipc_conn.c

ipc_eid.o: compile ipc_eid.c getpeereid.h ipc.h
	./compile ipc_eid.c

ipc_listen.o: compile ipc_listen.c ipc.h
	./compile ipc_listen.c

ipc_local.o: compile ipc_local.c byte.h ipc.h
	./compile ipc_local.c

ipc_stream.o: compile ipc_stream.c ndelay.h ipc.h
	./compile ipc_stream.c

ipccat: makeinclude makescrip warn-auto.sh ipccat.sh
	rm -f ipccat
	./makeinclude code warn-auto.sh ipccat.sh \
	| ./makescrip ipccat ipccat ipccat.tmp \
	> ipccat
	chmod 755 ipccat

ipcclient: load ipcclient.o unix.a socket.lib
	./load ipcclient unix.a  `cat socket.lib`

ipcclient.o: compile ipcclient.c sig.h exit.h sgetopt.h str.h ipc.h \
ipcpath.h fd.h buffer.h error.h strerr.h pathexec.h subgetopt.h
	./compile ipcclient.c

ipccommand: load ipccommand.o unix.a
	./load ipccommand unix.a 

ipccommand.o: compile ipccommand.c sig.h wait.h fork.h fmt.h scan.h \
buffer.h strerr.h str.h exit.h
	./compile ipccommand.c

ipcconnect: makeinclude makescrip warn-auto.sh ipcconnect.sh
	rm -f ipcconnect
	./makeinclude code warn-auto.sh ipcconnect.sh \
	| ./makescrip ipcconnect ipcconnect ipcconnect.tmp \
	> ipcconnect
	chmod 755 ipcconnect

ipcdo: makeinclude makescrip warn-auto.sh ipcdo.sh
	rm -f ipcdo
	./makeinclude code warn-auto.sh ipcdo.sh \
	| ./makescrip ipcdo ipcdo ipcdo.tmp \
	> ipcdo
	chmod 755 ipcdo

ipcexec: load ipcexec.o unix.a
	./load ipcexec unix.a 

ipcexec-config: load ipcexec-config.o unix.a auto_home.o
	./load ipcexec-config unix.a auto_home.o 

ipcexec-config.o: compile ipcexec-config.c strerr.h exit.h auto_home.h \
generic-conf.h fmt.h buffer.h
	./compile ipcexec-config.c

ipcexec.o: compile ipcexec.c str.h byte.h fmt.h scan.h exit.h prot.h \
open.h stralloc.h alloc.h buffer.h error.h strerr.h env.h pathexec.h \
rules.h fd.h gen_alloc.h stralloc.h gen_alloc.h
	./compile ipcexec.c

ipcexecrules: load ipcexecrules.o unix.a
	./load ipcexecrules unix.a 

ipcexecrules.o: compile ipcexecrules.c strerr.h stralloc.h getln.h \
buffer.h exit.h fmt.h scan.h byte.h cdb_make.h open.h gen_alloc.h \
buffer.h stralloc.h buffer.h uint32.h gen_alloc.h
	./compile ipcexecrules.c

ipcexecrulescheck: load ipcexecrulescheck.o unix.a
	./load ipcexecrulescheck unix.a 

ipcexecrulescheck.o: compile ipcexecrulescheck.c byte.h buffer.h strerr.h \
env.h rules.h stralloc.h open.h exit.h stralloc.h gen_alloc.h gen_alloc.h
	./compile ipcexecrulescheck.c

ipchandle.o: compile ipchandle.c uint16.h str.h byte.h fmt.h scan.h ip4.h \
fd.h exit.h env.h prot.h open.h wait.h stralloc.h alloc.h buffer.h \
error.h strerr.h sgetopt.h ipc.h ipcpath.h ndelay.h rules.h sig.h \
iopause.h coe.h lock.h gen_alloc.h subgetopt.h stralloc.h taia.h \
gen_alloc.h tai.h uint64.h
	./compile ipchandle.c

ipcpath.h: compile tryipcpath print-ipcpath.sh
	rm -f ipcpath.h
	sh print-ipcpath.sh > ipcpath.h

ipcperl: load ipcperl.o ipchandle.o unix.a socket.lib perlembed.lib
	./load ipcperl ipchandle.o unix.a  `cat socket.lib` `cat perlembed.lib`

ipcperl.o: compile ccperl ipcperl.c strerr.h stralloc.h str.h gen_alloc.h
	./compile `cat ccperl` ipcperl.c

ipcprint: load ipcprint.o ipchandle.o unix.a socket.lib
	./load ipcprint ipchandle.o unix.a  `cat socket.lib`

ipcprint.o: compile ipcprint.c buffer.h env.h
	./compile ipcprint.c

ipcrules: load ipcrules.o unix.a
	./load ipcrules unix.a 

ipcrules.o: compile ipcrules.c strerr.h stralloc.h getln.h buffer.h \
exit.h fmt.h byte.h cdb_make.h scan.h open.h gen_alloc.h buffer.h \
stralloc.h buffer.h uint32.h gen_alloc.h
	./compile ipcrules.c

ipcrulescheck: load ipcrulescheck.o unix.a
	./load ipcrulescheck unix.a 

ipcrulescheck.o: compile ipcrulescheck.c byte.h buffer.h strerr.h env.h \
open.h rules.h exit.h stralloc.h gen_alloc.h
	./compile ipcrulescheck.c

ipcrun: makeinclude makescrip warn-auto.sh ipcrun.sh
	rm -f ipcrun
	./makeinclude code warn-auto.sh ipcrun.sh \
	| ./makescrip ipcrun ipcrun ipcrun.tmp \
	> ipcrun
	chmod 755 ipcrun

ipcserver: load ipcserver.o unix.a socket.lib
	./load ipcserver unix.a  `cat socket.lib`

ipcserver.o: compile ipcserver.c str.h byte.h fmt.h scan.h fd.h exit.h \
env.h prot.h open.h wait.h stralloc.h alloc.h buffer.h error.h strerr.h \
sgetopt.h pathexec.h ipc.h ipcpath.h rules.h sig.h ndelay.h gen_alloc.h \
subgetopt.h stralloc.h gen_alloc.h
	./compile ipcserver.c

it: sysdeps ipcclient ipcserver ipccat ipcconnect ipcrules ipcrulescheck \
ipcexecrules ipcexecrulescheck ipcdo ipccommand ipcexec ipcrun \
ipcexec-config ipcprint getuid getgid connect-io ipcperl

load: conf-ld print-ld.sh systype warn-auto.sh
	rm -f load
	sh print-ld.sh > load
	chmod 755 load

lock_ex.o: compile lock_ex.c hasflock.h lock.h
	./compile lock_ex.c

lock_un.o: compile lock_un.c hasflock.h lock.h
	./compile lock_un.c

makeinclude: makeinclude.sh warn-auto.sh
	rm -f makeinclude
	cat warn-auto.sh makeinclude.sh > makeinclude
	chmod 755 makeinclude

makelib: print-ar.sh systype warn-auto.sh
	rm -f makelib
	sh print-ar.sh > makelib
	chmod 755 makelib

makescrip: warn-auto.sh print-makescrip.sh conf-scrip home conf-ipcexec
	rm -f makescrip
	sh print-makescrip.sh < conf-scrip > makescrip
	chmod 755 makescrip

ndelay_off.o: compile ndelay_off.c ndelay.h
	./compile ndelay_off.c

ndelay_on.o: compile ndelay_on.c ndelay.h
	./compile ndelay_on.c

open_append.o: compile open_append.c open.h
	./compile open_append.c

open_read.o: compile open_read.c open.h
	./compile open_read.c

open_trunc.o: compile open_trunc.c open.h
	./compile open_trunc.c

pathexec_env.o: compile pathexec_env.c stralloc.h alloc.h str.h byte.h \
env.h pathexec.h gen_alloc.h
	./compile pathexec_env.c

pathexec_run.o: compile pathexec_run.c error.h stralloc.h str.h env.h \
pathexec.h gen_alloc.h
	./compile pathexec_run.c

perlembed.lib: conf-perl conf-ldperl print-perlembed.sh
	rm -f perlembed.lib
	sh print-ldperl.sh > perlembed.lib

prot.o: compile prot.c hasshsgr.h prot.h
	./compile prot.c

rules.o: compile rules.c alloc.h stralloc.h open.h cdb.h rules.h \
gen_alloc.h uint32.h stralloc.h gen_alloc.h
	./compile rules.c

scan_uint.o: compile scan_uint.c scan.h
	./compile scan_uint.c

scan_ulong.o: compile scan_ulong.c scan.h
	./compile scan_ulong.c

seek_set.o: compile seek_set.c seek.h
	./compile seek_set.c

select.h: choose compile trysysel.c select.h1 select.h2
	./choose c trysysel select.h1 select.h2 > select.h

sgetopt.o: compile sgetopt.c buffer.h sgetopt.h subgetopt.h subgetopt.h
	./compile sgetopt.c

sig.o: compile sig.c sig.h
	./compile sig.c

sig_block.o: compile sig_block.c sig.h hassgprm.h
	./compile sig_block.c

sig_catch.o: compile sig_catch.c sig.h hassgact.h
	./compile sig_catch.c

sig_pause.o: compile sig_pause.c sig.h hassgprm.h
	./compile sig_pause.c

socket.lib: trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

str_chr.o: compile str_chr.c str.h
	./compile str_chr.c

str_diff.o: compile str_diff.c str.h
	./compile str_diff.c

str_len.o: compile str_len.c str.h
	./compile str_len.c

str_start.o: compile str_start.c str.h
	./compile str_start.c

stralloc_cat.o: compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: compile stralloc_catb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_catb.c

stralloc_cats.o: compile stralloc_cats.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: compile stralloc_eady.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_eady.c

stralloc_opyb.o: compile stralloc_opyb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_opyb.c

stralloc_opys.o: compile stralloc_opys.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: compile stralloc_pend.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_pend.c

strerr_die.o: compile strerr_die.c buffer.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

subgetopt.o: compile subgetopt.c subgetopt.h
	./compile subgetopt.c

sysdeps: systype compile load
	rm -f sysdeps
	cat systype compile load >> sysdeps
	grep sysdep *.h 2>/dev/null >> sysdeps || :

systype: find-systype.sh trycpp.c x86cpuid.c
	sh find-systype.sh > systype

tai_pack.o: compile tai_pack.c tai.h uint64.h
	./compile tai_pack.c

taia_add.o: compile taia_add.c taia.h tai.h uint64.h
	./compile taia_add.c

taia_approx.o: compile taia_approx.c taia.h tai.h uint64.h
	./compile taia_approx.c

taia_frac.o: compile taia_frac.c taia.h tai.h uint64.h
	./compile taia_frac.c

taia_less.o: compile taia_less.c taia.h tai.h uint64.h
	./compile taia_less.c

taia_now.o: compile taia_now.c taia.h tai.h uint64.h
	./compile taia_now.c

taia_pack.o: compile taia_pack.c taia.h tai.h uint64.h
	./compile taia_pack.c

taia_sub.o: compile taia_sub.c taia.h tai.h uint64.h
	./compile taia_sub.c

taia_uint.o: compile taia_uint.c taia.h tai.h uint64.h
	./compile taia_uint.c

tryipcpath: load tryipcpath.o fmt_ulong.o
	./load tryipcpath fmt_ulong.o 

tryipcpath.o: compile tryipcpath.c fmt.h
	./compile tryipcpath.c

uint32.h: choose compile load tryulong32.c uint32.h1 uint32.h2
	./choose clr tryulong32 uint32.h1 uint32.h2 >uint32.h

uint32_pack.o: compile uint32_pack.c uint32.h
	./compile uint32_pack.c

uint32_unpack.o: compile uint32_unpack.c uint32.h
	./compile uint32_unpack.c

uint64.h: choose compile load tryulong64.c uint64.h1 uint64.h2
	./choose clr tryulong64 uint64.h1 uint64.h2 >uint64.h

unix.a: makelib alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o \
buffer_2.o buffer_get.o buffer_put.o buffer_copy.o buffer_read.o \
buffer_write.o env.o error.o error_str.o fd_copy.o fd_move.o \
fd_shutdown.o fmt_ulong.o scan_ulong.o scan_uint.o getln.o getln2.o \
ipc_accept.o ipc_bind.o ipc_conn.o ipc_listen.o ipc_local.o ipc_eid.o \
ipc_stream.o ndelay_on.o ndelay_off.o open_read.o open_trunc.o \
open_append.o pathexec_env.o pathexec_run.o prot.o seek_set.o sgetopt.o \
sig.o sig_block.o sig_catch.o sig_pause.o str_chr.o str_diff.o str_len.o \
str_start.o stralloc_cat.o stralloc_catb.o stralloc_cats.o \
stralloc_copy.o stralloc_eady.o stralloc_opyb.o stralloc_opys.o \
stralloc_pend.o strerr_die.o strerr_sys.o subgetopt.o wait_nohang.o \
wait_pid.o iopause.o iopause_proxy.o tai_pack.o taia_add.o taia_approx.o \
taia_frac.o taia_less.o taia_now.o taia_pack.o taia_sub.o taia_uint.o \
getpeereid.o cdb.o cdb_hash.o cdb_make.o byte_zero.o byte_copy.o \
byte_chr.o byte_diff.o byte_cr.o rules.o uint32_pack.o uint32_unpack.o \
generic-conf.o lock_ex.o lock_un.o coe.o
	./makelib unix.a alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o \
	buffer_2.o buffer_get.o buffer_put.o buffer_copy.o buffer_read.o \
	buffer_write.o env.o error.o error_str.o fd_copy.o fd_move.o \
	fd_shutdown.o fmt_ulong.o scan_ulong.o scan_uint.o getln.o getln2.o \
	ipc_accept.o ipc_bind.o ipc_conn.o ipc_listen.o ipc_local.o ipc_eid.o \
	ipc_stream.o ndelay_on.o ndelay_off.o open_read.o open_trunc.o \
	open_append.o pathexec_env.o pathexec_run.o prot.o seek_set.o sgetopt.o \
	sig.o sig_block.o sig_catch.o sig_pause.o str_chr.o str_diff.o str_len.o \
	str_start.o stralloc_cat.o stralloc_catb.o stralloc_cats.o \
	stralloc_copy.o stralloc_eady.o stralloc_opyb.o stralloc_opys.o \
	stralloc_pend.o strerr_die.o strerr_sys.o subgetopt.o wait_nohang.o \
	wait_pid.o iopause.o iopause_proxy.o tai_pack.o taia_add.o taia_approx.o \
	taia_frac.o taia_less.o taia_now.o taia_pack.o taia_sub.o taia_uint.o \
	getpeereid.o cdb.o cdb_hash.o cdb_make.o byte_zero.o byte_copy.o \
	byte_chr.o byte_diff.o byte_cr.o rules.o uint32_pack.o uint32_unpack.o \
	generic-conf.o lock_ex.o lock_un.o coe.o

wait_nohang.o: compile wait_nohang.c haswaitp.h
	./compile wait_nohang.c

wait_pid.o: compile wait_pid.c error.h haswaitp.h
	./compile wait_pid.c
