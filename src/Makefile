default: \
it

wait_pid.o: \
makefile.build \
error.h \
default.o.build \
wait_pid.c \
compile \
haswaitp.h
	sh makefile.build default.o.build wait_pid.o wait_pid

wait_nohang.o: \
makefile.build \
default.o.build \
wait_nohang.c \
compile \
haswaitp.h
	sh makefile.build default.o.build wait_nohang.o wait_nohang

unix.a: \
makefile.build \
default.a.build \
makelib \
unix=l \
coe.o \
lock_un.o \
lock_ex.o \
generic-conf.o \
uint32_unpack.o \
uint32_pack.o \
rules.o \
byte_cr.o \
byte_diff.o \
byte_chr.o \
byte_copy.o \
byte_zero.o \
cdb_make.o \
cdb_hash.o \
cdb.o \
getpeereid.o \
taia_uint.o \
taia_sub.o \
taia_pack.o \
taia_now.o \
taia_less.o \
taia_frac.o \
taia_approx.o \
taia_add.o \
tai_pack.o \
iopause_proxy.o \
iopause.o \
wait_pid.o \
wait_nohang.o \
subgetopt.o \
strerr_sys.o \
strerr_die.o \
stralloc_pend.o \
stralloc_opys.o \
stralloc_opyb.o \
stralloc_eady.o \
stralloc_copy.o \
stralloc_cats.o \
stralloc_catb.o \
stralloc_cat.o \
str_start.o \
str_len.o \
str_diff.o \
str_chr.o \
sig_pause.o \
sig_catch.o \
sig_block.o \
sig.o \
sgetopt.o \
seek_set.o \
prot.o \
pathexec_run.o \
pathexec_env.o \
open_append.o \
open_trunc.o \
open_read.o \
ndelay_off.o \
ndelay_on.o \
ipc_stream.o \
ipc_eid.o \
ipc_local.o \
ipc_listen.o \
ipc_conn.o \
ipc_bind.o \
ipc_accept.o \
getln2.o \
getln.o \
scan_uint.o \
scan_ulong.o \
fmt_ulong.o \
fd_shutdown.o \
fd_move.o \
fd_copy.o \
error_str.o \
error.o \
env.o \
buffer_write.o \
buffer_read.o \
buffer_copy.o \
buffer_put.o \
buffer_get.o \
buffer_2.o \
buffer_1.o \
buffer_0.o \
buffer.o \
alloc_re.o \
alloc.o
	sh makefile.build default.a.build unix.a unix

uint64.h: \
makefile.build \
uint64.h.build \
uint64.h2 \
uint64.h1 \
tryulong64.c \
load \
compile \
choose
	sh makefile.build uint64.h.build uint64.h 

uint32_unpack.o: \
makefile.build \
default.o.build \
uint32_unpack.c \
compile \
uint32.h
	sh makefile.build default.o.build uint32_unpack.o uint32_unpack

uint32_pack.o: \
makefile.build \
default.o.build \
uint32_pack.c \
compile \
uint32.h
	sh makefile.build default.o.build uint32_pack.o uint32_pack

uint32.h: \
makefile.build \
uint32.h.build \
uint32.h2 \
uint32.h1 \
tryulong32.c \
load \
compile \
choose
	sh makefile.build uint32.h.build uint32.h 

tryipcpath.o: \
makefile.build \
fmt.h \
default.o.build \
tryipcpath.c \
compile
	sh makefile.build default.o.build tryipcpath.o tryipcpath

tryipcpath: \
makefile.build \
tryipcpath=x \
default.build \
fmt_ulong.o \
tryipcpath.o \
load
	sh makefile.build default.build tryipcpath tryipcpath

taia_uint.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_uint.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_uint.o taia_uint

taia_sub.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_sub.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_sub.o taia_sub

taia_pack.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_pack.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_pack.o taia_pack

taia_now.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_now.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_now.o taia_now

taia_less.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_less.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_less.o taia_less

taia_frac.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_frac.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_frac.o taia_frac

taia_approx.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_approx.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_approx.o taia_approx

taia_add.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
taia_add.c \
compile \
uint64.h
	sh makefile.build default.o.build taia_add.o taia_add

tai_pack.o: \
makefile.build \
tai.h \
default.o.build \
tai_pack.c \
compile \
uint64.h
	sh makefile.build default.o.build tai_pack.o tai_pack

systype: \
makefile.build \
x86cpuid.c \
trycpp.c \
find-systype.sh \
default.build
	sh makefile.build default.build systype systype

sysdeps: \
makefile.build \
default.build \
uint64.h \
select.h \
iopause.h \
haswaitp.h \
hasshsgr.h \
hassgprm.h \
hassgact.h \
hasflock.h \
fork.h \
load \
compile \
systype
	sh makefile.build default.build sysdeps sysdeps

subgetopt.o: \
makefile.build \
subgetopt.h \
default.o.build \
subgetopt.c \
compile
	sh makefile.build default.o.build subgetopt.o subgetopt

strerr_sys.o: \
makefile.build \
strerr.h \
error.h \
default.o.build \
strerr_sys.c \
compile
	sh makefile.build default.o.build strerr_sys.o strerr_sys

strerr_die.o: \
makefile.build \
strerr.h \
exit.h \
buffer.h \
default.o.build \
strerr_die.c \
compile
	sh makefile.build default.o.build strerr_die.o strerr_die

stralloc_pend.o: \
makefile.build \
gen_alloc.h \
gen_allocdefs.h \
stralloc.h \
alloc.h \
default.o.build \
stralloc_pend.c \
compile
	sh makefile.build default.o.build stralloc_pend.o stralloc_pend

stralloc_opys.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
str.h \
byte.h \
default.o.build \
stralloc_opys.c \
compile
	sh makefile.build default.o.build stralloc_opys.o stralloc_opys

stralloc_opyb.o: \
makefile.build \
gen_alloc.h \
byte.h \
stralloc.h \
default.o.build \
stralloc_opyb.c \
compile
	sh makefile.build default.o.build stralloc_opyb.o stralloc_opyb

stralloc_eady.o: \
makefile.build \
gen_alloc.h \
gen_allocdefs.h \
stralloc.h \
alloc.h \
default.o.build \
stralloc_eady.c \
compile
	sh makefile.build default.o.build stralloc_eady.o stralloc_eady

stralloc_copy.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
byte.h \
default.o.build \
stralloc_copy.c \
compile
	sh makefile.build default.o.build stralloc_copy.o stralloc_copy

stralloc_cats.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
str.h \
byte.h \
default.o.build \
stralloc_cats.c \
compile
	sh makefile.build default.o.build stralloc_cats.o stralloc_cats

stralloc_catb.o: \
makefile.build \
gen_alloc.h \
byte.h \
stralloc.h \
default.o.build \
stralloc_catb.c \
compile
	sh makefile.build default.o.build stralloc_catb.o stralloc_catb

stralloc_cat.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
byte.h \
default.o.build \
stralloc_cat.c \
compile
	sh makefile.build default.o.build stralloc_cat.o stralloc_cat

str_start.o: \
makefile.build \
str.h \
default.o.build \
str_start.c \
compile
	sh makefile.build default.o.build str_start.o str_start

str_len.o: \
makefile.build \
str.h \
default.o.build \
str_len.c \
compile
	sh makefile.build default.o.build str_len.o str_len

str_diff.o: \
makefile.build \
str.h \
default.o.build \
str_diff.c \
compile
	sh makefile.build default.o.build str_diff.o str_diff

str_chr.o: \
makefile.build \
str.h \
default.o.build \
str_chr.c \
compile
	sh makefile.build default.o.build str_chr.o str_chr

socket.lib: \
makefile.build \
default.lib.build \
load \
compile \
trylsock.c
	sh makefile.build default.lib.build socket.lib socket

sig_pause.o: \
makefile.build \
sig.h \
default.o.build \
sig_pause.c \
compile \
hassgprm.h
	sh makefile.build default.o.build sig_pause.o sig_pause

sig_catch.o: \
makefile.build \
sig.h \
default.o.build \
hassgact.h \
sig_catch.c \
compile
	sh makefile.build default.o.build sig_catch.o sig_catch

sig_block.o: \
makefile.build \
sig.h \
default.o.build \
hassgprm.h \
sig_block.c \
compile
	sh makefile.build default.o.build sig_block.o sig_block

sig.o: \
makefile.build \
sig.h \
default.o.build \
sig.c \
compile
	sh makefile.build default.o.build sig.o sig

sgetopt.o: \
makefile.build \
subgetopt.h \
sgetopt.h \
buffer.h \
default.o.build \
sgetopt.c \
compile
	sh makefile.build default.o.build sgetopt.o sgetopt

select.h: \
makefile.build \
select.h.build \
select.h2 \
select.h1 \
trysysel.c \
compile \
choose
	sh makefile.build select.h.build select.h 

seek_set.o: \
makefile.build \
seek.h \
default.o.build \
seek_set.c \
compile
	sh makefile.build default.o.build seek_set.o seek_set

scan_ulong.o: \
makefile.build \
scan.h \
default.o.build \
scan_ulong.c \
compile
	sh makefile.build default.o.build scan_ulong.o scan_ulong

scan_uint.o: \
makefile.build \
scan.h \
default.o.build \
scan_uint.c \
compile
	sh makefile.build default.o.build scan_uint.o scan_uint

rules.o: \
makefile.build \
gen_alloc.h \
rules.h \
cdb.h \
open.h \
stralloc.h \
alloc.h \
default.o.build \
rules.c \
compile \
uint32.h
	sh makefile.build default.o.build rules.o rules

prot.o: \
makefile.build \
prot.h \
default.o.build \
prot.c \
compile \
hasshsgr.h
	sh makefile.build default.o.build prot.o prot

perlembed.lib: \
makefile.build \
print-perlembed.sh \
conf-ldperl \
conf-perl \
perlembed.lib.build
	sh makefile.build perlembed.lib.build perlembed.lib 

pathexec_run.o: \
makefile.build \
gen_alloc.h \
pathexec.h \
env.h \
str.h \
stralloc.h \
error.h \
default.o.build \
pathexec_run.c \
compile
	sh makefile.build default.o.build pathexec_run.o pathexec_run

pathexec_env.o: \
makefile.build \
gen_alloc.h \
pathexec.h \
env.h \
byte.h \
str.h \
alloc.h \
stralloc.h \
default.o.build \
pathexec_env.c \
compile
	sh makefile.build default.o.build pathexec_env.o pathexec_env

open_trunc.o: \
makefile.build \
open.h \
default.o.build \
open_trunc.c \
compile
	sh makefile.build default.o.build open_trunc.o open_trunc

open_read.o: \
makefile.build \
open.h \
default.o.build \
open_read.c \
compile
	sh makefile.build default.o.build open_read.o open_read

open_append.o: \
makefile.build \
open.h \
default.o.build \
open_append.c \
compile
	sh makefile.build default.o.build open_append.o open_append

ndelay_on.o: \
makefile.build \
ndelay.h \
default.o.build \
ndelay_on.c \
compile
	sh makefile.build default.o.build ndelay_on.o ndelay_on

ndelay_off.o: \
makefile.build \
ndelay.h \
default.o.build \
ndelay_off.c \
compile
	sh makefile.build default.o.build ndelay_off.o ndelay_off

makescrip: \
makefile.build \
conf-ipcexec \
home \
conf-scrip \
print-makescrip.sh \
warn-auto.sh \
default.build
	sh makefile.build default.build makescrip makescrip

makelib: \
makefile.build \
default.build \
warn-auto.sh \
systype \
print-ar.sh
	sh makefile.build default.build makelib makelib

makeinclude: \
makefile.build \
warn-auto.sh \
makeinclude.sh \
default.build
	sh makefile.build default.build makeinclude makeinclude

lock_un.o: \
makefile.build \
lock.h \
default.o.build \
lock_un.c \
compile \
hasflock.h
	sh makefile.build default.o.build lock_un.o lock_un

lock_ex.o: \
makefile.build \
lock.h \
default.o.build \
lock_ex.c \
compile \
hasflock.h
	sh makefile.build default.o.build lock_ex.o lock_ex

load: \
makefile.build \
warn-auto.sh \
print-load.sh \
conf-ld \
default.build
	sh makefile.build default.build load load

it: \
makefile.build \
sysdeps \
ipcperl \
ipcaccept \
ipclisten \
connect-io \
getgid \
getuid \
ipcprint \
ipcexec-config \
ipcrun \
ipcexec \
ipccommand \
ipcdo \
ipcexecrulescheck \
ipcexecrules \
ipcrulescheck \
ipcrules \
ipcconnect \
ipccat \
ipcserver \
ipcclient \
it=d \
default.build
	sh makefile.build default.build it it

ipcserver.o: \
makefile.build \
subgetopt.h \
gen_alloc.h \
ndelay.h \
sig.h \
rules.h \
ipc.h \
pathexec.h \
sgetopt.h \
strerr.h \
error.h \
buffer.h \
alloc.h \
stralloc.h \
wait.h \
open.h \
prot.h \
env.h \
exit.h \
fd.h \
scan.h \
fmt.h \
byte.h \
str.h \
default.o.build \
ipcserver.c \
compile \
fork.h \
ipcpath.h
	sh makefile.build default.o.build ipcserver.o ipcserver

ipcserver: \
makefile.build \
ipcserver=x \
default.build \
socket.lib \
unix.a \
ipcserver.o \
load
	sh makefile.build default.build ipcserver ipcserver

ipcrun: \
makefile.build \
ipcrun.sh \
warn-auto.sh \
ipcrun.sh \
warn-auto.sh \
default.build \
makescrip \
makeinclude \
ipcrun=s
	sh makefile.build default.build ipcrun ipcrun

ipcrulescheck.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
exit.h \
rules.h \
open.h \
env.h \
strerr.h \
buffer.h \
byte.h \
default.o.build \
ipcrulescheck.c \
compile
	sh makefile.build default.o.build ipcrulescheck.o ipcrulescheck

ipcrulescheck: \
makefile.build \
ipcrulescheck=x \
default.build \
unix.a \
ipcrulescheck.o \
load
	sh makefile.build default.build ipcrulescheck ipcrulescheck

ipcrules.o: \
makefile.build \
gen_alloc.h \
open.h \
scan.h \
cdb_make.h \
byte.h \
fmt.h \
exit.h \
buffer.h \
getln.h \
stralloc.h \
strerr.h \
default.o.build \
ipcrules.c \
compile \
uint32.h
	sh makefile.build default.o.build ipcrules.o ipcrules

ipcrules: \
makefile.build \
ipcrules=x \
default.build \
unix.a \
ipcrules.o \
load
	sh makefile.build default.build ipcrules ipcrules

ipcprint.o: \
makefile.build \
env.h \
buffer.h \
default.o.build \
ipcprint.c \
compile
	sh makefile.build default.o.build ipcprint.o ipcprint

ipcprint: \
makefile.build \
ipcprint=x \
default.build \
socket.lib \
unix.a \
ipchandle.o \
ipcprint.o \
load
	sh makefile.build default.build ipcprint ipcprint

ipcperl.o: \
makefile.build \
gen_alloc.h \
str.h \
stralloc.h \
strerr.h \
ipcperl.o.build \
ipcperl.c \
ccperl \
compile
	sh makefile.build ipcperl.o.build ipcperl.o 

ipcperl: \
makefile.build \
ipcperl=x \
default.build \
perlembed.lib \
socket.lib \
unix.a \
ipchandle.o \
ipcperl.o \
load
	sh makefile.build default.build ipcperl ipcperl

ipcpath.h: \
makefile.build \
ipcpath.h.build \
print-ipcpath.sh \
tryipcpath \
compile
	sh makefile.build ipcpath.h.build ipcpath.h 

ipclisten.o: \
makefile.build \
subgetopt.h \
gen_alloc.h \
ndelay.h \
sig.h \
ipc.h \
pathexec.h \
sgetopt.h \
strerr.h \
error.h \
buffer.h \
alloc.h \
stralloc.h \
wait.h \
open.h \
prot.h \
env.h \
exit.h \
fd.h \
scan.h \
fmt.h \
byte.h \
str.h \
default.o.build \
ipclisten.c \
compile \
fork.h \
ipcpath.h
	sh makefile.build default.o.build ipclisten.o ipclisten

ipclisten: \
makefile.build \
ipclisten=x \
default.build \
socket.lib \
unix.a \
ipclisten.o \
load
	sh makefile.build default.build ipclisten ipclisten

ipchandle.o: \
makefile.build \
tai.h \
taia.h \
subgetopt.h \
gen_alloc.h \
lock.h \
coe.h \
sig.h \
rules.h \
ndelay.h \
ipc.h \
sgetopt.h \
strerr.h \
error.h \
buffer.h \
alloc.h \
stralloc.h \
wait.h \
open.h \
prot.h \
env.h \
exit.h \
fd.h \
ip4.h \
scan.h \
fmt.h \
byte.h \
str.h \
uint16.h \
default.o.build \
ipchandle.c \
compile \
uint64.h \
iopause.h \
ipcpath.h
	sh makefile.build default.o.build ipchandle.o ipchandle

ipcexecrulescheck.o: \
makefile.build \
gen_alloc.h \
exit.h \
open.h \
stralloc.h \
rules.h \
env.h \
strerr.h \
buffer.h \
byte.h \
default.o.build \
ipcexecrulescheck.c \
compile
	sh makefile.build default.o.build ipcexecrulescheck.o ipcexecrulescheck

ipcexecrulescheck: \
makefile.build \
ipcexecrulescheck=x \
default.build \
unix.a \
ipcexecrulescheck.o \
load
	sh makefile.build default.build ipcexecrulescheck ipcexecrulescheck

ipcexecrules.o: \
makefile.build \
gen_alloc.h \
open.h \
cdb_make.h \
byte.h \
scan.h \
fmt.h \
exit.h \
buffer.h \
getln.h \
stralloc.h \
strerr.h \
default.o.build \
ipcexecrules.c \
compile \
uint32.h
	sh makefile.build default.o.build ipcexecrules.o ipcexecrules

ipcexecrules: \
makefile.build \
ipcexecrules=x \
default.build \
unix.a \
ipcexecrules.o \
load
	sh makefile.build default.build ipcexecrules ipcexecrules

ipcexec.o: \
makefile.build \
gen_alloc.h \
fd.h \
rules.h \
pathexec.h \
env.h \
strerr.h \
error.h \
buffer.h \
alloc.h \
stralloc.h \
open.h \
prot.h \
exit.h \
scan.h \
fmt.h \
byte.h \
str.h \
default.o.build \
ipcexec.c \
compile
	sh makefile.build default.o.build ipcexec.o ipcexec

ipcexec-config.o: \
makefile.build \
buffer.h \
fmt.h \
generic-conf.h \
auto_home.h \
exit.h \
strerr.h \
default.o.build \
ipcexec-config.c \
compile
	sh makefile.build default.o.build ipcexec-config.o ipcexec-config

ipcexec-config: \
makefile.build \
ipcexec-config=x \
default.build \
auto_home.o \
unix.a \
ipcexec-config.o \
load
	sh makefile.build default.build ipcexec-config ipcexec-config

ipcexec: \
makefile.build \
ipcexec=x \
default.build \
unix.a \
ipcexec.o \
load
	sh makefile.build default.build ipcexec ipcexec

ipcdo: \
makefile.build \
ipcdo.sh \
warn-auto.sh \
ipcdo.sh \
warn-auto.sh \
default.build \
makescrip \
makeinclude \
ipcdo=s
	sh makefile.build default.build ipcdo ipcdo

ipcconnect: \
makefile.build \
ipcconnect.sh \
warn-auto.sh \
ipcconnect.sh \
warn-auto.sh \
default.build \
makescrip \
makeinclude \
ipcconnect=s
	sh makefile.build default.build ipcconnect ipcconnect

ipccommand.o: \
makefile.build \
exit.h \
str.h \
strerr.h \
buffer.h \
scan.h \
fmt.h \
wait.h \
sig.h \
default.o.build \
ipccommand.c \
compile \
fork.h
	sh makefile.build default.o.build ipccommand.o ipccommand

ipccommand: \
makefile.build \
ipccommand=x \
default.build \
unix.a \
ipccommand.o \
load
	sh makefile.build default.build ipccommand ipccommand

ipcclient.o: \
makefile.build \
subgetopt.h \
pathexec.h \
strerr.h \
error.h \
buffer.h \
fd.h \
ipc.h \
str.h \
sgetopt.h \
exit.h \
sig.h \
ipcclient.c \
compile \
default.o.build \
ipcpath.h
	sh makefile.build default.o.build ipcclient.o ipcclient

ipcclient: \
makefile.build \
socket.lib \
unix.a \
ipcclient.o \
load \
ipcclient=x \
default.build
	sh makefile.build default.build ipcclient ipcclient

ipccat: \
makefile.build \
ipccat.sh \
warn-auto.sh \
ipccat.sh \
warn-auto.sh \
default.build \
makescrip \
makeinclude \
ipccat=s
	sh makefile.build default.build ipccat ipccat

ipcaccept.o: \
makefile.build \
subgetopt.h \
gen_alloc.h \
lock.h \
ndelay.h \
sig.h \
rules.h \
ipc.h \
pathexec.h \
sgetopt.h \
strerr.h \
error.h \
buffer.h \
alloc.h \
stralloc.h \
wait.h \
open.h \
prot.h \
env.h \
exit.h \
fd.h \
scan.h \
fmt.h \
byte.h \
str.h \
default.o.build \
ipcaccept.c \
compile \
fork.h \
ipcpath.h
	sh makefile.build default.o.build ipcaccept.o ipcaccept

ipcaccept: \
makefile.build \
ipcaccept=x \
default.build \
socket.lib \
unix.a \
ipcaccept.o \
load
	sh makefile.build default.build ipcaccept ipcaccept

ipc_stream.o: \
makefile.build \
ipc.h \
ndelay.h \
default.o.build \
ipc_stream.c \
compile
	sh makefile.build default.o.build ipc_stream.o ipc_stream

ipc_local.o: \
makefile.build \
ipc.h \
byte.h \
default.o.build \
ipc_local.c \
compile
	sh makefile.build default.o.build ipc_local.o ipc_local

ipc_listen.o: \
makefile.build \
ipc.h \
default.o.build \
ipc_listen.c \
compile
	sh makefile.build default.o.build ipc_listen.o ipc_listen

ipc_eid.o: \
makefile.build \
ipc.h \
getpeereid.h \
default.o.build \
ipc_eid.c \
compile
	sh makefile.build default.o.build ipc_eid.o ipc_eid

ipc_conn.o: \
makefile.build \
ipc.h \
ndelay.h \
str.h \
byte.h \
error.h \
default.o.build \
ipc_conn.c \
compile \
ipcpath.h
	sh makefile.build default.o.build ipc_conn.o ipc_conn

ipc_bind.o: \
makefile.build \
ipc.h \
str.h \
byte.h \
error.h \
default.o.build \
ipc_bind.c \
compile \
ipcpath.h
	sh makefile.build default.o.build ipc_bind.o ipc_bind

ipc_accept.o: \
makefile.build \
ipc.h \
byte.h \
default.o.build \
ipc_accept.c \
compile
	sh makefile.build default.o.build ipc_accept.o ipc_accept

iopause_proxy.o: \
makefile.build \
tai.h \
taia.h \
error.h \
fd.h \
buffer.h \
default.o.build \
iopause_proxy.c \
compile \
uint64.h \
iopause.h
	sh makefile.build default.o.build iopause_proxy.o iopause_proxy

iopause.o: \
makefile.build \
tai.h \
taia.h \
default.o.build \
select.h \
iopause.c \
compile \
uint64.h \
iopause.h
	sh makefile.build default.o.build iopause.o iopause

iopause.h: \
makefile.build \
iopause.h.build \
iopause.h2 \
iopause.h1 \
trypoll.c \
load \
compile \
choose
	sh makefile.build iopause.h.build iopause.h 

haswaitp.h: \
makefile.build \
haswaitp.h.build \
haswaitp.h2 \
haswaitp.h1 \
trywaitp.c \
load \
compile \
choose
	sh makefile.build haswaitp.h.build haswaitp.h 

hasshsgr.h: \
makefile.build \
hasshsgr.h.build \
warn-shsgr \
chkshsgr \
hasshsgr.h2 \
hasshsgr.h1 \
tryshsgr.c \
compile \
choose
	sh makefile.build hasshsgr.h.build hasshsgr.h 

hassgprm.h: \
makefile.build \
hassgprm.h.build \
hassgprm.h2 \
hassgprm.h1 \
trysgprm.c \
compile \
choose
	sh makefile.build hassgprm.h.build hassgprm.h 

hassgact.h: \
makefile.build \
hassgact.h.build \
hassgact.h2 \
hassgact.h1 \
trysgact.c \
compile \
choose
	sh makefile.build hassgact.h.build hassgact.h 

hasflock.h: \
makefile.build \
hasflock.h.build \
hasflock.h2 \
hasflock.h1 \
tryflock.c \
load \
compile \
choose
	sh makefile.build hasflock.h.build hasflock.h 

getuid.o: \
makefile.build \
exit.h \
buffer.h \
fmt.h \
strerr.h \
default.o.build \
getuid.c \
compile
	sh makefile.build default.o.build getuid.o getuid

getuid: \
makefile.build \
getuid=x \
default.build \
unix.a \
getuid.o \
load
	sh makefile.build default.build getuid getuid

getpeereid.o: \
makefile.build \
default.o.build \
getpeereid.c \
compile
	sh makefile.build default.o.build getpeereid.o getpeereid

getpeereid.c: \
makefile.build \
getpeereid.oops \
getpeereid.syscall \
getpeereid.so_peercred \
getpeereid.c.build \
trysopc.c \
trygpid.c \
choosing \
load \
compile \
systype
	sh makefile.build getpeereid.c.build getpeereid.c 

getln2.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
buffer.h \
getln.h \
byte.h \
default.o.build \
getln2.c \
compile
	sh makefile.build default.o.build getln2.o getln2

getln.o: \
makefile.build \
gen_alloc.h \
stralloc.h \
buffer.h \
getln.h \
byte.h \
default.o.build \
getln.c \
compile
	sh makefile.build default.o.build getln.o getln

getgid.o: \
makefile.build \
exit.h \
buffer.h \
fmt.h \
strerr.h \
default.o.build \
getgid.c \
compile
	sh makefile.build default.o.build getgid.o getgid

getgid: \
makefile.build \
getgid=x \
default.build \
unix.a \
getgid.o \
load
	sh makefile.build default.build getgid getgid

generic-conf.o: \
makefile.build \
generic-conf.h \
open.h \
buffer.h \
strerr.h \
default.o.build \
generic-conf.c \
compile
	sh makefile.build default.o.build generic-conf.o generic-conf

fork.h: \
makefile.build \
fork.h.build \
fork.h2 \
fork.h1 \
tryvfork.c \
load \
compile \
choose
	sh makefile.build fork.h.build fork.h 

fmt_ulong.o: \
makefile.build \
fmt.h \
default.o.build \
fmt_ulong.c \
compile
	sh makefile.build default.o.build fmt_ulong.o fmt_ulong

fd_shutdown.o: \
makefile.build \
error.h \
fd.h \
default.o.build \
fd_shutdown.c \
compile
	sh makefile.build default.o.build fd_shutdown.o fd_shutdown

fd_move.o: \
makefile.build \
fd.h \
default.o.build \
fd_move.c \
compile
	sh makefile.build default.o.build fd_move.o fd_move

fd_copy.o: \
makefile.build \
fd.h \
default.o.build \
fd_copy.c \
compile
	sh makefile.build default.o.build fd_copy.o fd_copy

error_str.o: \
makefile.build \
error.h \
default.o.build \
error_str.c \
compile
	sh makefile.build default.o.build error_str.o error_str

error.o: \
makefile.build \
error.h \
default.o.build \
error.c \
compile
	sh makefile.build default.o.build error.o error

env.o: \
makefile.build \
env.h \
str.h \
default.o.build \
env.c \
compile
	sh makefile.build default.o.build env.o env

connect-io.o: \
makefile.build \
tai.h \
taia.h \
sig.h \
ndelay.h \
scan.h \
strerr.h \
exit.h \
default.o.build \
connect-io.c \
compile \
uint64.h \
iopause.h
	sh makefile.build default.o.build connect-io.o connect-io

connect-io: \
makefile.build \
connect-io=x \
default.build \
unix.a \
connect-io.o \
load
	sh makefile.build default.build connect-io connect-io

compile: \
makefile.build \
warn-auto.sh \
systype \
print-compile.sh \
conf-cc \
default.build
	sh makefile.build default.build compile compile

coe.o: \
makefile.build \
coe.h \
default.o.build \
coe.c \
compile
	sh makefile.build default.o.build coe.o coe

choosing: \
makefile.build \
choosing.sh \
warn-auto.sh \
choosing.sh \
warn-auto.sh \
default.build \
makescrip \
makeinclude \
choosing=s
	sh makefile.build default.build choosing choosing

choose: \
makefile.build \
choose.sh \
warn-auto.sh \
choose.sh \
warn-auto.sh \
makescrip \
makeinclude \
choose=s \
default.build
	sh makefile.build default.build choose choose

chkshsgr.o: \
makefile.build \
exit.h \
default.o.build \
chkshsgr.c \
compile
	sh makefile.build default.o.build chkshsgr.o chkshsgr

chkshsgr: \
makefile.build \
chkshsgr=x \
default.build \
chkshsgr.o \
load
	sh makefile.build default.build chkshsgr chkshsgr

cdb_make.o: \
makefile.build \
buffer.h \
cdb_make.h \
cdb.h \
alloc.h \
error.h \
seek.h \
default.o.build \
cdb_make.c \
compile \
uint32.h
	sh makefile.build default.o.build cdb_make.o cdb_make

cdb_hash.o: \
makefile.build \
cdb.h \
default.o.build \
cdb_hash.c \
compile \
uint32.h
	sh makefile.build default.o.build cdb_hash.o cdb_hash

cdb.o: \
makefile.build \
cdb.h \
byte.h \
seek.h \
error.h \
default.o.build \
cdb.c \
compile \
uint32.h
	sh makefile.build default.o.build cdb.o cdb

ccperl: \
makefile.build \
print-ccperl.sh \
conf-perl \
conf-ccperl \
ccperl.build
	sh makefile.build ccperl.build ccperl 

byte_zero.o: \
makefile.build \
byte.h \
default.o.build \
byte_zero.c \
compile
	sh makefile.build default.o.build byte_zero.o byte_zero

byte_diff.o: \
makefile.build \
byte.h \
default.o.build \
byte_diff.c \
compile
	sh makefile.build default.o.build byte_diff.o byte_diff

byte_cr.o: \
makefile.build \
byte.h \
default.o.build \
byte_cr.c \
compile
	sh makefile.build default.o.build byte_cr.o byte_cr

byte_copy.o: \
makefile.build \
byte.h \
default.o.build \
byte_copy.c \
compile
	sh makefile.build default.o.build byte_copy.o byte_copy

byte_chr.o: \
makefile.build \
byte.h \
default.o.build \
byte_chr.c \
compile
	sh makefile.build default.o.build byte_chr.o byte_chr

buffer_write.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_write.c \
compile
	sh makefile.build default.o.build buffer_write.o buffer_write

buffer_read.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_read.c \
compile
	sh makefile.build default.o.build buffer_read.o buffer_read

buffer_put.o: \
makefile.build \
error.h \
byte.h \
str.h \
buffer.h \
default.o.build \
buffer_put.c \
compile
	sh makefile.build default.o.build buffer_put.o buffer_put

buffer_get.o: \
makefile.build \
error.h \
byte.h \
buffer.h \
default.o.build \
buffer_get.c \
compile
	sh makefile.build default.o.build buffer_get.o buffer_get

buffer_copy.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_copy.c \
compile
	sh makefile.build default.o.build buffer_copy.o buffer_copy

buffer_2.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_2.c \
compile
	sh makefile.build default.o.build buffer_2.o buffer_2

buffer_1.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_1.c \
compile
	sh makefile.build default.o.build buffer_1.o buffer_1

buffer_0.o: \
makefile.build \
buffer.h \
default.o.build \
buffer_0.c \
compile
	sh makefile.build default.o.build buffer_0.o buffer_0

buffer.o: \
makefile.build \
buffer.h \
default.o.build \
buffer.c \
compile
	sh makefile.build default.o.build buffer.o buffer

auto_home.o: \
makefile.build \
default.o.build \
auto_home.c \
compile
	sh makefile.build default.o.build auto_home.o auto_home

auto_home.c: \
makefile.build \
auto_home.c.build \
home \
auto-str
	sh makefile.build auto_home.c.build auto_home.c 

auto-str.o: \
makefile.build \
exit.h \
buffer.h \
default.o.build \
auto-str.c \
compile
	sh makefile.build default.o.build auto-str.o auto-str

auto-str: \
makefile.build \
auto-str=x \
default.build \
unix.a \
auto-str.o \
load
	sh makefile.build default.build auto-str auto-str

alloc_re.o: \
makefile.build \
byte.h \
alloc.h \
default.o.build \
alloc_re.c \
compile
	sh makefile.build default.o.build alloc_re.o alloc_re

alloc.o: \
makefile.build \
error.h \
alloc.h \
default.o.build \
alloc.c \
compile
	sh makefile.build default.o.build alloc.o alloc

