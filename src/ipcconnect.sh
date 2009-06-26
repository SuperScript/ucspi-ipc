test $# -ne 1 && { echo "ipcconnect: usage: ipcconnect path" >&2; exit 100; }
exec #HOME#/command/ipcclient -l0 -- "$1" #HOME#/command/connect-io 3600 6 7
