test $# -ge 1 || {
  echo "ipcrun: usage: ipcrun prog" >&2
  exit 100;
}
exec #HOME#/command/ipcclient -l0 #IPCEXEC#/s #HOME#/command/ipccommand 0 "$@"
