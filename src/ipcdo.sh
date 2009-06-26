test $# -ge 2 || {
  echo "ipcdo: usage: ipcdo user prog" >&2
  exit 100;
}
user="${1-root}"
user=`id -u "$user"`
shift
exec #HOME#/command/ipcclient -l0 #IPCEXEC#/s #HOME#/command/ipccommand "$user" "$@"
