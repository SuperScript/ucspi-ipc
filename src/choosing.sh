
result="$3"

case "$1" in
  *c*) ./compile "$2.o" "$2.c" >/dev/null 2>&1 || {
      rm -f "$2.o" "$2"
      exit 1 
    }
    ;;
esac

case "$1" in
  *l*) ./load "$2" "$2" >/dev/null 2>&1 || exit 1 ;;
esac

case "$1" in
  *r*) "./$2" >/dev/null 2>&1 || exit 1 ;;
esac


rm -f "$2.o" "$2"

exec cat "$result"

