dependon compile tryipcpath print-ipcpath.sh
formake rm -f ipcpath.h
formake 'sh print-ipcpath.sh > ipcpath.h'
rm -f ipcpath.h
sh print-ipcpath.sh
exit 0
