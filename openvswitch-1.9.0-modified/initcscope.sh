#! /bin/sh
rm -f cscope.*
find /home/lsch/mytest/openvswitch-1.9.0 -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*,sh"> cscope.files
cscope -bqk
