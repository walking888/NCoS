#!/usr/bin/env bash

ISSTARTSWITCHD=$(ps ax| grep "ovs-vswitchd"| grep -v grep| wc -l)
if [ $ISSTARTSWITCHD -eq 0 ]; then
	echo "ovs-vswitchd is not run!"
else 
	echo "stop ovs-vswitchd!"
    sudo killall ovs-vswitchd
fi

# stop ovs server
ISSTARTSERVER=$(ps ax| grep "ovsdb-server"| grep -v grep| wc -l)
if [ $ISSTARTSERVER -eq 0 ]; then
	echo "ovsdb-server is not on!"
else
	echo "stop ovsdb-server!"
    sudo killall ovsdb-server
fi



ISINSERT=$(lsmod | grep "openvswitch" | wc -l)
if [ $ISINSERT -eq 0 ]; then
	echo "openvswitch mod is not load!"
else 
	echo "remove openvswitch module!"
    sudo rmmod openvswitch.ko
fi


