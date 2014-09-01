#!/usr/bin/env bash

if [ $# -gt 0 ]; then
    OPENVSWITCH=$1
else
    OPENVSWITCH=~/openvswitch
fi

DEBUG=$#
function bugprint()
{
	if [ $DEBUG -gt 0 ]; then
		echo $1
	fi
}

CONFDBPATH="/usr/local/etc/openvswitch/conf.db"
ISDB=" -e $CONFDBPATH"
bugprint $ISDB

if [ ! $ISDB ]; then
    echo "create DB"
    FLAGDB=0   # this means DB is new
    sudo mkdir -p /usr/local/etc/openvswitch
    sudo ovsdb-tool create $CONFDBPATH $OPENVSWITCH/vswitchd/vswitch.ovsschema
else
    echo "already have a DB"
    FLAGDB=1
fi

ISINSERT=$(lsmod | grep "openvswitch" | wc -l)
bugprint $ISINSERT
if [ $ISINSERT -eq 0 ]; then
	echo "Now insmod openvswitch!"
	sudo insmod $OPENVSWITCH/datapath/linux/openvswitch.ko
else 
	echo "openvswitch module is already installed!"
fi

# start ovs server
ISSTARTSERVER=$(ps ax| grep "ovsdb-server"| grep -v grep| wc -l)
bugprint $ISSTARTSERVER
if [ $ISSTARTSERVER -eq 0 ]; then
	echo "start ovsdb-server!"
	sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,manager_options \
                     --private-key=db:SSL,private_key \
                     --certificate=db:SSL,certificate \
                     --bootstrap-ca-cert=db:SSL,ca_cert \
                     --pidfile --detach
else
	echo "server is already started!"
fi

# init db
if [ $FLAGDB -eq 0 ]; then
    echo "init DB"
    sudo ovs-vsctl --no-wait init
fi

ISSTARTSWITCHD=$(ps ax| grep "ovs-vswitchd"| grep -v grep| wc -l)
bugprint $ISSTARTSWITCHD
if [ $ISSTARTSWITCHD -eq 0 ]; then
	echo "start ovs-vswitchd!"
	sudo ovs-vswitchd --pidfile --detach  --log-file
else 
	echo "ovs-vswitchd is already started!"
fi
