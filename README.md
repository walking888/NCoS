Thank you for visiting us.
Contact us: liusicheng888@gmail.com

This project is a network coding framework over software-defined network. There are two part of the work: a controller (pox-0.2.0-modified), a switch module (openvswitch-1.9.0-modified). We have add "group management", "topology service", "statistics service", "buffer management", "multipath multicast routing", "flow entry generation" modules in the controller to manage network coding. We also add coding function in openvswitch. For fast add consistent action in both controller and switch, we write a tool: action\_add.

In order to run the test, we use mininet 2.0.0 as the test bed and write a simple script topo-butterfly.py (Because we do not add or change any code on mininet, readers can download it yourself at: git://github.com/mininet/mininet). Also we modified iperf as the receiver and the sender. The modified iperf receiver will send report to controller and these report can be collected by our pox controller for further analysis.

0. how to download submodule iperf-modified and pox-0.2.0-modified-ext-multicast
    In project path, use command:
        git submodule init
        git submodule update

1. openvswitch-1.9.0-modified
    We have change or add the file below:
    \lib\       ofp-util.h ofp-util.c ofp-util.def ofp-msgs.c ofp-actions.h ofp-actions.c
    \ofproto\   ofproto-dpif.c
    \datapath\  actions.c datapath.c datapath.h Modules.mk
    \include\   \linux      openvswitch.h
                \openflow   openflow-nc.h openflow.h
    \           Makefile.am Makefile.in


    Information in INSTALL will teach to how to build and install the kernel module and run the service. All the command is the same as it before.

2. pox-0.2.0-modified
    We have modified several files to support IGMPv3 packets, udp packets and openflow-nc packets. These files is:
    \pox\lib\packet\    igmp.py udp.py ipv4.py
    \pox\openflow\      topology.py libopenflow_01.py nc.py

    Other modules described in our paper is in \ext\multicast\. Because we donot change the git history of original pox, so we put our modified files in path: \replace-pox-0.2.0\.

    How to use our pox controller is shown in \ext\multicast\README. Here topo-butterfly.py is on the file list as an mininet script example.

3. action\_add
    This tool is help us add action into pox and openvswitch. The file example give us a introduction on how to defined an action.
    Run .\action_add.py will show the help. You need firstt follow the example to write a struct_file. This tool can only run on original openvswitch-1.9.0 and pox-0.2.0. All the code it modified or added is tagged.

4. iperf-modified
    We do not change any command, so you can use it as before.
