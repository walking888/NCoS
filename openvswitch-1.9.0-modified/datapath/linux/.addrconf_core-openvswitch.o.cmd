cmd_/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o := gcc -Wp,-MD,/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/.addrconf_core-openvswitch.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/4.7/include -I/home/lsch/mytest/openvswitch-1.9.0/include -I/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/compat -I/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/compat/include  -I/usr/src/linux-headers-3.5.0-23-generic/arch/x86/include -Iarch/x86/include/generated -Iinclude  -include /usr/src/linux-headers-3.5.0-23-generic/include/linux/kconfig.h -Iubuntu/include  -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m64 -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -DCONFIG_AS_AVX=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -Wframe-larger-than=1024 -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -pg -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO -DVERSION=\"1.9.0\" -I/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/.. -I/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/.. -g -include /home/lsch/mytest/openvswitch-1.9.0/datapath/linux/kcompat.h  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(addrconf_core_openvswitch)"  -D"KBUILD_MODNAME=KBUILD_STR(openvswitch)" -c -o /home/lsch/mytest/openvswitch-1.9.0/datapath/linux/.tmp_addrconf_core-openvswitch.o /home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.c

source_/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o := /home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.c

deps_/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o := \
  /home/lsch/mytest/openvswitch-1.9.0/datapath/linux/kcompat.h \
  include/linux/version.h \

/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o: $(deps_/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o)

$(deps_/home/lsch/mytest/openvswitch-1.9.0/datapath/linux/addrconf_core-openvswitch.o):
