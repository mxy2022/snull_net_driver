###############################################################
#
# Linux kernel - 4.4.0
# Author       - Meixiuyi
#
# snull network device build file
#
###############################################################

# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y
#CFLAGS = y


# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSBULL_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

ifeq ($(CFlAGS), y) 
CFLAGS += $(DEBFLAGS)
CFLAGS += -I..
endif

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= snull.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?= /usr/src/linux-headers-4.4.0-31-generic
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif



clean:
#	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
	rm -rf *.o *.ko *.mod.c *odule*

ifeq ($(CFlAGS), y) 
depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend
endif

ifeq ($(CFlAGS), y) 
ifeq (.depend,$(wildcard .depend))
include .depend
endif
endif
