obj-m += test.o

KDIR = /usr/src/linux-4.4
#PWD = /home/dskym/KUSS2

all :
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean :
	rm -rf *.o *.ko *.mod.* *.symvers *.order
