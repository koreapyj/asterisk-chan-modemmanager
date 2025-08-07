PROJM =  chan_modemmanager.so
chan_modemmanagerm_so_OBJS =  chan_modemmanager.o
res_mmsd_so_OBJS = res_mmsd.o
SOURCES = chan_modemmanager.c
HEADERS = 

CC = gcc
LD = ld
STRIP = strip
RM = rm -fr
INSTALL = install
CHMOD = chmod

CFLAGS  = -I/usr/include/ModemManager -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/libmm-glib -std=gnu11 -DAST_MODULE_SELF_SYM=__internal_chan_modemmanager_self -fPIC
LDFLAGS = -lportaudio -lasound -lm -lpthread -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lmm-glib
SOLINK  = -shared
LIBS    = 

srcdir = @srcdir@
VPATH = @srcdir@

all: chan_modemmanager.so res_mmsd.so

clean:
	$(RM) chan_modemmanager.o chan_modemmanager.so res_mmsd.o res_mmsd.so

chan_modemmanager.so: $(chan_modemmanagerm_so_OBJS) Makefile
	$(LD) $(LDFLAGS) $(SOLINK) -o $@ $(chan_modemmanagerm_so_OBJS) $(LIBS)

res_mmsd.so: $(res_mmsd_so_OBJS) Makefile
	$(LD) $(LDFLAGS) $(SOLINK) -o $@ $(res_mmsd_so_OBJS) $(LIBS)

ifneq ($(wildcard .*.d),)
   include .*.d
endif
