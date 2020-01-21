AM_CFLAGS = -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs \
        -g -O0 \
        -fno-inline \
        -fno-short-enums \
        -fPIC

AM_CPPFLAGS = $(CFLAGS) \
        -I../inc


##################### at library ##################
library_includedir = $(pkgincludedir)
library_include_HEADERS = ../inc/askey_locker.h

lib_LTLIBRARIES = libaskey_locker.la
libaskey_locker_la_CC = @CC@
libaskey_locker_la_SOURCES = askey_locker.c
libaskey_locker_la_CFLAGS  = $(AM_CFLAGS)
libaskey_locker_la_CPPFLAGS = $(AM_CFLAGS) $(AM_CPPFLAGS)
libaskey_locker_la_LDFLAGS  = -shared -version-info 1:0:0 -lcrypto


##################### at_send execute ##################
#bin_PROGRAMS = askey_locker
#at_send_CC = @CC@
#at_send_SOURCES = send_at.cpp
#at_send_CFLAGS = $(AM_CFLAGS) $(AM_CPPFLAGS)
#at_send_CPPFLAGS = $(AM_CPPFLAGS)
#at_send_LDFLAGS = -lpthread -lalog
#at_send_LDADD = libat.la
