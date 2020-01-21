AM_CFLAGS = -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs \
        -g -O0 \
        -fno-inline \
        -fno-short-enums 


AM_CPPFLAGS = $(CFLAGS) \
        -I../inc



##################### at_send execute ##################
bin_PROGRAMS = askey_locker
askey_locker_CC = @CC@
askey_locker_SOURCES = test.c
askey_locker_CFLAGS = $(AM_CFLAGS) $(AM_CPPFLAGS)
askey_locker_CPPFLAGS = $(AM_CPPFLAGS)
askey_locker_LDFLAGS = -I../inc -L../src
askey_locker_LDADD = -laskey_locker -lcrypto
