# build.mk - Makefile to build libgpg-error using Visual-C
# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# This is a helper make script to build libgpg-error for WindowsCE
# using the Microsoft Visual C compiler.  

# The target build directory where we run the Visual C compiler/ This
# needs to be an absolute directory name.  Further we expect this
# structure of the tree:
# 
#   TARGET/src - Source directories:  One directory for each project
#         /bin - Installed DLLs
#         /lib - Installed import libs.
#         /include - Instaled header files.

targetdir = /home/smb/xppro-gnu
targetsrc = $(targetdir)/src

# Install directories (relative)
bindir = ../../../bin
libdir = ../../../lib
incdir = ../../../include

help:
	@echo "Run "
	@echo "  make -f ../contrib/conf-w32ce-msc/build.mk copy-source"
	@echo "on the POSIX system and then"
	@echo "  nmake -f build.mk all"
	@echo "  nmake -f build.mk install"
	@echo "on the Windows system"

ce_defines = -DWINCE -D_WIN32_WCE=0x502 -DUNDER_CE \
             -DWIN32_PLATFORM_PSPC -D_UNICODE -DUNICODE \
             -D_CONSOLE -DARM -D_ARM_
#-D_DEBUG -DDEBUG 

# See libgpg-error's build-mk for a list of compiler options.
CFLAGS = -nologo -W3 -fp:fast -Os $(ce_defines) \
         -DHAVE_CONFIG_H -DDLL_EXPORT -D_CRT_SECURE_NO_WARNINGS \
	 -I. -I$(incdir) -I$(incdir)/gpg-extra

LDFLAGS =

# Standard source files
sources = \
	assuan.c                 \
	context.c  		 \
	system.c  		 \
	debug.c  		 \
	conversion.c  		 \
	sysutils.c  		 \
	client.c  		 \
	server.c  		 \
	assuan-error.c  	 \
	assuan-buffer.c  	 \
	assuan-handler.c  	 \
	assuan-inquire.c  	 \
	assuan-listen.c  	 \
	assuan-pipe-server.c  	 \
	assuan-socket-server.c   \
	assuan-pipe-connect.c  	 \
	assuan-socket-connect.c  \
	assuan-uds.c  		 \
	assuan-logging.c  	 \
	assuan-socket.c  	 \
	system-w32ce.c  	 \
	assuan-io.c  		 \
	putc_unlocked.c  	 \
	memrchr.c  		 \
	stpcpy.c  		 \
	setenv.c                 \
	vasprintf.c              \
        assuan-defs.h            \
        debug.h                  \
	libassuan.def

# The object files we need to create from sources.
objs = \
	assuan.obj               \
	context.obj  		 \
	system.obj  		 \
	debug.obj  		 \
	conversion.obj  	 \
	sysutils.obj  		 \
	client.obj  		 \
	server.obj  		 \
	assuan-error.obj  	 \
	assuan-buffer.obj  	 \
	assuan-handler.obj  	 \
	assuan-inquire.obj  	 \
	assuan-listen.obj  	 \
	assuan-pipe-server.obj   \
	assuan-socket-server.obj \
	assuan-pipe-connect.obj  \
	assuan-socket-connect.obj \
	assuan-uds.obj  	 \
	assuan-logging.obj  	 \
	assuan-socket.obj  	 \
	system-w32ce.obj  	 \
	assuan-io.obj  		 \
	putc_unlocked.obj  	 \
	memrchr.obj  		 \
	stpcpy.obj  		 \
	setenv.obj               \
	vasprintf.obj


# Sources files in this directory inclduing this Makefile
conf_sources = \
	build.mk \
	config.h \
        stdint.h

# Source files built by running the standard build system.
built_sources = \
	assuan.h


copy-static-source:
	@if [ ! -f ./assuan-defs.h ]; then \
           echo "Please cd to the src/ directory first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/libassuan/src $(sources);
	cd ../contrib/conf-w32ce-msc ; \
           cp -t $(targetsrc)/libassuan/src $(conf_sources)


copy-built-source:
	@if [ ! -f ./assuan.h ]; then \
           echo "Please build using ./autogen.sh --build-w32ce first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/libassuan/src $(built_sources)

copy-source: copy-static-source copy-built-source


.c.obj:
	$(CC) $(CFLAGS) -c $<

all:  $(sources) $(conf_sources) $(built_sources) $(objs)
	link    /DLL /IMPLIB:libassuan-0-msc.lib \
                /OUT:libassuan-0-msc.dll \
		/DEF:libassuan.def /NOLOGO /MANIFEST:NO \
		/NODEFAULTLIB:"oldnames.lib" /DYNAMICBASE:NO \
	        $(objs) $(libdir)/libgpg-error-0-msc.lib \
		coredll.lib corelibc.lib ole32.lib oleaut32.lib uuid.lib \
		commctrl.lib ws2.lib /subsystem:windowsce,5.02

# Note that we don't need to create the install directories because
# libgpg-error must have been build and installed prior to this
# package.
install: all
	copy /y libassuan-0-msc.dll $(bindir:/=\)
	copy /y libassuan-0-msc.lib $(libdir:/=\)
	copy /y assuan.h $(incdir:/=\)

clean:
	del *.obj libassuan-0-msc.lib libassuan-0-msc.dll libassuan-0-msc.exp

