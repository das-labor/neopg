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

# Some options of Visual-C:
# -W3   Set warning level 3
# -Zi   Generate debug info
# -Od   Disable optimization
# -Gm   Enable minimal rebuild (for C++)
# -EHsc Exception handling model sc 
# -MTd  Create a debug multithreaded executable
# -fp:  Floating point behaviour
# -GR-  Disable runtime type information
# -Os   Favor small code
# -LD   Create a DLL
# -Fe   Set executable output name (may be only a directory)
CFLAGS = -nologo -W3 -fp:fast -Os $(ce_defines) \
         -DHAVE_CONFIG_H -DDLL_EXPORT -I. -Igpg-extra

LDFLAGS =

# Standard source files
sources = \
	init.c init.h      \
	strsource.c	   \
	strerror.c	   \
	code-to-errno.c	   \
	code-from-errno.c  \
	w32-gettext.c      \
        gettext.h          \
	err-sources.h 	   \
	err-codes.h

# Sources files in this directory inclduing this Makefile
conf_sources = \
	build.mk \
	config.h \
	stdint.h

# Source files built by running the standard build system.
built_sources = \
	code-from-errno.h \
	code-to-errno.h	  \
	err-codes-sym.h	  \
	err-sources-sym.h \
	errnos-sym.h	  \
	gpg-error.h	  \
	mkerrcodes.h	  \
	mkw32errmap.map.c \
	gpg-error.def     \
	gpg-extra/errno.h

copy-static-source:
	@if [ ! -f ./w32-gettext.c ]; then \
           echo "Please cd to the src/ directory first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/libgpg-error/src $(sources);
	cd ../contrib/conf-w32ce-msc ; \
           cp -t $(targetsrc)/libgpg-error/src $(conf_sources)


copy-built-source:
	@if [ ! -f ./mkw32errmap.map.c ]; then \
           echo "Please build using ./autogen.sh --build-w32ce first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/libgpg-error/src $(built_sources)
	-mkdir $(targetsrc)/libgpg-error/src/gpg-extra
	mv $(targetsrc)/libgpg-error/src/errno.h \
           $(targetsrc)/libgpg-error/src/gpg-extra

copy-source: copy-static-source copy-built-source


all:  $(sources) $(conf_sources) $(built_sources)
	$(CC) $(CFLAGS) -c w32-gettext.c
	$(CC) $(CFLAGS) -c init.c
	$(CC) $(CFLAGS) -c strsource.c
	$(CC) $(CFLAGS) -c strerror.c
	$(CC) $(CFLAGS) -c code-to-errno.c
	$(CC) $(CFLAGS) -c code-from-errno.c
	link.exe /DLL /IMPLIB:libgpg-error-0-msc.lib \
	        /OUT:libgpg-error-0-msc.dll \
		/DEF:gpg-error.def /NOLOGO /MANIFEST:NO \
		/NODEFAULTLIB:"oldnames.lib" /DYNAMICBASE:NO \
	        w32-gettext.obj init.obj strsource.obj strerror.obj \
	  	code-to-errno.obj code-from-errno.obj \
		coredll.lib corelibc.lib ole32.lib oleaut32.lib uuid.lib \
		commctrl.lib /subsystem:windowsce,5.02

install: all
	-mkdir $(bindir:/=\)
	-mkdir $(libdir:/=\)
	-mkdir $(incdir:/=\)
	-mkdir $(incdir:/=\)\gpg-extra
	copy /y gpg-error.h $(incdir:/=\)
	copy /y gpg-extra\errno.h $(incdir:/=\)\gpg-extra
	copy /y libgpg-error-0-msc.dll $(bindir:/=\)
	copy /y libgpg-error-0-msc.lib $(libdir:/=\)

clean:
	del *.obj libgpg-error-0-msc.lib \
            libgpg-error-0-msc.dll libgpg-error-0-msc.exe
