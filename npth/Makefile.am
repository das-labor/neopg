# Makefile.am - Top level Makefile for npth.
# Copyright (C) 2011 g10 Code GmbH
#
# This file is part of nPth.
#
# nPth is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
#
# nPth is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = npth-config.in npth.m4 npth.spec.in autogen.sh autogen.rc HACKING
bin_SCRIPTS = npth-config
m4datadir = $(datadir)/aclocal
m4data_DATA = npth.m4

if RUN_TESTS
tests = tests
else
tests =
endif

if HAVE_W32_SYSTEM
npthdir = w32
else
npthdir = src
endif

SUBDIRS = ${npthdir} ${tests}

# Fix the version of the spec file and create a file named VERSION
# to be used for patch's Prereq: feature.
dist-hook: gen-ChangeLog
	@set -e; \
	sed -e 's/@pkg_version@/$(VERSION)/g' \
	    $(top_srcdir)/npth.spec.in  > $(distdir)/npth.spec
	echo "$(VERSION)" > $(distdir)/VERSION


gen_start_date = 2011-12-01T00:00:00
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	   gitlog-to-changelog						\
	    --append-dot --tear-off					\
	    --amend=build-aux/git-log-fix				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;\
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi
