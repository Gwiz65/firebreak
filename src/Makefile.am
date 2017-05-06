## ****************************************************************************
## * src/Makefile.am                                                          *
## *                                                                          *
## * Copyright (C) 2017 Gwiz <gwiz65@gmail.com>                               *
## *                                                                          *
## * firebreak is free software: you can redistribute it and/or modify it     *
## * under the terms of the GNU General Public License as published by the    *
## * Free Software Foundation, either version 3 of the License, or            *
## * (at your option) any later version.                                      *
## *                                                                          *
## * firebreak is distributed in the hope that it will be useful, but         *
## * WITHOUT ANY WARRANTY; without even the implied warranty of               *
## * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
## * See the GNU General Public License for more details.                     *
## *                                                                          *
## * You should have received a copy of the GNU General Public License along  *
## * with this program.  If not, see <http://www.gnu.org/licenses/>.          *
## *                                                                          *
## ****************************************************************************
##
## Process this file with automake to produce Makefile.in

firebreakuidir = $(pkgdatadir)/ui
firebreakui_DATA = firebreak.ui

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	$(FIREBREAK_CFLAGS)

AM_CFLAGS =\
	 -Wall\
	 -g

bin_PROGRAMS = firebreak \
	fbmon

firebreak_SOURCES = \
	firebreak.c \
	firebreak.h

firebreak_LDFLAGS = \
	-Wl,--export-dynamic

firebreak_LDADD = $(FIREBREAK_LIBS)

fbmon_SOURCES =  \
	fbmon.c

EXTRA_DIST = $(firebreakui_DATA)

# Remove ui directory on uninstall
uninstall-local:
	-rm -r $(firebreakuidir)
	-rm -r $(pkgdatadir)

# set bin suid
install-exec-hook:
	chmod 4755 $(bindir)/fbmon
