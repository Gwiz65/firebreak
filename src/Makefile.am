## Process this file with automake to produce Makefile.in

## Created by Anjuta


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

