## Process this file with automake to produce Makefile.in
## Created by Anjuta

SUBDIRS = src 

firebreakdocdir = ${prefix}/doc/firebreak
firebreakdoc_DATA = \
	README\
	COPYING\
	AUTHORS\
	ChangeLog\
	INSTALL\
	NEWS


EXTRA_DIST = $(firebreakdoc_DATA)


# Remove doc directory on uninstall
uninstall-local:
	-rm -r $(firebreakdocdir)
