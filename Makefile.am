## ****************************************************************************
## * Makefile.am                                                              *
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
## ****************************************************************************/
##
## Process this file with automake to produce Makefile.in

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
