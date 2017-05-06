dnl ****************************************************************************
dnl * configure.ac                                                             *
dnl *                                                                          *
dnl * Copyright (C) 2017 Gwiz <gwiz65@gmail.com>                               *
dnl *                                                                          *
dnl * firebreak is free software: you can redistribute it and/or modify it     *
dnl * under the terms of the GNU General Public License as published by the    *
dnl * Free Software Foundation, either version 3 of the License, or            *
dnl * (at your option) any later version.                                      *
dnl *                                                                          *
dnl * firebreak is distributed in the hope that it will be useful, but         *
dnl * WITHOUT ANY WARRANTY; without even the implied warranty of               *
dnl * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
dnl * See the GNU General Public License for more details.                     *
dnl *                                                                          *
dnl * You should have received a copy of the GNU General Public License along  *
dnl * with this program.  If not, see <http://www.gnu.org/licenses/>.          *
dnl *                                                                          *
dnl ****************************************************************************
dnl
dnl Process this file with autoconf to produce a configure script.

AC_INIT(firebreak, 0.18)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.11])
AM_SILENT_RULES([yes])
AC_PROG_CC
LT_INIT
PKG_CHECK_MODULES(FIREBREAK, [gtk+-3.0])
AC_OUTPUT([Makefile src/Makefile])
