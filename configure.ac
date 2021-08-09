## configure.ac -- Process this file with autoconf to produce configure
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

AC_INIT([mctp], [0.1], [https://github.com/CodeConstruct/mctp])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_INSTALL

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([foreign -Wportability -Woverride])
AM_SILENT_RULES([yes])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(SYSTEMD, [libsystemd], [have_systemd=yes])

AM_CONDITIONAL([HAVE_SYSTEMD], [test x$have_systemd = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
