/*

build-prefix.h - build prefix header for building git
Copyright (C) 2014 Kyle J. McKay.  All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_4
#define MAC_OS_X_VERSION_10_4 1040
#endif
#ifndef MAC_OS_X_VERSION_10_5
#define MAC_OS_X_VERSION_10_5 1050
#endif
#undef OLD_ICONV
#undef XDL_FAST_HASH
#if MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_5
#define OLD_ICONV 1
#endif
#ifdef __x86_64__
/* XDL_FAST_HASH has some extremely bad worst case performance issues */
/* See http://thread.gmane.org/gmane.comp.version-control.git/261638 */
/* #define XDL_FAST_HASH 1 */
#endif
#undef GETTEXT_H
#define GETTEXT_H
#undef _
#define _(s) gettext(s)
#undef N_
/* N_(x) MUST NOT have any parenthesis around expansion! */
#define N_(s) s
#undef Q_
#define Q_(s,p,n) ngettext((s),(p),(n))
extern void git_setup_gettext(void);
extern char *gettext(const char *msgid);
extern int gettext_width(const char *s);
#undef ngettext
#define ngettext(s,p,n) (((n)==1)?gettext(s):gettext(p))
