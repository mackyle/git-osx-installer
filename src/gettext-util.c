/*

gettext-util.c - git gettext utility for Mac OS X
Copyright (C) 2014,2015 Kyle J. McKay.  All rights reserved.

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

#include "git-compat-util.h"
#include "gettext.h"

int main(int argc, char **argv)
{
	const char usage[] = "Usage: git gettext MSGID [MSGID_PLURAL N]";
	long n = 0;
	if (argc != 2 && argc != 4)
		die("%s", usage);
	if (argc == 4) {
		char *end;
		n = strtol(argv[3], &end, 10);
		if (!argv[3][0] || *end || n < 0)
			die("%s", usage);
	}
	git_setup_gettext();
	if (argc == 4) {
		printf("%s", ngettext(argv[1], argv[2], (unsigned long)n));
	} else {
		printf("%s", gettext(argv[1]));
	}
	return 0;
}
