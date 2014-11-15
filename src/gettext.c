/*

gettext.c - gettext equivalents for Mac OS X
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

/* If GIT_TEXTDOMAINDIR then a bundle named git-messages.bundle should be
 * located there containing a Contents/Resources/<lang>.lproj/Localizable.strings
 * file for each supported messages localization.
 * If GIT_TEXTDOMAINDIR is not set then it typically defaults to something
 * like $prefix/share/locale from the build settings.
 * If GIT_USE_PREFERENCES_LOCALE is true then LANG, LC_ALL, LC_MESSAGES
 * will be ignored and the user's international language preferences will be
 * used to select the messages locale.
 * If GIT_USE_PREFERENCES_LOCALE is not set but the preference
 * org.git-scm.use_preferences_locale is set to a boolean true (in either the
 * user's or all users' globalDomain) then also behave as though
 * GIT_USE_PREFERENCES_LOCALE is set to true.
 */

#include <CoreFoundation/CoreFoundation.h>
#include "cache.h"
#include "utf8.h"
#include <locale.h>
#include <langinfo.h>
#include <libcharset.h>
#include <xlocale.h>
#include <iconv.h>
#include <stdlib.h>
#include <string.h>

#if defined(OLD_ICONV) || (defined(__sun__) && !defined(_XPG6))
	typedef const char **iconv_p2;
#else
	typedef char **iconv_p2;
#endif

static char charset[32];
static char localename[32];
static int is_utf8_codeset;
static int icok;
static iconv_t ic;
static CFBundleRef bndl;
static CFStringRef localestr;
static CFURLRef localestringsurl;
static int gettext_inited;
static CFDictionaryRef localedict;
static CFMutableDictionaryRef localeiconvdict;

static char *strlcpyuc(char *dst, const char *src, size_t cnt)
{
	char *ptr;

	if (!cnt || !dst)
		return dst;

	ptr = dst;
	if (src) {
		while (*src && --cnt) {
			char ch = *src++;
			if ('a' <= ch && ch <= 'z')
				ch -= 'a' + 'A';
			*ptr++ = ch;
		}
	}
	*ptr = '\0';
	return dst;
}

static char touc(char c)
{
    return ('a' <= c && c <= 'z') ? c - 'a' + 'A' : c;
}

static char tolc(char c)
{
    return ('A' <= c && c <= 'Z') ? c - 'A' + 'a' : c;
}

void git_setup_gettext(void)
{
	const char *codeset;
	const char *localedir;
	char bundlepath[PATH_MAX];
	CFURLRef burl;
	CFArrayRef bl;
	int use_pref_locale = git_env_bool("GIT_USE_PREFERENCES_LOCALE", -1);

	if (use_pref_locale < 0) {
		CFBooleanRef b = CFPreferencesCopyValue(
			CFSTR("org.git-scm.use_preferences_locale"),
			kCFPreferencesAnyApplication,
			kCFPreferencesCurrentUser,
			kCFPreferencesAnyHost);
		if (!b) b = CFPreferencesCopyValue(
			CFSTR("org.git-scm.use_preferences_locale"),
			kCFPreferencesAnyApplication,
			kCFPreferencesAnyUser,
			kCFPreferencesCurrentHost);
		if (b) {
			if (CFGetTypeID(b) == CFBooleanGetTypeID()) {
				use_pref_locale = CFBooleanGetValue(b) ? 1 : 0;
			}
			CFRelease(b);
		}
		if (use_pref_locale < 0)
			use_pref_locale = 0;
	}
	if (!setlocale(LC_ALL, "")) {
		const char *newlc = NULL;
		const char *lcvar = getenv("LC_ALL");
		if (!lcvar) lcvar = getenv("LC_MESSAGES");
		if (!lcvar) lcvar = getenv("LANG");
		if (lcvar && strlen(lcvar) == 2 && !strchr(lcvar, '_')) {
			char trylc[6];
			trylc[0] = tolc(lcvar[0]);
			trylc[1] = tolc(lcvar[1]);
			trylc[2] = '_';
			trylc[3] = touc(lcvar[0]);
			trylc[4] = touc(lcvar[1]);
			trylc[5] = '\0';
			newlc = setlocale(LC_ALL, trylc);
		}
		if (!newlc)
			setlocale(LC_ALL, "C");
	}
	codeset = nl_langinfo(CODESET);
	if (!codeset || !*codeset)
		codeset = locale_charset();
	strlcpyuc(charset, codeset, sizeof(charset));
	is_utf8_codeset = !charset[0] || !strcmp(charset, "UTF-8");
	strlcpy(localename, querylocale(LC_MESSAGES_MASK, NULL), sizeof(localename));
	if (!is_utf8_codeset) {
		char transcharset[64];
		strlcpy(transcharset, charset, sizeof(transcharset));
		strlcat(transcharset, "//TRANSLIT", sizeof(transcharset));
		ic = iconv_open(transcharset, "UTF-8");
		if (ic != (iconv_t)-1)
			icok = 1;
	}
	localedir = getenv("GIT_TEXTDOMAINDIR");
	if (!localedir)
		localedir = GIT_LOCALE_PATH; /* typically $prefix/share/locale */
	snprintf(bundlepath, sizeof(bundlepath), "%s/git-messages.bundle", localedir);
	burl = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
		(const UInt8 *)bundlepath, strlen(bundlepath), true);
	if (burl) {
		bndl = CFBundleCreate(kCFAllocatorDefault, burl);
		CFRelease(burl);
	}
	bl = NULL;
	if (bndl)
		bl = CFBundleCopyBundleLocalizations(bndl);
	if (bl) {
		CFArrayRef al = NULL;
		CFArrayRef pa = NULL;
		if (!use_pref_locale) {
			CFStringRef l = CFStringCreateWithCString(kCFAllocatorDefault,
				localename, kCFStringEncodingUTF8);
			if (l) {
				pa = CFArrayCreate(kCFAllocatorDefault,
					(const void **)&l, 1, &kCFTypeArrayCallBacks);
				CFRelease(l);
			}
		}
		if (pa || use_pref_locale) {
			al = CFBundleCopyLocalizationsForPreferences(bl, pa);
			if (pa) CFRelease(pa);
		}
		if (al) {
			if (CFArrayGetCount(al)) {
				CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(al, 0);
				if (s && CFGetTypeID(s) == CFStringGetTypeID()) {
				    CFRetain(s);
				    localestr = s;
				}
			}
			CFRelease(al);
		}
		CFRelease(bl);
	}
	if (localestr)
		localestringsurl = CFBundleCopyResourceURLForLocalization(bndl,
			CFSTR("Localizable"), CFSTR("strings"), NULL, localestr);
}

static void git_init_gettext(void)
{
	if (gettext_inited) return;
	gettext_inited = 1;
	if (localestringsurl) {
		CFDataRef xml;
		SInt32 err;
		if (CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault,
		    localestringsurl, &xml, NULL, NULL, &err)) {
			CFPropertyListRef pl = CFPropertyListCreateFromXMLData(
				kCFAllocatorDefault, xml, kCFPropertyListImmutable, NULL);
			CFRelease(xml);
			if (pl) {
				if (CFGetTypeID(pl) == CFDictionaryGetTypeID())
					localedict = pl;
				else
					CFRelease(pl);
			}
		}
	}
	if (localedict) {
		localeiconvdict = CFDictionaryCreateMutable(kCFAllocatorDefault,
			CFDictionaryGetCount(localedict), &kCFTypeDictionaryKeyCallBacks, NULL);
	}
}

int gettext_width(const char *s)
{
	return is_utf8_codeset ? utf8_strwidth(s) : strlen(s);
}

static CFStringRef get_dict_str(CFDictionaryRef d, CFStringRef k)
{
	CFStringRef v;
	if (!d || !k)
		return NULL;
	v = (CFStringRef) CFDictionaryGetValue(d, k);
	return v && CFGetTypeID(v) == CFStringGetTypeID() ? v : NULL;
}

char *gettext(const char *msgid)
{
	CFStringRef key;
	CFStringRef valstr;
	char *val, *newval;
	size_t s;
	int newvalalloc = 0;

	if (!gettext_inited)
		git_init_gettext();

	if (!msgid || !*msgid || !localeiconvdict || (!is_utf8_codeset && !icok))
		return (char *)msgid;

	key = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, msgid,
		kCFStringEncodingUTF8, kCFAllocatorNull);
	if (!key)
		return (char *)msgid;
	val = (char *)CFDictionaryGetValue(localeiconvdict, key);
	if (val) {
		CFRelease(key);
		return val;
	}
	valstr = get_dict_str(localedict, key);
	if (!valstr) {
		CFRelease(key);
		return (char *)msgid;
	}
	newval = (char *)CFStringGetCStringPtr(valstr, kCFStringEncodingUTF8);
	if (!newval) {
		s = (size_t)CFStringGetMaximumSizeForEncoding(CFStringGetLength(valstr),
			kCFStringEncodingUTF8) + 1;
		newval = (char *)malloc(s);
		if (!newval) {
			CFRelease(key);
			return (char *)msgid;
		}
		if (!CFStringGetCString(valstr, newval, (CFIndex)s, kCFStringEncodingUTF8)) {
			free(newval);
			CFRelease(key);
			return (char *)msgid;
		}
		newvalalloc = 1;
	}
	if (is_utf8_codeset) {
		/* no iconv needed */
		CFDictionarySetValue(localeiconvdict, key, newval);
		CFRelease(key);
		return newval;
	}
	{
		size_t iclen = strlen(newval);
		char *newival = (char *)malloc(iclen + 8);
		size_t ilen, olen;
		char *iptr, *optr;

		if (!newival) {
			if (newvalalloc) free(newval);
			CFRelease(key);
			return (char *)msgid;
		}
		iconv(ic, NULL, NULL, NULL, NULL);
		iptr = newval;
		optr = newival;
		ilen = iclen;
		olen = iclen + 7;
		if (iconv(ic, (iconv_p2)&iptr, &ilen, &optr, &olen) != (size_t)-1) {
			*optr = '\0';
			CFDictionarySetValue(localeiconvdict, key, newival);
			if (newvalalloc) free(newval);
			CFRelease(key);
			return newival;
		}
		free(newival);
		if (newvalalloc) free(newval);
		CFRelease(key);
	}
	return (char *)msgid;
}
