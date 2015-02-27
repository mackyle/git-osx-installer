#ifdef GETTEXT_DEFINES_GET_PREFERRED_LANGUAGES

/* From the original gettext.c file after the Add Accept-Language patch added */

const char *get_preferred_languages(void);

/*
 * Guess the user's preferred languages from the value in LANGUAGE environment
 * variable and LC_MESSAGES locale category if NO_GETTEXT is not defined.
 *
 * The result can be a colon-separated list like "ko:ja:en".
 */
const char *get_preferred_languages(void)
{
	const char *retval;

	retval = getenv("LANGUAGE");
	if (retval && *retval)
		return retval;

#ifndef NO_GETTEXT
	retval = setlocale(LC_MESSAGES, NULL);
	if (retval && *retval &&
		strcmp(retval, "C") &&
		strcmp(retval, "POSIX"))
		return retval;
#endif

	return NULL;
}

#endif /* GETTEXT_DEFINES_GET_PREFERRED_LANGUAGES */
