Patches Information
===================

The various patches, enhancements and downright replacements used to build
the version of Git and supplementary software included in the Git OS X
Installer are collected here.

For the files/patches included herein, some have explicit licenses embedded
within them (typically GPLv2).  For the ones that do not explicitly mention
a license the standard Git license applies -- this is especially true for
any 'Signed-off-by' patches taken from the Git mailing list.  The standard
Git license is GPLv2 ONLY.

Other files that do not have an explicit license and did not come from the
Git mailing list are my own code and where the source file does not say
otherwise are licensed under GPLv2 or, at your option, any later version.


Git Patches
-----------

* Use Mac OS X native API to show language translations

  - `src/build-prefix.h`
  - `src/gettext.c`
  - `src/gettext-util.c`
  - `patches/git-sh-i18n-sh-git_gettext.diff`
  - `patches/git-gettext-failures.diff`

* Use libcurl for imap send

  - `patches/km/git-imap-send_use_libcurl.txt`

  This enables using CRAM-MD5 in an imap tunnel without needing OpenSSL.

* Use libcurl for send email

  - `patches/km/git-send-email-libcurl.txt`

  My own patches to make `git-send-email.perl` use libcurl instead of
  OpenSSL.  Has not been posted elsewhere.

* Use fgetln when getdelim is not available

  - `patches/km/strbuf_getwholeline-fgetln.txt`

  My own patches to make `strbuf_getwholeline` use fgetln when called with
  a delimiter of `\n` if fgetln is available but getdelim is not.
  Has not been posted elsewhere.

* Use a different pack.windowmemory default setting instead of 0

  - `patches/windowmemory/q/t_util_sys__memsize.diff`
  - `patches/windowmemory/q/t_gc_default-windowmemory.diff`

  My own patches to change the pack.windowmemory default from 0 (meaning
  unlimited) to a sane default that should avoid memory thrashing especially
  when running gc --aggressive with a 64-bit address space.  Has not been
  posted elsewhere.

* Avoid PERL5LIB etc. variable conflicts

  - `patches/km/no-perl-vars.txt`

  My own patch to unset troublesome Perl environment variables before running
  subcommands.  This prevents incompatible PERL5LIB libraries from being picked
  up by Git's perl-based utilities.  Has not been posted elsewhere.

* Make git-remote-mediawiki work properly:

  - `patches/mediawiki/q/t_mediawiki_no-dupes.diff`
  - `patches/mediawiki/q/t_mediawiki_namespaces.diff`
  - `patches/mediawiki/q/t_mediawiki_max-revision.diff`
  - `patches/mediawiki/q/t_mediawiki_mediaimport.diff`
  - `patches/mediawiki/q/t_mediawiki_many-revisions.difff`
  - `patches/mediawiki/q/t_mediawiki_empty-commit.diff`
  - `patches/mediawiki/q/t_mediawiki_skip-notfound-media.diff`

  My own patches to make git-remote-mediawiki work properly.  The no-dupes
  patch avoids importing more than one copy of the same history (typically it
  would import two copies).  The max-revision patch allows it to actually find
  the correct maximum revision so that a fetchStrategy of 'by_rev' can work
  properly.  The namespaces patch allows a 'by_rev' fetchStrategy to fetch an
  update regardless of what namespace it's located in when no pages or
  categories have been set to otherwise limit the import.  The mediaimport
  patch allows it to actually find the media to import when the mediaimport
  flag is set to true and the media has a timestamp that does not exactly match
  the page's down to the last second.  The many-revisions patch allows a
  fetchStrategy of 'by_rev' to succeed when the number of revisions that need
  to be fetched is very large.  The empty-commit patch preserves a MediaWiki
  revision that only has a comment which can happen if the revision data has
  somehow been obliterated.  And finally the skip-notfound-media patch treats
  a 404 (and 403) error the same as an imageinfo query that finds nothing when
  mediaimport has been enabled.  Have not been posted elsewhere.

* Improve usability of git-instaweb:

  - `patches/instaweb/q/t_instaweb_highlight.diff`
  - `patches/instaweb/q/t_instaweb_mimetypes.diff`
  - `patches/instaweb/q/t_instaweb_defaults.diff`
  - `patches/instaweb/q/t_instaweb_git-browser.diff`
  - `patches/instaweb/q/t_instaweb_ipv6.diff`
  - `patches/instaweb/q/t_instaweb_fcgi.diff`
  - `patches/instaweb/q/t_instaweb_readme.diff`
  - `patches/instaweb/q/t_instaweb_default-to-local.diff`
  - `patches/instaweb/q/t_instaweb_no-kill-nothing.diff`
  - `patches/instaweb/q/t_instaweb_auto-port.diff`
  - `patches/instaweb/q/t_instaweb_restrict-bare.diff`
  - `patches/instaweb/q/t_instaweb_worktree.diff`

  My own patches to improve the usability of git instaweb by enabling source
  highlighting if highlight is available, using the installed copy of
  mime.types (since there isn't such a file in OS X), enabling pathinfo mode,
  blame and better rename detection, adding a 'graphiclog' link to the pages
  that uses git-browser to show a graphic representation of commit ancestry,
  binding to both IPv4 and IPv6 addresses and browsing to localhost instead of
  127.0.0.1, enabling readme blob display, defaulting to binding only to the
  localhost address if `instaweb.local` has not been set at all, avoiding
  attempting to kill using a process id of "", attempting to automatically
  select an available port to listen on if one was not specified and the first
  chosen port is not available and finally set the gitweb configuration item
  $projects_list_restrict when running in a bare repository.  The ipv6 patch is
  only effective when using lighttpd as the web server (which is the default).
  The fcgi patch enables FCGI mode when the needed FCGI perl module is present.
  The worktree patch makes instaweb work properly when used with `git worktree`
  instances.  Have not been posted elsewhere.

* Add submodule support to gitweb:

  - `patches/gitweb/q/gitweb-find-project-dirs-with-.git-gitdir-links.diff`

  My own patch to allow gitweb to find submodules that use gitdir links.  With
  this patch using git instaweb in a working tree that contains checked-out
  submodules makes it very easy to browse the submodules -- without the patch
  they are not listed in the gitweb projects list.  Has not been posted
  elsewhere.

* Add $projects_list_restrict support to gitweb:

  - `patches/gitweb/q/gitweb-support-projects_list_restrict.diff`

  My own patch to allow gitweb to restrict the projects found when
  $projects_list is set to a directory to only those in a single subdirectory
  or those with a full path that matches a specified regular expression.
  Has not been posted elsewhere.

* Various gitweb bug fixes / enhancements:

- `patches/gitweb/q/*.diff`

  A selection of various patches from Girocco's [1] custom version of
  gitweb [2] that vastly improves the usability of git instaweb by making
  gitweb work so much better.

  [1] <http://repo.or.cz/w/girocco.git>  
  [2] <http://repo.or.cz/w/git/gitweb.git/blob/girocco:README_FIRST.txt>

* contrib/git-log-compact:

  - `patches/km/contrib-git-log-compact.txt`

  My own patch that adds contrib/git-log-compact a git log --oneline alternative
  that includes dates, times and initials.  See the README file in the patch or
  visit [3] for detailed information and screen shots.

  [3] <https://mackyle.github.io/git-log-compact/>


Curl Patches
------------

In order to provide compatibility with Mac OS X 10.4 AND web sites using
SHA-256/SHA-384 hashes in their certificates, the version of libcurl that has
been included as part of the Git OS X Installer uses the darwinssl backend
that relies on Secure Transport instead of OpenSSL.

Unfortunately the released version of the darwinssl backend has many
deficiencies that make it unsuitable for use as a replacement when users are
expecting to be able to provide multiple client certificates possibly combined
with an RSA private key all in PEM format.

Additionally the as-released darwinssl backend doesn't really work on older
Mac OS X versions as-is.  Oh it may compile on Mac OS X 10.5 without complaints
but it immediately crashes and burns when one tries to use it.  And it does not
support Mac OS X 10.4 at all as released.

* Curl darwinssl backend universal Mac OS X compatibility

  - `patches/curl/curl_darwinssl_macosx.c`
  - `patches/curl/stcompat.c`
  - `patches/curl/stcompat.h`
  - `patches/curl/q/t_ntlm_no-one-shot.diff`
  - `patches/curl/q/t_securetransport_extra-data.diff`
  - `patches/curl/q/t_pinning_darwin.diff`
  - `patches/curl/q/t_pinning_dummy-key.diff`
  - `patches/curl/q/t_docs_manpage.diff`

* Curl mk-ca-bundle script improvements

  - `patches/curl/q/t_mk-ca-bundle_improvements.diff`


PCRE Patches
------------

The PCRE library provides a POSIX wrapper that allows the PCRE library to be
used in place of the regular POSIX regex routines.  Unfortunately, the standard
PCRE wrapper lacks full POSIX compatibility for the REG_NEWLINE option and does
not have any BRE (Basic Regular Expression) support at all.

These patches provide a fully usable `regex.h` substitute via an enhanced and
completely POSIX compatible pcreposix library which allows it to be used with
Git so that the Git NO_REGEX compilation option can be avoided.

The Git NO_REGEX compilation option causes a Git-provided regular expression
library to be used.  Unfortunately, it has some severe problems and is best
avoided.  For full details see <https://github.com/mackyle/pcreposix-compat>.

With these patches, the PCRE posix wrapper library is used to replace the
unwanted Git NO_REGEX compatibility library with a much more robust version
that uses the PCRE backend.

* PCRE pcreposix improvement patches

  - `patches/pcreposix/0001-pcre-extended-options.diff`
  - `patches/pcreposix/0002-posix-reg-newline.diff`
  - `patches/pcreposix/0003-posix-reg-basic.diff`
  - `patches/pcreposix/0004-compat-reg-nospec.diff`
  - `patches/pcreposix/0005-compat-reg-pend.diff`
  - `patches/pcreposix/0006-posix-reg-extended.diff`
  - `patches/pcreposix/0007-extras-reg-pcre.diff`
  - `patches/pcreposix/0008-posix-defines-not-enum.diff`
  - `patches/pcreposix/0009-posix-regoff-type.diff`
  - `patches/pcreposix/0010-compat-reg-startend.diff`
  - `patches/pcreposix/0011-compat-version.diff`
  - `patches/pcreposix/0012-compat-readme.diff`


Lighttpd Patches
----------------

* Provide an idle timeout option

  - `patches/lighttpd/q/t_server_idle-timeout.diff`

* A couple of other lighttpd patches are included to
  avoid having to maintain multiple patch series, but
  their changes are not relevant to the Git OS X Installer.


GnuPG Patches
-------------

The standard build of gpg does not allow one to create any keys with bit
lengths larger than 4096 bits.  (Once created, existing versions of gpg can
use such a key without problems.)  However, according to NIST 800-57, an RSA
key 3072 bits in length only provides 128 bits of security strength.  In order
to comply with NIST policy on the use of AES to protect national information
and meet the TOP SECRET requirements a security strength of at least 192 bits
is required.  That necessitates an RSA key of 7680 bits (see NIST 800-57).
Hence the gpg patch to permit creation of such keys.

* Always allow larger RSA keys up to 16384 bits to be created

  - `patches/gnupg/q/t_gnupg_longer-keys.diff`

* Make trailing ":pid:protocol" part of GPG_AGENT_INFO optional (launchd)

  - `patches/gnupg/q/t_launchd_agent-compat.diff`


Compatibility Patches
---------------------

Other than the giant Curl darwinssl backend patch, some other compatibility
patches are needed in order to build for Mac OS X 10.4 without losing any
functionality.

These consist of the remaining files in the include and src subdirectories
and provide the following compatibility fixes:

* Curl support for NTLM on Mac OS X 10.4

  Special thanks to Libtomcrypt <http://libtom.org/> for providing a public
  domain version of DES needed to make this work.

* Git support CRAM-MD5 when `git-imap-send` is using a tunnel

  This is really just some glue and an implementation of HMAC MD5 based
  on RFC 2104 that uses the OS X Common Crypto MD5 hash implementation.

* GnuPG support using libedit instead of libreadline

  This is just some simplistic linker glue (`src/gnupgcompat.c`) and a clever
  compiler prefix file (`src/gnupg-prefix.h`).


Other Stuff
-----------

For the neophyte using gpg the first time can be rather intimidating.  To this
end a copy of the GNU Privacy Handbook has been included here in doc/gnupg.  It
has not been modified and was simply copied from the original location at
<https://www.gnupg.org/gph/en/manual.html>.
