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

  - `patches/br/git-imap-send_use_libcurl.txt`

  This is a backport of v1 of the patch from the mailing list at:
  <http://article.gmane.org/gmane.comp.version-control.git/255954>.
  Additionally it has the strbuf leak fixes suggested on the list at:
  <http://article.gmane.org/gmane.comp.version-control.git/259120>
  and the GIT_CURL_VERBOSE and CURLUSESSL_TRY fixes posted to the list at:
  <http://thread.gmane.org/gmane.comp.version-control.git/262057>
  <http://thread.gmane.org/gmane.comp.version-control.git/262058>.

* Use libcurl for send email

  - `patches/km/git-send-email-libcurl.txt`

  My own patches to make `git-send-email.perl` use libcurl instead of
  OpenSSL.  Has not been posted elsewhere.

* Support Tcl 8.4 for git-gui

  - `patches/km/git-gui-tcl-8_4.txt`

  My own patch to make git-gui actually work with Tcl 8.4 which is all
  it's supposed to require.  Posted to the list and picked up at:
  <http://thread.gmane.org/gmane.comp.version-control.git/262055>.

* Support auto threads detection on older OS X

  - `patches/km/thread-utils-osx.txt`

  My own patch to make thread-utils.c online_cpus function return the
  correct value on older Mac OS X versions.  Has not been posted elsewhere.

* Use a different pack.windowmemory default setting instead of 0

  - `patches/km/window-memory-default.txt`

  My own patch to change the pack.windowmemory default from 0 (meaning
  unlimited) to a sane default that should avoid memory thrashing especially
  when running gc --aggressive with a 64-bit address space.  Has not been
  posted elsewhere.

* Avoid PERL5LIB etc. variable conflicts

  - `patches/km/no-perl-vars.txt`

  My own patch to unset troublesome Perl environment variables before running
  subcommands.  This prevents incompatible PERL5LIB libraries from being picked
  up by Git's perl-based utilities.  Has not been posted elsewhere.

* Allow notes refs to be anywhere if given in full

  - `patches/sc/any-notes-ref.txt`
  - `patches/km/any-notes-ref-tests.txt`

  Both patches included in the thread and discussion at:
  <http://thread.gmane.org/gmane.comp.version-control.git/257281>.

* Create update-server-info files with correct permissions

  - `patches/jk/update-server-info-fix.txt`

  Available from the list and picked up to hopefully be in a maint update.
  <http://thread.gmane.org/gmane.comp.version-control.git/262026>.

* Make git-http-push work with cURL >= 7.40

  - `patches/jk/curl-740-fix.txt`

  Available from the list and picked up to hopefully be in a maint update.
  <http://thread.gmane.org/gmane.comp.version-control.git/262323>.


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
but it immediately crashes and burns when you try to use it.  And it does not
support Mac OS X 10.4 at all as released.

* Curl darwinssl backend universal Mac OS X compatibility

  - `patches/curl/curl_darwinssl_macosx.c`
  - `patches/curl/ntlm_core_no_oneshot_patch.txt`
  - `patches/curl/stcompat.c`
  - `patches/curl/stcompat.h`
  - `patches/curl/urldata_add_khra_patch.txt`

* Curl mk-ca-bundle script improvements

  - `patches/curl/mk-ca-bundle_improvements.txt`


GnuPG Patches
-------------

The standard build of gpg does not allow one to create any keys with bit
lengths larger than 4096 bits.  (Once created, existing versions of gpg can
use such a key without problems.)  However, according to NIST 800-57, a RSA key
3072 bits in length only provides 128 bits of security strength.  In order to
comply with NIST policy on the use of AES to protect national information and
meet the TOP SECRET requirements a security strength of at least 192 bits is
required.  That necessitates an RSA key of 7680 bits (see NIST 800-57).  Hence
the gpg patch to permit creation of such keys.

* Allow larger RSA keys to be created

  - `patches/gnupg/allow_longer_keys.txt`


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
