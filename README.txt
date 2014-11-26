Git OS X Installer
==================

Patches (see the README_PATCHES.txt file) to build a version of Git for Mac OS X
10.4.8 and later (PPC/X86/32/64) that includes the Git translations (optionally
selected based on System Preferences > International > Languages) and integrates
well with the native OS X libraries.

The built version of Git uses Secure Transport (via a very enhanced version of
curl's darwinssl backend) to fully support SHA-256 https certificates on
Mac OS X 10.4 and Mac OS X 10.5 without need for a custom build of OpenSSL.

All certificates for https/smtps/imaps verification come from the standard
system keychain locations (unless one of the Git certificate configuration
options is used).

Patches are also included to allow GnuPG to generate larger RSA keys (again,
see README_PATCHES.txt for details).

Pre-built installers that include Git, TopGit (optional), curl comand line
utility (optional) and GnuPG (optional) can be found in the releases area at:
<https://github.com/mackyle/git-osx-installer/releases>.

See the Git OS X Installer home page at:
<http://mackyle.github.io/git-osx-installer>
