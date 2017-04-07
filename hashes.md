Git OS X Installer Hashes
=========================

The list of hashes for each released version of the Git OS X Installer can be
found below under the matching "Git X.X.X OS X Installer" heading where
"X.X.X" is replaced with the version of the installer in question.

The part of this document between here and the first one of those headings
contains ad nauseam instructions for verifying the hashes -- just skip right
over those sections if you already know what to do 'cause there's nothing new
for you to see in them otherwise.


Downloads
---------

Installer download links are available from the Git OS X Installer home page
accessible at:

  * https://mackyle.github.io/git-osx-installer
  * http://mackyle.github.io/git-osx-installer


GPG Public Signing Key
----------------------

In case it's not clear from the instructions below, the public GPG key needed
to verify the signed tags is in the blob signed with the `mackyle-gpg-pub` tag.

Use `git show mackyle-gpg-pub` after cloning the repository (see below for
a list of available repository clone URLs) for detailed instructions.


Verifying Signed Hashes
-----------------------

The hashes listed here are signed by a Git tag with the same name as the
Git version being installed by the installer.

This document (`hashes.txt` aka `hashes.md`) can be found in the `www`
subdirectory of a `git checkout` of any of the signed tags starting with
version v2.11.1.

For earlier versions, the older versions' hashes are also included in the
v2.11.1 and later signed versions of this document, but they are also available
in either the `feed.atom` or `index.html` file in the same `www` subdirectory
of the checkout of the signed tag corresponding to the older versions (note
that the v2.1.4 tag only has `index.html` available).

If you have a `git clone` of the Git OS X Installer repository (see the next
section for a veritable plethora of `git clone` URLs you can use) you may do:

    git checkout v2.11.1      # or whatever version you are interested in
    git show mackyle-gpg-pub  # shows instructions for verifying the tag
    less www/hashes.txt       # views this file (v2.11.1 and later tags only)

To verify using a web browser, follow these steps:

 1. Go to https://github.com/mackyle/git-osx-installer/tags
 2. Find the tag for the version you are interested in (they should all show
    a "Verified" button to their right)
 3. Click on the tag's name (e.g. "v2.11.1")
 4. Notice the "Verified" button to the left of the tag on the new page
 5. Click on the little price tag icon that's just a bit above the "Verified"
    button (be sure to click that and NOT the hexadecimal line below it!)
 6. If you clicked the correct link you will end up at a URL that ends in
    the tag name you're interested in immediately preceded by "/tree/" e.g.
    something like https://github.com/mackyle/git-osx-installer/tree/v2.11.1
 7. Click on the "www" link with the folder icon to its left to navigate into
    the "www" subdirectory
 8. For tag versions v2.11.1 or later click the "hashes.md" link to view
    the verified signed tag version of this document or (for earlier versions)
    pick either the "feed.atom" or "index.html" links (v2.1.4 only has the
    "index.html" link available)
 9. Use your favorite checksum generating tool to verify that the hash(es) of
    the installer ".dmg" file you downloaded match the listed values for the
    version you downloaded -- NEVER use the downloaded installer if the hashes
    do not match!

If you have the file `git-2.11.1-osx-installer.dmg` in the current directory,
these commands can be used to compute its hashes for verification:

    git hash-object --no-filters git-2.11.1-osx-installer.dmg # BLOB hash
    openssl dgst -sha256 git-2.11.1-osx-installer.dmg         # SHA256 hash
    openssl dgst -sha1 git-2.11.1-osx-installer.dmg           # SHA1 hash
    openssl dgst -md5 git-2.11.1-osx-installer.dmg            # MD5 hash

Other tools can also be used (`sha1sum`, `md5sum`, etc.) but most folks will
have the `openssl` command (via either OpenSSL or LibreSSL) or already have
an older version of Git installed.  Relying on only the SHA1 or MD5 hash is
not recommended (especially in light of <https://shattered.it/>), but using
BOTH is a reasonable compromise if you do not have an an SHA-256 capable
`openssl` command (older Mac OS X versions) and you don't have a version of
Git installed on your machine yet (also likely for older Mac OS X versions).


Repository Access
-----------------

The Git OS X Installer repository may be web browsed at any of these URLs:

 * https://github.com/mackyle/git-osx-installer
 * https://bitbucket.org/mackyle/git-osx-installer
 * http://repo.or.cz/git-osx-installer

The Git OS X Installer repository may be cloned from any of these URLs:

 * https://github.com/mackyle/git-osx-installer.git
 * https://bitbucket.org/mackyle/git-osx-installer
 * ssh://git@repo.or.cz/git-osx-installer
 * http://repo.or.cz/git-osx-installer
 * git://github.com/mackyle/git-osx-installer.git
 * git://repo.or.cz/git-osx-installer


Git 2.11.1 OS X Installer
-------------------------

    TAG:    v2.11.1
    SIZE:   13539616 bytes
    MD5:    5c60b689a247a82db0959fa6ae6f6009
    SHA1:   170d4003995b3f61e9d90c4dce26d952e6a3233f
    BLOB:   7b05ded6a165654adaa523a7e36d78b12b80c626
    SHA256: f0ecff26a593f7586834df12091ea12f222e0741653241049b35e9584e63ef56


Git 2.10.2 OS X Installer
-------------------------

    TAG:    v2.10.2
    SIZE:   13411504 bytes
    MD5:    4f09d2549b83163b2682122d1232119b
    SHA1:   c4bd2a83bf311dbb02be468ea101790c62f1d8ca
    BLOB:   78be32e00b9b462afd50ddef65919ab5df261eda
    SHA256: 87f08933c79c0de8217ccb8028870a491c2c5c40ec158b91da48f8c4130c1fd6


Git 2.9.3 OS X Installer
------------------------

    TAG:    v2.9.3
    SIZE:   13500993 bytes
    MD5:    b573c09bff0acd532c952659a64c66ca
    SHA1:   3a0f7cd4827c267f1750e20cb11f57ca91ca0941
    BLOB:   ec857b1f42d0ce7965a91e17ea8a26b00fc5e8c5
    SHA256: 012f03a068551f68ea92063c113c56894b30915b3e4f7c27a8cfb7d02a278ce2


Git 2.8.4 OS X Installer
------------------------

    TAG:    v2.8.4
    SIZE:   13385231 bytes
    MD5:    664ef90eb20ee614723293ed58b7a025
    SHA1:   63422bcd9795892a5e2a5effdf974115ca5082fa
    BLOB:   deded1a6d81a7c209f6e1cc6324ba6ad8f8776af
    SHA256: 6075bf151d04e639dd4d574f05e87ff89cc203d92e26712ea8a61f9e7d720e79


Git 2.8.3 OS X Installer
------------------------

    TAG:    v2.8.3
    SIZE:   13385591 bytes
    MD5:    23e75353fc4e9011fb680986b9df05d9
    SHA1:   32864aec4b043acd7fc2d0fd89c3e9ba5b00cd60
    BLOB:   6dc9c5008915991c64b25c3db1265191b53083f1
    SHA256: fa7f304c47d5695e746dcd9c8ec1f7ad781231dcb7c28cf050444fc63b4365d5


Git 2.8.2 OS X Installer
------------------------

    TAG:    v2.8.2
    SIZE:   13077180 bytes
    MD5:    fc63a827021acc3983b9a8c25b8f44bb
    SHA1:   0089923eb7e18efc4ecb90f7177adcd5a7f4b2d5
    BLOB:   b312d624f062f46947675b725aea195793259c93
    SHA256: 78a9eab23d124bbc37e162a6976623706620bd86cb3a22233d1fb68c8a0856c2


Git 2.7.4 OS X Installer
------------------------

    TAG:    v2.7.4
    SIZE:   12973229 bytes
    MD5:    d9bbd22ce3e1f1db4ec9e5ee7ea5e867
    SHA1:   fdadefcb27930295ea15b8299b4e61530fedd9bd
    BLOB:   7d8f07c28e2734a85959f531d3aa4b6893aff2c0
    SHA256: ad43775d0a419695db67f74e14607743e21e6ca210bb9b12d36e2da0e0b559e0


Git 2.7.2 OS X Installer
------------------------

    TAG:    v2.7.2
    SIZE:   12976946 bytes
    MD5:    8b975731ac1744460c4a8b5a3a25c9a7
    SHA1:   bb149bf72bb854b2c059397774a52da57aa3b4a3
    BLOB:   ed9850a7eeee5bebd9640d3c81af3d72d1187aee
    SHA256: 2fc3577a742c4773ce4ed06916bc40517833256c4765e7d4738d6adc92e98a51

  Note: This version is no longer recommended.


Git 2.6.6 OS X Installer
------------------------

    TAG:    v2.6.6
    SIZE:   12892815 bytes
    MD5:    c9d53f8eafad3c40d0a21c31f1ef33b3
    SHA1:   4907db759b6eb504c8b4c4f937bb5ddae0186073
    BLOB:   3552d31b29e8a09552913e23f71b3b51fb69ae77
    SHA256: c733dfcff8b4cbf54ea7448959ff1767284180426c82224914d4406b1575ff09


Git 2.6.5 OS X Installer
------------------------

    TAG:    v2.6.5
    SIZE:   12894850 bytes
    MD5:    fafa263802b7d1d6e2790376efe06a0b
    SHA1:   7d37273d9f450e22bc1d95158d91b4be82781a1c
    BLOB:   11f92468b50873b040eba8a1e5eb9c67cfdb3967
    SHA256: 24960ff9d3d4be85cad1e3a9c72c2f9a176fa39382c0ac0560b4f9caf929f18a

  Note: This version is no longer recommended.


Git 2.5.5 OS X Installer
------------------------

    TAG:    v2.5.5
    SIZE:   12722289 bytes
    MD5:    cd4ddf472b1389979a0ea85cec0b97f0
    SHA1:   7f031f322cb8296fb376c83a7cc0dd196a741ccd
    BLOB:   31fc189c04f0f391d5b1f0a8f04c6d1eb6e76d7d
    SHA256: 8957e634b3ca65ac1e4b53b2ea447bdccbf439c538dc23b3a04d22160352fecc


Git 2.5.4 OS X Installer
------------------------

    TAG:    v2.5.4
    SIZE:   12719309 bytes
    MD5:    da0810616bcf363d6042c04cf7935ff5
    SHA1:   d6538a55e51f2f85bd1605d7824d4a3056716bdc
    BLOB:   2f89c16737915c10bef82a06fdd80721bd38154e
    SHA256: 4f258fa73937c2a220c6b996831ecbb2e4d0601ae4cf64cc5fe315c3d214713d

  Note: This version is no longer recommended.


Git 2.4.11 OS X Installer
-------------------------

    TAG:    v2.4.11
    SIZE:   12646061 bytes
    MD5:    7986123c8cbb0a01dd69eb2ff912886a
    SHA1:   e10ba213305a7bcb5d74f4947d418afa59aa0665
    BLOB:   6ad8d8b259cde78e66856b7b35047e32517d0f22
    SHA256: 20d85f3d71389ca795696c98bdf5482d339c084c1f46817452a2918c14088629


Git 2.4.10 OS X Installer
-------------------------

    TAG:    v2.4.10
    SIZE:   12552395 bytes
    MD5:    3550c8079f6923cdbac4923f45fe16ac
    SHA1:   59aa26e0ba61bac0ab23b81ea1b7172bf33f704a
    BLOB:   3be9f172fea4fd951a15ea0dd32e26b5d4ce4e23
    SHA256: 8100a9757005737427cf5977f61e090c2472662cf69f570a434093d9db1714b2

  Note: This version is no longer recommended.


Git 2.3.10 OS X Installer
-------------------------

    TAG:    v2.3.10
    SIZE:   12375288 bytes
    MD5:    c5de880533715eeab4f1f598e46d0bba
    SHA1:   19be02affaa152e9802dca908e10e72e89b976fb
    BLOB:   1e502d1e57efff63080bcca95a49f8c3a30bdb04
    SHA256: 0fbdce3c5059cc354cd3c4a0ad78ff2604b51213a861f21b9d191ddb501205e1

  Note: This version is no longer recommended.


Git 2.3.9 OS X Installer
------------------------

    TAG:    v2.3.9
    SIZE:   12366733 bytes
    MD5:    ebe202b389ffb4ec4c801c6e67092c10
    SHA1:   6590b6805efdb68d48d136b8f5286876f5319030
    BLOB:   9818ef806a3f11316970a6a8ccb1c69dff6da41c
    SHA256: 931e4da909adb77190733b113445bbf46a400125be9a5dfa6d3674bcab042613

  Note: This version is no longer recommended.


Git 2.3.3 OS X Installer
------------------------

    TAG:    v2.3.3
    SIZE:   11977353 bytes
    MD5:    c0c83704785fc25f249051b5421e6bfe
    SHA1:   a937a247ec164357914ba04ba9e4d8c71fb0fd9a
    BLOB:   e0c8ef4720a90546e8ea3b12a7e38223f1bad83f
    SHA256: 587bbb92db27c6af27603397dae10334203c0e8693d7fa289b41ca704584a50a

  Note: This version is no longer recommended.


Git 2.3.2 OS X Installer
------------------------

    TAG:    v2.3.2
    SIZE:   11964730 bytes
    MD5:    2abaf1c17ba4911a3cc4f553d0bb5880
    SHA1:   2fa4e53fdcee29ca6414b9b906cbb013e9afbaf7
    BLOB:   d4d5114cb4755578403f1536d41824c872be9433
    SHA256: 49ee8daa770f9a1ea37fc297f2cddee00c5672fd8cb2c20c3a3afbe8ede81ec7

  Note: This version is no longer recommended.


Git 2.2.2 OS X Installer
------------------------

    TAG:    v2.2.2
    SIZE:   11414459 bytes
    MD5:    4d818156d6f67b0189f56c453e7deec3
    SHA1:   67ea4e2fda289e5cbcb293d2879f7aeefb76cf97
    BLOB:   80fc86e2dc53049bf7c3e7515aaa685ba154e8cb
    SHA256: 713ca9cad446c4cb93465fd7eaaa382b6ffcd9502ea358563e6b8cc83daa22aa

  Note: This version is no longer recommended.


Git 2.1.4 OS X Installer
------------------------

    TAG:    v2.1.4
    SIZE:   11243134 bytes
    MD5:    3608f85b7b2c6a855d4f7906db0e7f3f
    SHA1:   152447ea9b2086275a0d4e56a7d97455a8cbae56
    BLOB:   131f919be411bdd817fb5c5bd005feacb0a0d536
    SHA256: dacf300a3d4e7821ae0db947c8498b6ce14f96d91ffc1a7c4107a61a95294836

  Note: This version is no longer recommended.
