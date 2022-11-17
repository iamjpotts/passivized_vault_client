
A client library for working with [Vault](https://www.vaultproject.io/) through its 
[REST api](https://www.vaultproject.io/api-docs).

## Capabilities

### Initialization and Setup

* Generation of clear or encrypted unseal keys
* Generation of root token 
* Generation of clear or encrypted recovery keys
* Configuring transit keys and transit unseal

### Policies

* Create, update, and list policies
* Attach policies to userpass users

### Monitoring

* Getting status

### Username/Password Authentication

* Create user and get details
* Update passwords
* List users
* Login (validate password and get Vault token)
* Delete

## Limitations

See the warning on [REST api](https://www.vaultproject.io/api-docs):

    Backwards compatibility: At the current version, Vault does not yet promise backwards compatibility even with the v1
    prefix. We'll remove this warning when this policy changes. At this point in time the core API
    (that is, sys/ routes) change very infrequently, but various secrets engines/auth methods/etc. sometimes have minor
    changes to accommodate new features as they're developed.

The above warning means this library could potentially break with newer versions of Vault.

The library is experimental, and currently tested only with Vault 1.11.

## GPG Key Generation

To demo using PGP (GPG) to encrypt the unseal keys and root tokens generated by
Vault, you can create several fake users, each with their own key pair.

    $ gpg --quick-generate-key operator1@testuri.org
    $ gpg --quick-generate-key operator2@testuri.org
    $ gpg --quick-generate-key operator3@testuri.org
    $ gpg --quick-generate-key root-user@testuri.org

Listing key pairs having private keys:

    $ gpg -K

Export the public keys of each key pair:

    $ gpg --output operator1.pgp --export operator1@testuri.org
    $ gpg --output operator2.pgp --export operator2@testuri.org
    $ gpg --output operator3.pgp --export operator3@testuri.org
    $ gpg --output root-user.pgp --export root-user@testuri.org

    Note: DO NOT use the "--armor" flag - Vault requires binary public keys.


## Platforms

### Linux

All library features are available on Linux.

### Mac

All library features are available on Macs, but because of limitations of Docker networking on Macs,
all automated tests that require a live Vault server are disabled.

### Windows

All library features are available on Windows, but because Hashicorp does not offer a Windows build of the Vault server,
all automated tests that require a live Vault server are disabled.
