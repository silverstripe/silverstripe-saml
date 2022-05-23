<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Technical notes](#technical-notes)
  - [Interface between SAML and LDAP](#interface-between-saml-and-ldap)
  - [SAML+LDAP sequence](#samlldap-sequence)
  - [Member record manipulation](#member-record-manipulation)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Technical notes

## Interface between SAML and LDAP

The SAML and LDAP ([separate module](https://github.com/silverstripe/silverstripe-ldap)) components interact only through the following two locations:

* `GUID` field on `Member`, added by both `SAMLMemberExtension` and `LDAPMemberExtension`.
* `LDAPMemberExtension::memberLoggedIn` login hook, triggered after any login (including after
`SAMLAuthenticator::authenticate`)

## SAML+LDAP sequence

Normal sequence, involving single sign-on and LDAP synchronisation:

1. User requests a secured resource, and is redirected to `SAMLLoginForm`
1. User clicks the only button on the form
1. `SAMLAuthenticator::authenticate` is called
1. User is redirected to an Identity Provider (IdP), by utilising the `SAMLHelper` (and the contained library)
1. User performs the authentication off-site
1. User is sent back to `SAMLController::acs`, with an appropriate authentication token
1. If `Member` record is not found, stub is created with some basic fields (i.e. GUID, name, surname, email), but no group
mapping.
1. User is logged into SilverStripe as that member, considered authenticated. GUID is used to uniquely identify that
user.
1. A login hook is triggered at `LDAPMemberExtension::memberLoggedIn`
1. LDAP synchronisation is performed by looking up the GUID. All `Member` fields are overwritten with the data obtained
from LDAP, and LDAP group mappings are added.
1. User is now authorised, since the group mappings are in place.

## Member record manipulation

`Member` records are manipulated from `SAMLAuthenticator::authenticate` in this module. Members are identified by GUIDs by both LDAP
and SAML components.

* `SAMLAuthenticator::authenticate`: creates stub `Member` after authorisation (if non-existent).

Records are manipulated in multiple places in the LDAP module (if you have it installed):

* `LDAPAuthenticator::authenticate`: creates stub `Member` after authorisation (if non-existent).
* `LDAPMemberExtension::memberLoggedIn`: triggers LDAP synchronisation, rewriting all `Member` fields.
* `LDAPMemberSyncTask::run`: pulls all LDAP records and creates relevant `Members`.

## NameID Validation

Note that NameID validation is not essential to security and since most IdPs don't clarify format, validation is disabled by default.

This section is very much configuration over convention. You should establish a stable nameID (format and claim source) with
your IdP administrator rather than account for every case.

**The size of the NameID is always validated to check if it will fit in the `GUID` field on `Member` (`DBVarchar(50)`).**

Regarding this limit on the `GUID` field you can raise that (including the validation limit) via:
```yml
SilverStripe\Security\Member:
  db:
    GUID: 'Varchar(0-255)'
```
as long as this config has a higher [priority](https://docs.silverstripe.org/en/4/developer_guides/configuration/configuration/#before-after-priorities) than `SilverStripe\SAML\Extensions\SAMLMemberExtension`.
This is not recommended if you already have data you don't plan on migrating within the GUID column.

Some very basic NameID validation is available. You can enable this via the following config:
```yml
SilverStripe\SAML\Services\SAMLConfiguration:
  validate_nameid: true
```

Out of the box the GUID NameID format is registered for Azure AD and ADFS. You can add more via extensions.

For example adding Email validation for a response with the nameid format `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`:
```php
<?php

namespace ACME\SAML\Extensions;

use SilverStripe\Core\Extension;

/**
 * Class EmailNameIDValidationExtension
 * 
 * Validates a NameID in email form.
 */
class EmailNameIDValidationExtension extends Extension
{
    public function updateNameIDValidation(string $nameID, string $nameIDFormat): bool
    {
        if ($nameIDFormat !== 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') {
            return false;
        }

        return (bool) filter_var($nameID, FILTER_VALIDATE_EMAIL);
    }
}
```
```yml
SilverStripe\SAML\Services\SAMLConfiguration:
  extensions:
    - ACME\SAML\Extensions\EmailNameIDValidationExtension
```