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
