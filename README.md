# SilverStripe SAML module

[![Build Status](https://travis-ci.org/silverstripe/silverstripe-saml.svg)](https://travis-ci.org/silverstripe/silverstripe-saml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/silverstripe/silverstripe-saml/badges/quality-score.png)](https://scrutinizer-ci.com/g/silverstripe/silverstripe-saml/)
[![codecov](https://codecov.io/gh/silverstripe/silverstripe-saml/branch/master/graph/badge.svg)](https://codecov.io/gh/silverstripe/silverstripe-saml)

# NOTE: Module is unstable and untested

## Introduction

This SilverStripe module provides single sign-on authentication with SAML.

This component can also be used alongside the default SilverStripe authentication scheme.

## Requirements

 * PHP 5.6+ with extensions: openssl, dom, and mcrypt
 * SilverStripe 4.0+
 * Active Directory on Windows Server 2008 R2 or greater (AD)
 * Active Directory Federation Services 2.0 or greater (ADFS)
 * HTTPS endpoint on SilverStripe site
 * HTTPS endpoint on ADFS
 * SSL/StartTLS encrypted LDAP endpoint on Active Directory

This module has been tested on the following configurations:

 * Windows Server 2008 R2 with ADFS 2.0
 * Windows Server 2012 R2 with ADFS 3.0

This module has not been tested on non-Microsoft directory products, such as OpenLDAP.

## Overview

![](docs/en/img/saml_ad_integration.png)
*(Image) Typical authentication and authorisation flow for this module*

[Security Assertion Markup Language (SAML)](http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) is an XML-based, open-standard data format for exchanging authentication and authorization data between parties. The single most important requirement that SAML addresses is web browser single sign-on (SSO).

With this module, SilverStripe site is able to act as a SAML Service Provider (SP) entity, and thus allows users to perform a single sign-on against a centralised user directory (an Identity Provider - IdP).

The intended counterparty for this module is the [Active Directory Federation Services (ADFS)](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services). ADFS is a software component developed by Microsoft that can be installed on Windows Server operating systems to provide users with single sign-on access to systems and applications located across organizational boundaries.

ADFS uses a claims-based access control authorization model to maintain application security and implement federated identity. We rely on this mechanism for authentication, and for automated synchronisation of some basic personal details into SilverStripe.

## Security

With appropriate configuration, this module provides a secure means of authentication and authorisation.

For secure communication over the internet during the SAML authentication process, users must communicate with SilverStripe and ADFS using HTTPS. Similarly, for AD authentication to be secure users must access the SilverStripe site using HTTPS.

SilverStripe trusts ADFS responses based on pre-shared x509 certificates. These certificates are exchanged between the Identity Provider (ADFS) and the Service Provider (SilverStripe site) during the initial configuration phase.

AD user synchronisation and authentication is hidden behind the backend (server to server communication), but must still use encrypted LDAP communication to prevent eavesdropping (either StartTLS or SSL - this is configurable). If the webserver and the AD server are hosted in different locations, a VPN could also be used to further encapsulate the traffic going over the public internet.

## In-depth guides

* [Developer guide](docs/en/developer.md) - configure your SilverStripe site
* [ADFS administrator guide](docs/en/adfs.md) - prepare the Identity Provider
* [CMS usage guide](docs/en/usage.md) - manage LDAP group mappings
* [Troubleshooting](docs/en/troubleshooting.md) - common problems

## Changelog

Please see the GitHub releases for changes.
