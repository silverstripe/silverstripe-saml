# Silverstripe SAML module

[![Build Status](https://github.com/silverstripe/silverstripe-saml/actions/workflows/ci.yml/badge.svg)](https://github.com/silverstripe/silverstripe-saml/actions/workflows/ci.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/silverstripe/silverstripe-saml/badges/quality-score.png)](https://scrutinizer-ci.com/g/silverstripe/silverstripe-saml/)
[![codecov](https://codecov.io/gh/silverstripe/silverstripe-saml/branch/master/graph/badge.svg)](https://codecov.io/gh/silverstripe/silverstripe-saml)

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Overview](#overview)
- [Security](#security)
- [In-depth guides](#in-depth-guides)
  - [For Silverstripe developers](#for-silverstripe-developers)
  - [For identity provider administrators](#for-identity-provider-administrators)
- [Changelog](#changelog)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction

This Silverstripe module provides single sign-on authentication integration with a SAML provider.

This component can also be used alongside the default Silverstripe authentication scheme.

## Requirements

- PHP 8+ with extensions: openssl, dom
- Silverstripe CMS 5 (see `2` branch for Silverstripe 4)
- Active Directory Federation Services 2.0 or greater (ADFS)
- HTTPS endpoint on Silverstripe site
- HTTPS endpoint on ADFS

This module has previously been tested on the following configurations, but is now untested:

- Windows Server 2008 R2 with ADFS 2.0
- Windows Server 2012 R2 with ADFS 3.0

**Note:** For LDAP only Active Directory integration, please see [silverstripe-ldap](https://github.com/silverstripe/silverstripe-ldap).

## Overview

![](docs/en/img/saml_ad_integration.png)
_(Image) Typical authentication and authorisation flow for this module_

[Security Assertion Markup Language (SAML)](http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) is an XML-based, open-standard data format for exchanging authentication and authorization data between parties. The single most important requirement that SAML addresses is web browser single sign-on (SSO).

With this module, Silverstripe site is able to act as a SAML Service Provider (SP) entity, and thus allows users to perform a single sign-on against a centralised user directory (an Identity Provider - IdP).

The intended counterparty for this module is the [Active Directory Federation Services (ADFS)](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services). ADFS is a software component developed by Microsoft that can be installed on Windows Server operating systems to provide users with single sign-on access to systems and applications located across organizational boundaries.

ADFS uses a claims-based access control authorization model to maintain application security and implement federated identity. We rely on this mechanism for authentication, and for automated synchronisation of some basic personal details into Silverstripe.

This module doesn't allow you to store additional user attributes. If this is desired, you can optionally install the [silverstripe-ldap](https://github.com/silverstripe/silverstripe-ldap) module and run alongside to synchronise custom user attributes from an Active Directory server.

## Security

With appropriate configuration, this module provides a secure means of authentication and authorisation.

For secure communication over the internet during the SAML authentication process, users must communicate with Silverstripe and ADFS using HTTPS. Similarly, for AD authentication to be secure users must access the Silverstripe site using HTTPS.

Silverstripe trusts ADFS responses based on pre-shared X509 certificates. These certificates are exchanged between the Identity Provider (ADFS) and the Service Provider (Silverstripe site) during the initial configuration phase.

## In-depth guides

### For Silverstripe developers

- [Developer guide](docs/en/developer.md) - configure your Silverstripe site
- [Troubleshooting](docs/en/troubleshooting.md) - common problems

### For identity provider administrators

These guides will help you prepare your identity provider and configure it to work with the module correctly.

- [ADFS administrator guide](docs/en/adfs.md)
- [Azure AD administrator guide](docs/en/azure-ad.md)

## Changelog

Please see the [GitHub releases](https://github.com/silverstripe/silverstripe-saml/releases) for changes.
