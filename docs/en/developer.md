# Developer guide

This guide will step you through configuring your SilverStripe project to function as a SAML 2.0 Service Provider (SP). It will also show you a typical way to synchronise user details and group memberships from LDAP, using the [LDAP module](https://github.com/silverstripe/silverstripe-ldap).

As a SilverStripe developer after reading this guide, you should be able to correctly configure your site to integrate with the Identity Provider (IdP). You will also be able to authorise users based on their AD group memberships, and synchronise their personal details.

We assume ADFS 2.0 or greater is used as an IdP.

## Table of contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Install the module](#install-the-module)
- [Make x509 certificates available](#make-x509-certificates-available)
  - [SP certificate and key](#sp-certificate-and-key)
  - [IdP certificate](#idp-certificate)
- [YAML configuration](#yaml-configuration)
  - [A note on signature algorithm config](#a-note-on-signature-algorithm-config)
  - [Service Provider (SP)](#service-provider-sp)
  - [Identity Provider (IdP)](#identity-provider-idp)
- [Establish trust](#establish-trust)
- [Configure SilverStripe Authenticators](#configure-silverstripe-authenticators)
  - [Show the SAML Login button on login form](#show-the-saml-login-button-on-login-form)
  - [Bypass auto login](#bypass-auto-login)
- [Test the connection](#test-the-connection)
- [Configure LDAP synchronisation](#configure-ldap-synchronisation)
  - [Connect with LDAP](#connect-with-ldap)
  - [More information on LDAP](#more-information-on-ldap)
- [Debugging](#debugging)
  - [SAML debugging](#saml-debugging)
- [Advanced SAML configuration](#advanced-saml-configuration)
- [Resources](#resources)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Install the module

First step is to add this module into your SilverStripe project. You can use Composer for this:

```
composer require silverstripe/saml
```

Commit the changes.

## Make x509 certificates available

SAML uses pre-shared certificates for establishing trust between the Service Provider (SP - here, SilverStripe) the Identity Provider (IdP - here, ADFS).

### SP certificate and key

You need to make the SP x509 certificate and private key available to the SilverStripe site to be able to sign SAML requests. The certificate's "Common Name" needs to match the site endpoint that the ADFS will be using.

For testing purposes, you can generate this yourself by using the `openssl` command:

```
openssl req -x509 -nodes -newkey rsa:2048 -keyout saml.pem -out saml.crt -days 1826
```

Contact your system administrator if you are not sure how to install these.

### IdP certificate

You also need to make the certificate for your ADFS endpoint available to the SilverStripe site. Talk with your ADFS administrator to find out how to obtain this.

If you are managing ADFS yourself, consult the [ADFS administrator guide](adfs.md).

You may also be able to extract the certificate yourself from the IdP endpoint if it has already been configured: `https://<idp-domain>/FederationMetadata/2007-06/FederationMetadata.xml`.

## YAML configuration

Now we need to make the *silverstripe-saml* module aware of where the certificates can be found.

Add the following configuration to `mysite/_config/saml.yml` (make sure to replace paths to the certificates and keys):

```yaml
---
Name: mysamlsettings
---
SilverStripe\SAML\Services\SAMLConfiguration:
  strict: true
  debug: false
  SP:
    entityId: "https://<your-site-domain>"
    privateKey: "<path-to-silverstripe-private-key>.pem"
    x509cert: "<path-to-silverstripe-cert>.crt"
  IdP:
    entityId: "https://<idp-domain>/adfs/services/trust"
    x509cert: "<path-to-adfs-cert>.pem"
    singleSignOnService: "https://<idp-domain>/adfs/ls/"
  Security:
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
```

If you don't use absolute paths, the certificate paths will be relative to the site web root.

All IdP and SP endpoints must use HTTPS scheme with SSL certificates matching the domain names used.

### A note on signature algorithm config

The signature algorithm must match the setting in the ADFS relying party trust
configuration. For ADFS it's possible to downgrade the default from SHA-256 to
 SHA-1, but this is not recommended. To do this, you can change YAML configuration:

```yaml
SilverStripe\SAML\Services\SAMLConfiguration:
  Security:
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
```

### Service Provider (SP)

 - `entityId`: This should be the base URL with https for the SP
 - `privateKey`: The private key used for signing SAML request
 - `x509cert`: The public key that the IdP is using for verifying a signed request

### Identity Provider (IdP)

 - `entityId`: Provided by the IdP, but for ADFS it's typically `https://<idp-domain>/adfs/services/trust`
 - `x509cert`: The token-signing certificate from ADFS (base 64 encoded)
 - `singleSignOnService`: The endpoint on ADFS for where to send the SAML login request

## Establish trust

At this stage the SilverStripe site trusts the ADFS, but the ADFS does not have any way to establish the identity of the SilverStripe site.

ADFS should now be configured to extract the SP certificate from SilverStripe's SP endpoint. Once this is completed, bi-directional trust has been established and the authentication should be possible.

*silverstripe-saml* has some specific requirements on how ADFS is configured. If you are managing ADFS yourself, or you are assisting an ADFS administrator, consult the [ADFS administrator guide](adfs.md).

## Configure SilverStripe Authenticators

To be able to use the SAML or the LDAP authenticator you will need to set them up in the `mysite/_config/saml.yml`.

You can choose which authenticators you would like to display on the login form.

### Show the SAML Login button on login form

```yaml
SilverStripe\Core\Injector\Injector:
  SilverStripe\Security\Security:
    properties:
      Authenticators:
        default: %$SilverStripe\SAML\Authenticators\SAMLAuthenticator
```

**Note:** to prevent locking yourself out if using the LDAP module as well, before you remove the "MemberAuthenticator" make sure you map at least one LDAP group to the SilverStripe `Administrator` Security Group. Consult [CMS usage docs](usage.md) for how to do it.

### Bypass auto login

If you register the SAMLAuthenticator as the default authenticator, it will automatically send users to the ADFS login server when they are required to login.
Should you need to access the login form with all the configured Authenticators, go to:

```yaml
/Security/login?showloginform=1
```

Note that if you have unregistered the `MemberAuthenticator`, and you wish to use that method during `showloginform=1`, you
will need to set a cookie so it can be used temporarily.

This will set a cookie to show `MemberAuthenticator` if `showloginform=1` is requested:

```php
use SilverStripe\LDAP\Authenticators\LDAPAuthenticator;
use SilverStripe\Control\Cookie;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Security;

if (isset($_GET['showloginform'])) {
    Cookie::set('showloginform', (bool)$_GET['showloginform'], 1);
}

if (!Cookie::get('showloginform')) {
    Config::modify()->merge(Authenticator::class, 'authenticators', [SAMLAuthenticator::class]);

    Config::modify()->merge(Injector::class, Security::class, [
        'properties' => [
            'Authenticators' => [
                'default' => '%$' . SAMLAuthenticator::class,
            ]
        ]
    ]);
}
```

If you do this, either clear your cookie or set the query string param back to 0 to return to using the LDAP login form.

For more information see the [`SAMLSecurityExtension.php`](../../src/Authenticators/SAMLSecurityExtension.php).

## Test the connection

At this stage you should be able to authenticate. If you cannot, you should double check the claims rules and hashing algorithm used by ADFS. Consult [ADFS administrator guide](adfs.md) to assist the ADFS administrator.

You can also review the [troubleshooting](troubleshooting.md) guide if you are experiencing problems.

## Configure LDAP synchronisation

**Prerequisite:** install the [silverstripe-ldap module](https://github.com/silverstripe/silverstripe-ldap).

These are the reasons for configuring LDAP synchronisation:

* It allows you to authorise users based on their AD groups. *silverstripe-ldap* is able to automatically maintain Group memberships for its managed users based on the AD "memberOf" attribute.
* You can pull in additional personal details about your users that may not be available from the IdP directly - either because of claim rules, or inherent limitations such as binary data transfers.
* The data is only synchronised upon modification, so it helps to keep SAML payloads small.

### Connect with LDAP

Example configuration for `mysite/_config/ldap.yml`:

```yaml
SilverStripe\LDAP\Model\LDAPGateway:
  options:
    'host': 'ad.mydomain.local'
    'username': 'myusername'
    'password': 'mypassword'
    'accountDomainName': 'mydomain.local'
    'baseDn': 'DC=mydomain,DC=local'
    'networkTimeout': 10
    'useSsl': 'TRUE'
```

### More information on LDAP

For more information on configuring LDAP, see the [LDAP module documentation](https://github.com/silverstripe/silverstripe-ldap/blob/master/docs/en/developer.md).

## Debugging

There are certain parts of his module that have debugging messages logged. You can configure logging to receive these via email, for example. For more information on this topic see [Logging and Error Handling](https://docs.silverstripe.org/en/4/developer_guides/debugging/error_handling/) in the developer documentation.

### SAML debugging

To enable some very light weight debugging from the 3rd party library set the `debug` to true

```yaml
SilverStripe\SAML\Services\SAMLConfiguration:
  debug: true
```

In general it can be tricky to debug what is failing during the setup phase. The SAML protocol error
message as quite hard to decipher.

In most cases it's configuration issues that can debugged by using the ADFS Event log, see the
[Diagnostics in ADFS 2.0](http://blogs.msdn.com/b/card/archive/2010/01/21/diagnostics-in-ad-fs-2-0.aspx)
for more information.

Also ensure that all protocols are matching. SAML is very sensitive to differences in http and https in URIs.

## Advanced SAML configuration

It is possible to customize all the settings provided by the 3rd party SAML code.

This can be done by registering your own `SilverStripe\SAML\Services\SAMLConfiguration` object via `mysite/_config/saml.yml`:

Example:

```yaml
---
Name: samlconfig
After:
  - "#samlsettings"
---
SilverStripe\Core\Injector\Injector:
  SAMLConfService: YourVendor\YourModule\MySAMLConfiguration
```

and then in your namespaced `MySAMLConfiguration.php`:

```php
<?php

namespace YourVendor\YourModule;

class MySAMLConfiguration
{
    public function asArray()
    {
        return [
            // add settings here;
        ];
    }
}
```

See the [advanced\_settings/\_example.php](https://github.com/onelogin/php-saml/blob/master/advanced_settings_example.php)
for the advanced settings.

## Resources

 - [ADFS Deep-Dive: Onboarding Applications](http://blogs.technet.com/b/askpfeplat/archive/2015/03/02/adfs-deep-dive-onboarding-applications.aspx)
