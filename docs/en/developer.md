# Developer guide

This guide will step you through configuring your Silverstripe project to function as a SAML 2.0 Service Provider (SP). It will also show you a typical way to synchronise user details and group memberships from LDAP, using the [LDAP module](https://github.com/silverstripe/silverstripe-ldap).

As a Silverstripe developer after reading this guide, you should be able to correctly configure your site to integrate with the Identity Provider (IdP). You will also be able to authorise users based on their AD group memberships, and synchronise their personal details.

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
  - [Additional configuration for Azure AD](#additional-configuration-for-azure-ad)
  - [GUID Transformation](#guid-transformation)
- [Establish trust](#establish-trust)
- [Configure Silverstripe Authenticators](#configure-silverstripe-authenticators)
  - [Show the SAML Login button on login form](#show-the-saml-login-button-on-login-form)
  - [Automatically require SAML login for every request](#automatically-require-saml-login-for-every-request)
- [Test the connection](#test-the-connection)
- [Configure LDAP synchronisation](#configure-ldap-synchronisation)
  - [Connect with LDAP](#connect-with-ldap)
  - [More information on LDAP](#more-information-on-ldap)
- [Debugging](#debugging)
  - [SAML debugging](#saml-debugging)
- [Advanced SAML configuration](#advanced-saml-configuration)
  - [Allow insecure linking-by-email](#allow-insecure-linking-by-email)
  - [Adjust the requested AuthN contexts](#adjust-the-requested-authn-contexts)
  - [Allow authentication with alternative domains (e.g. subdomains)](#allow-authentication-with-alternative-domains-eg-subdomains)
  - [Create your own SAML configuration for completely custom settings](#create-your-own-saml-configuration-for-completely-custom-settings)
  - [Additional GET Query Params for SAML](#additional-get-query-params-for-saml)
- [Resources](#resources)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Install the module

First step is to add this module into your Silverstripe project. You can use Composer for this:

```
composer require silverstripe/saml
```

Commit the changes.

## Make x509 certificates available

SAML uses pre-shared certificates for establishing trust between the Service Provider (SP - here, Silverstripe) and the Identity Provider (IdP - here, ADFS).

### SP certificate and key

You need to make the SP x509 certificate and private key available to the Silverstripe site to be able to sign SAML requests. The certificate's "Common Name" needs to match the site endpoint that the ADFS will be using.

For testing purposes, you can generate this yourself by using the `openssl` command:

```
openssl req -x509 -nodes -newkey rsa:2048 -keyout saml.pem -out saml.crt -days 1826
```

Contact your system administrator if you are not sure how to install these.

### IdP certificate

You also need to make the certificate for your ADFS endpoint available to the Silverstripe site. Talk with your ADFS administrator to find out how to obtain this.

* In you are integrating with ADFS, direct the ADFS administrator to the [ADFS administrator guide](adfs.md).
* If you are integrating with Azure AD, direct the Azure AD administrator to the [Azure AD administrator guide](azure-ad.md).

Note: For Azure AD, you will first need to decide on the Entity ID (see next step) so that you can provide this to the Azure AD administrator - they can't provide you the certificates until you provide them the Entity ID and Reply URL values.

You may also be able to extract the certificate yourself from the IdP endpoint if it has already been configured: `https://<idp-domain>/FederationMetadata/2007-06/FederationMetadata.xml`.

## YAML configuration

Now we need to make the *silverstripe-saml* module aware of where the certificates can be found.

**Note:** If you are configuring this application for integration with Azure AD, a couple of extra keys need to be set. See the '[Additional configuration for Azure AD](#additional-configuration-for-azure-ad)' section below.

Add the following configuration to `app/_config/saml.yml` (make sure to replace paths to the certificates and keys):

```yaml

---
Name: mysamlsettings
After: '#samlsettings'
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

All IdP and SP endpoints must use HTTPS scheme with TLS/HTTPS certificates matching the domain names used.

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

 - `entityId`: This should be the base URL with https for the SP (e.g. https://example.com)
 - `privateKey`: The private key used for signing SAML request
 - `x509cert`: The public key that the IdP is using for verifying a signed request

### Identity Provider (IdP)

 - `entityId`: Provided by the IdP, but for ADFS it's typically `https://<idp-domain>/adfs/services/trust`
 - `x509cert`: The token-signing certificate from ADFS (base 64 encoded)
 - `singleSignOnService`: The endpoint on ADFS for where to send the SAML login request

### Additional configuration for Azure AD

When configuring the module to support Azure AD, a couple of additional configuration values need to be set to work with Azure AD out of the box. The below configuration should be merged into the YML configuration you have added above.

```yaml
SilverStripe\SAML\Services\SAMLConfiguration:
  expect_binary_nameid: false
  SP:
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'

SilverStripe\SAML\Extensions\SAMLMemberExtension:
  claims_field_mappings:
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Email'
```

### User groups mapping

By default, any new users logged in using SSO will not have any groups assigned to them. If you want them to have want to bring over the groups from the Provider via claims field, you could enable it via

```yml
SilverStripe\SAML\Services\SAMLConfiguration:
  map_user_group: true
```

and specify the claims field to map

```yml
SilverStripe\SAML\Helpers\SAMLUserGroupMapper:
  group_claims_field: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'
```

### GUID Transformation

If you prefer to receive the GUID in lower-case or upper-case format you can use the
`updateGuid()` extension point on `\SilverStripe\SAML\Control\SAMLController`.

## Establish trust

At this stage the Silverstripe site trusts the IdP, but the IdP does not have any way to establish the identity of the Silverstripe site.

The IdP should now be configured to extract the SP certificate from Silverstripe's SP endpoint. Once this is completed, bi-directional trust has been established and the authentication should be possible.

*silverstripe-saml* has some specific requirements on how ADFS, Azure AD and other IdPs are configured. Consult one of the following guides depending on the IdP you are integrating with.

* [ADFS administrator guide](adfs.md)
* [Azure AD administrator guide](azure-ad.md)

In particular, most IdPs will require that you provide them with the entity ID and reply URLs (sometimes called the Assertion Consumer Service URL or ACS URL). These can be found by going to https://<site-domain>/saml/metadata once the above YML configuration is in place.

* The Entity ID is the URL exactly as you have entered it in the YML above, which should be the URL to the root of your website (e.g. https://example.com)
* The Reply URL is the Entity ID, with the suffix '/saml/acs' added to the end (e.g. https://example.com/saml/acs)

## Configure Silverstripe Authenticators

To be able to use the SAML or the LDAP authenticator you will need to set them up in the `mysite/_config/saml.yml`.

You can choose which authenticators you would like to display on the login form.

### Show the SAML Login button on login form

```yaml
SilverStripe\Core\Injector\Injector:
  SilverStripe\Security\Security:
    properties:
      Authenticators:
        default: '%$SilverStripe\SAML\Authenticators\SAMLAuthenticator'
```

**Note:** to prevent locking yourself out if using the LDAP module as well, before you remove the "MemberAuthenticator" make sure you map at least one LDAP group to the Silverstripe `Administrator` Security Group. Consult [CMS usage docs](usage.md) for how to do it.

### Automatically require SAML login for every request

You can require that all users are logged in via SAML before any request to any page by enabling the `SAMLMiddleware` class. This will force a redirect if the user is not logged in, and the URL does not match a defined set of exclusions. The default list of exclusions includes all /Security URLs, so you should not use this middleware on its own to prevent users from using the normal login form. You should ensure that the default authenticator is the SAMLAuthenticator like so:

```yaml
SilverStripe\Core\Injector\Injector:
  SilverStripe\Security\Security:
    properties:
      authenticators:
        default: '%$SilverStripe\SAML\Authenticators\SAMLAuthenticator'
```

You can enable the middleware like so:

```yaml
SilverStripe\Core\Injector\Injector:
  SilverStripe\Control\Director:
    properties:
      Middlewares:
        SAMLMiddleware: '%$SilverStripe\SAML\Middleware\SAMLMiddleware'
SilverStripe\SAML\Middleware\SAMLMiddleware:
  enabled: true
```

You can add any number of URLs that should **not** require automatic login via the `excluded_urls` config param using regex. By default, this includes any URL under `/Security` and `/saml`. These defaults should not be changed, but you can add additional exclusions:

```yaml
SilverStripe\SAML\Middleware\SAMLMiddleware:
  excluded_urls:
    - '/^MyUnauthenticatedController/i'
    - '/^signup/'
```

Note: These are evaluated on every request, so keep your exclusion list as small as possible.

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

### Allow insecure linking-by-email

Normally the SAML module looks for a `Member` record based only on the GUID returned by the IdP. However, this can break in some situations, particularly when you are retrofitting single-sign-on into an existing system that already has member records in the database. A common use-case is that the website is setup, with centralised SSO being added later. At that point, you already have members that are setup with standard email/password logins, and those email addresses are the same as the user's primary email in the IdP. When the SAML module searches for a user when they login via SSO for the first time, it won't find them based on GUID, and will throw an error because it will attempt to create a new member with the same email as an existing user.

For this reason, the `allow_insecure_email_linking` YML config variable exists. During the transition period, you can enable this option so that if the lookup-by-GUID fails to find a valid member, the module will then attempt to lookup via the provided email address before falling back to creating a new member record.

**Note: This is not recommended in production.** If this setting is enabled, then we fall back to relying on the non-unique email address to log in to an existing member's account. For example, consider the situation where John Smith previously had an email/password login to your website. They leave the company, and a new John Smith (unrelated to the website) inherits the email address when they join the company. If this option is enabled and the new John Smith attempts to login, despite them not being allowed access, we will set the user up and link them to the old accounts (and whatever permissions the old user had).

We strongly recommend that you perform a full review of all users and permission levels for all members in the CMS **before you enable this setting** to ensure you will only create accounts for people that currently exist at the IdP.

You can enable this setting with the following YML config:

```yaml

---
Name: mysamlsettings
After: '#samlsettings'
---
SilverStripe\SAML\Services\SAMLConfiguration:
  allow_insecure_email_linking: true
```

**Note**: You will also need to specify a `SAMLMemberExtension.claims_field_mappings` claim map that sets a value for 'Email', so that the IdP provides a value to include in the email field, for example:

```yaml
SilverStripe\SAML\Extensions\SAMLMemberExtension:
  claims_field_mappings:
    - 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'Email'
```

### Adjust the requested AuthN contexts

By default, this module requests the following contexts (aka. 'ways users can login'):
- `urn:federation:authentication:windows` (aka automatic Windows authentication)
- `urn:oasis:names:tc:SAML:2.0:ac:classes:Password` (aka username and password, known as 'forms' authentication on the ADFS end)
- `urn:oasis:names:tc:SAML:2.0:ac:classes:X509` (aka X.509 certificate)

For more details on what options are possible for Microsoft ADFS, [check out MSDN](https://msdn.microsoft.com/en-us/library/hh599318.aspx).

If you want to customise the requested options, you can do this via YML. For example, the below configuration ensures that only `windows` authentication is considered valid:

```yaml

---
Name: samlconfig
After:
  - "#samlsettings"
---
SilverStripe\SAML\Services\SAMLConfiguration:
  authn_contexts:
    - 'urn:federation:authentication:windows'
```

You can also set `disable_authn_contexts: true` which will disable the sending of AuthN contexts at all, allowing the remote IdP to make its best decision over what to use. This will also not require an exact match (and is therefore not recommended).

### Allow authentication with alternative domains (e.g. subdomains)

SAML Authentication responses are typically sent to the ACS (reply) url specified to the IdP - e.g. https://example.com/saml/acs - which does not take subdomains or alternative valid domains into account - effectively redirecting someone from sub.example.com to example.com on successful authentication. IdPs often allow for this via configuring other valid reply URLs for the SP. To allow for this within your Silverstripe app, set the `SAMLConfiguration.extra_acs_base` configuration to an array of valid strings. These need to be in the same format as the EntityId - valid URLs WITHOUT a trailing slash (since Silverstripe CMS 5.0).

```yml
SilverStripe\SAML\Services\SAMLConfiguration:
  extra_acs_base:
    - https://app.example.com
    - https://docs.example.com
```

### Create your own SAML configuration for completely custom settings

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

### Additional GET Query Params for SAML
example:
```yaml
SilverStripe\SAML\Services\SAMLConfiguration:
  additional_get_query_params:
    someGetQueryParameter: 'value'
    AnotherParameter: 'differentValue'
```

this configuration allows you to add two GET query parameters to endpoint request URL:
`https://your-idp.com/singleSignOnService/saml2?someGetQueryParameter=value&AnotherParameter=differentValue&SAMLRequest=XYZ....`

### Automatically redirect after authentication
If the user has CMS permission and you want to redirect to the CMS after successful authentication, you can set the default login destination like this:

```yaml
SilverStripe\Security\Security:
  default_login_dest: 'admin'
```

## Resources

 - [ADFS Deep-Dive: Onboarding Applications](http://blogs.technet.com/b/askpfeplat/archive/2015/03/02/adfs-deep-dive-onboarding-applications.aspx)
