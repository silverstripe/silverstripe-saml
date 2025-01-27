<?php

namespace SilverStripe\SAML\Tests\Services;

use OneLogin\Saml2\Constants;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Services\SAMLConfiguration;

class SAMLConfigurationTest extends SapphireTest
{
    protected function setUp(): void
    {
        parent::setUp();
        $config = Config::modify();
        $config->set(Director::class, 'alternate_base_url', 'https://running.test');

        $config->set(SAMLConfiguration::class, 'extra_acs_base', [
            'https://example.running.test'
        ]);

        $config->set(SAMLConfiguration::class, 'SP', [
            'entityId' => "https://running.test",
            'privateKey' => __DIR__ . '/fakeCertificate.pem',
            'x509cert' => __DIR__ . '/fakeCertificate.pem',
        ]);
        $config->set(SAMLConfiguration::class, 'IdP', [
            'entityId' => "idp.example.com",
            'singleSignOnService' => "https://idp.example.com/test/saml2",
            'x509cert' => __DIR__ . '/fakeCertificate.pem',
        ]);

        $config->set(SAMLConfiguration::class, 'strict', true);
        $config->set(SAMLConfiguration::class, 'debug', false);
        $config->set(SAMLConfiguration::class, 'Security', [
            'signatureAlgorithm' => 'If security is poetry, does that make it an Algo-rhythm?',
        ]);
    }

    public function provideBaseUrls(): array
    {
        return [
            [
                null,
                'https://running.test/saml/acs',
                'SP.EntityId should be used by default'
            ],
            [
                'https://example.running.test',
                'https://example.running.test/saml/acs',
                'Extra ACS should work when the loaded (or specified) domain matches'
            ],
            [
                'https://not-legit.running.test',
                'https://running.test/saml/acs',
                'Unlisted ACS base should result in the SP.EntityId being used instead',
            ],
        ];
    }

    /**
     * @dataProvider provideBaseUrls
     *
     * @param string $baseUrl
     * @param string $expectedOut
     * @return void
     */
    public function testAcsBaseIsSetCorrectly($baseUrl, $expectedOut, $message)
    {
        if (isset($baseUrl)) {
            Config::modify()->set(Director::class, 'alternate_base_url', $baseUrl);
        }
        $samlConfig = (new SAMLConfiguration())->asArray();
        $this->assertSame(
            $expectedOut,
            $samlConfig['sp']['assertionConsumerService']['url'],
            $message
        );
    }

    /**
     * Test generically, rather than specific advanced features
     *
     * The following configuration options exist, but are not used by `asArray`
     * - expect_binary_nameid
     * - allow_insecure_email_linking
     * - expose_guid_as_attribute
     * - additional_get_query_params
     * - login_persistent
     *
     * @return void
     */
    public function testAsArray()
    {
        $output = (new SAMLConfiguration())->asArray();

        foreach (['strict', 'debug', 'sp', 'idp', 'security'] as $key) {
            $this->assertArrayHasKey($key, $output);
        }

        $this->assertTrue($output['strict'], 'strict');
        $this->assertFalse($output['debug'], 'debug');

        $this->assertSame('https://running.test', $output['sp']['entityId'], 'sp.entityId');
        $this->assertSame("identifiable\n", $output['sp']['x509cert'], 'sp.x509cert');
        $this->assertSame("identifiable\n", $output['sp']['privateKey'], 'sp.privateKey');
        $this->assertSame(Constants::NAMEID_TRANSIENT, $output['sp']['NameIDFormat'], 'sp.NameIDFormat');
        $this->assertSame(
            'https://running.test/saml/acs',
            $output['sp']['assertionConsumerService']['url'],
            'sp.assertionConsumerService.url'
        );
        $this->assertSame(
            Constants::BINDING_HTTP_POST,
            $output['sp']['assertionConsumerService']['binding'],
            'sp.assertionConsumerService.binding'
        );

        $this->assertSame('idp.example.com', $output['idp']['entityId'], 'idp.entityId');
        $this->assertSame("identifiable\n", $output['idp']['x509cert'], 'idp.x509cert');
        $this->assertArrayHasKey('url', $output['idp']['singleSignOnService'], 'idp.singleSignOnService');
        $this->assertSame(
            Constants::BINDING_HTTP_REDIRECT,
            $output['idp']['singleSignOnService']['binding'],
            'idp.singleSignOnService.binding'
        );
        $this->assertArrayNotHasKey('singleLogoutService', $output['idp']);

        foreach ([
                'nameIdEncrypted',
                'authnRequestsSigned',
                'logoutRequestSigned',
                'logoutResponseSigned',
                'signMetadata',
                'wantMessagesSigned',
                'wantAssertionsSigned',
                'wantNameIdEncrypted',
                'signatureAlgorithm',
                'requestedAuthnContext',
                'wantXMLValidation',
            ] as $securityKey
        ) {
            $this->assertArrayHasKey($securityKey, $output['security']);
        }
        $this->assertSame(
            'If security is poetry, does that make it an Algo-rhythm?',
            $output['security']['signatureAlgorithm']
        );
    }

    public function provideAuthnContexts()
    {
        return [
            [null, null],
            [null, true],
            [null, false],
            [null, 'false'],
            [null, 'true'],
            ['this is invalid', null, true],
            ['this is invalid', true],
            [['urn:a:fake:context', 'urn:pretend:securityNoun'], null],
            [['urn:a:fake:context', 'urn:pretend:securityNoun'], true],
        ];
    }

    /**
     * @dataProvider provideAuthnContexts
     *
     * @return void
     */
    public function testAuthnContexts($contexts, $disabled, $expectDefault = false)
    {
        $config = SAMLConfiguration::config();
        if (!is_null($contexts)) {
            $config->set('authn_contexts', $contexts);
        }
        if (!is_null($disabled)) {
            $config->set('disable_authn_contexts', $disabled);
        }

        $default = [
            'urn:federation:authentication:windows',
            'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
            'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
        ];

        $outputContexts = (new SAMLConfiguration())->asArray()['security']['requestedAuthnContext'];

        if ($disabled) {
            $this->assertFalse($outputContexts, 'Disabled contexts should be `false`');
        } elseif (null === $contexts || $expectDefault) {
            $this->assertSame($default, $outputContexts, 'Requested Authn Contexts should match defaults');
        } else {
            $this->assertSame($contexts, $outputContexts, 'Contexts should match Silverstripe configuration setting');
        }
    }

    public function testIDPSingleLogout()
    {
        $setting = 'Log out of everything all at once';
        SAMLConfiguration::config()->merge('IdP', ['singleLogoutService' => $setting]);
        $this->assertSame($setting, (new SAMLConfiguration())->asArray()['idp']['singleLogoutService']['url']);
    }

    public function testNameIdFormatAcceptsCustomValue()
    {
        $setting = 'almost-random';
        SAMLConfiguration::config()->merge('SP', ['nameIdFormat' => $setting]);
        $this->assertSame($setting, (new SAMLConfiguration())->asArray()['sp']['NameIDFormat']);
    }
}
