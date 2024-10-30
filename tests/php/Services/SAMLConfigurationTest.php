<?php

namespace SilverStripe\SAML\Tests\Services;

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
            'signatureAlgorithm' => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
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
}
