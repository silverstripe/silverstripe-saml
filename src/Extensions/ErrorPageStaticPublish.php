<?php

namespace SilverStripe\SAML\Extensions;

use SilverStripe\ORM\DataExtension;
use SilverStripe\SAML\Middleware\SAMLMiddleware;

class ErrorPageStaticPublish extends DataExtension
{
    private ?bool $originallyEnabled = null;

    public function onBeforeStaticWrite()
    {
        $config = SAMLMiddleware::config();
        $this->originallyEnabled = $config->get('enabled');
        $config->set('enabled', false);
    }

    public function onAfterStaticWrite()
    {
        SAMLMiddleware::config()->set('enabled', $this->originallyEnabled);
    }
}
