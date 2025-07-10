<?php

namespace SilverStripe\SAML\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\SAML\Middleware\SAMLMiddleware;

class ErrorPageStaticPublish extends Extension
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
