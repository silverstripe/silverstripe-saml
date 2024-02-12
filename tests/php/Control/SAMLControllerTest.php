<?php

namespace SilverStripe\SAML\Tests\Control;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Control\SAMLController;

class SAMLControllerTest extends SapphireTest
{
    public function testGetForm(): void
    {
        $controller = new SAMLController();

        $form = $controller->getForm();

        $this->assertNotNull($form);
    }
}
