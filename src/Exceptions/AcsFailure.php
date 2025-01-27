<?php

namespace SilverStripe\SAML\Exceptions;

use RuntimeException;

/**
 * This is used a message carrying interface, rather than a "proper" exception (to halt execution)
 * A way to short out of ACS and centralise logging & user message display functionality without passing around details
 * like unique ID, etc. It also provides an easy way for extensions that utilise the ACS hook points to both log and
 * trigger authentication failures.
 *
 * @see SilverStripe\SAML\Control\SAMLController::acs
 */
class AcsFailure extends RuntimeException
{
}
