<?php

namespace OpenIDConnectServer\Test\Stubs;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

class UserNoClaimSetEntity implements UserEntityInterface
{
    use EntityTrait;

    public function __construct()
    {
        $this->setIdentifier(123);
    }
}
