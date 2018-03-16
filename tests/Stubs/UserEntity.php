<?php

namespace OpenIDConnectServer\Test\Stubs;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

class UserEntity implements UserEntityInterface, ClaimSetInterface
{
    use EntityTrait;

    public function __construct()
    {
        $this->setIdentifier(123);
    }

    public function getClaims()
    {
        return [
            'first_name'    => 'Steve',
            'last_name'     => 'Rhoades',
            'email'         => 'steve.rhoades@stephenrhoades.com'
        ];
    }
}
