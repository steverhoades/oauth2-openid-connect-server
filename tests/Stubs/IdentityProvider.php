<?php

namespace OpenIDConnectServer\Test\Stubs;

use OpenIDConnectServer\Repositories\IdentityProviderInterface;

class IdentityProvider implements IdentityProviderInterface
{
    const NO_CLAIMSET = 'no_claimset';
    const NO_IDENTIFIER = 'no_idetifier';

    protected $entity;

    public function __construct($type = null)
    {
        switch($type) {
            case self::NO_CLAIMSET:
                $this->entity = new UserNoClaimSetEntity();
                break;
            case self::NO_IDENTIFIER:
                $this->entity = new UserNoIdentifierEntity();
                break;
            default:
                $this->entity = new UserEntity();
        }
    }

    public function getUserEntityByIdentifier($identifier)
    {
        return $this->entity;
    }

}
