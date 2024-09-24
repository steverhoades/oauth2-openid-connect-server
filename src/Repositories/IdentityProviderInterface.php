<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace OpenIDConnectServer\Repositories;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

interface IdentityProviderInterface extends RepositoryInterface
{
    /**
     * @return UserEntityInterface&ClaimSetInterface
     */
    public function getUserEntityByIdentifier($identifier);
}
