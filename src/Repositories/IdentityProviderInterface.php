<?php
/**
 * Created by PhpStorm.
 * User: steverhoades
 * Date: 10/12/16
 * Time: 5:19 PM
 */

namespace OpenIDConnectServer\Repositories;

use League\OAuth2\Server\Repositories\RepositoryInterface;

interface IdentityProviderInterface extends RepositoryInterface
{
    public function getUserEntityByIdentifier($identifier);
}
