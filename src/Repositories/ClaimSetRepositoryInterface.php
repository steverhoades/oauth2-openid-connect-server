<?php
/**
 * Created by PhpStorm.
 * User: steverhoades
 * Date: 10/13/16
 * Time: 12:32 PM
 */

namespace OpenIDConnectServer\Repositories;


interface ClaimSetRepositoryInterface
{
    public function getClaimSetByScopeIdentifier($scopeIdentifier);
}
