<?php
/**
 * Created by PhpStorm.
 * User: steverhoades
 * Date: 10/13/16
 * Time: 12:30 PM
 */

namespace OpenIDConnectServer\Entities;

class ClaimSetEntity implements ClaimSetEntityInterface
{
    protected $scope;

    protected $claims;

    public function __construct($scope, array $claims)
    {
        $this->scope    = $scope;
        $this->claims   = $claims;
    }

    public function getScope()
    {
        return $this->scope;
    }

    public function getClaims()
    {
        return $this->claims;
    }
}
