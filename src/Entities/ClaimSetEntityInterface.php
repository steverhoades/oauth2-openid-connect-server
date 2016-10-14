<?php
/**
 * Created by PhpStorm.
 * User: steverhoades
 * Date: 10/13/16
 * Time: 12:35 PM
 */

namespace OpenIDConnectServer\Entities;


interface ClaimSetEntityInterface
{
    /**
     * @return string
     */
    public function getScope();

    /**
     * @return array
     */
    public function getClaims();
}
