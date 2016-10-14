<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
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
