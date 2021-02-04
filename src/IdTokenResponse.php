<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace OpenIDConnectServer;

use DateTimeImmutable;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;

class IdTokenResponse extends BearerTokenResponse
{
    /**
     * @var IdentityProviderInterface
     */
    protected $identityProvider;

    /**
     * @var ClaimExtractor
     */
    protected $claimExtractor;

    /**
     * @var Configuration
     */
    private $jwtConfiguration;

    /**
     * @var callable|null
     */
    private $tokenModifier = null;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        ClaimExtractor $claimExtractor
    ) {
        $this->identityProvider = $identityProvider;
        $this->claimExtractor   = $claimExtractor;
    }

    /**
     * Generate a JWT from the access token
     *
     * @return Token
     */
    private function getBuilder(AccessTokenEntityInterface $accessToken, UserEntityInterface $userEntity)
    {
        $this->initJwtConfiguration();

        $token = $this->jwtConfiguration->builder()
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->issuedAt(new DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->issuedBy('https://' . $_SERVER['HTTP_HOST'])
            ->relatedTo((string) $userEntity->getIdentifier());

        if (null !== ($modifier = $this->getIdTokenModifier())) {
            $token = call_user_func($modifier, $token);
        }

        if ($token instanceof Builder === false) {
            throw new \RuntimeException('The id token modifier must return an instance of Lcobucci\JWT\Builder');
        }

        return $token;
    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        /** @var UserEntityInterface $userEntity */
        $userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

        if (false === is_a($userEntity, UserEntityInterface::class)) {
            throw new \RuntimeException('UserEntity must implement UserEntityInterface');
        } elseif (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new \RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        // Add required id_token claims
        $builder = $this->getBuilder($accessToken, $userEntity);

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

        foreach ($claims as $claimName => $claimValue) {
            $builder = $builder->withClaim($claimName, $claimValue);
        }

        $token = $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        return [
            'id_token' => $token->toString()
        ];
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return bool
     */
    private function isOpenIDRequest($scopes)
    {
        // Verify scope and make sure openid exists.
        $valid  = false;

        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                $valid = true;
                break;
            }
        }

        return $valid;
    }

    /**
     * @see League\OAuth2\Server\Entities\Traits\AccessTokenTrait
     */
    private function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            LocalFileReference::file($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase() ?? ''),
            InMemory::plainText('')
        );
    }

    /**
     * @return callable|null
     */
    public function getIdTokenModifier()
    {
        return $this->tokenModifier;
    }

    /**
     * @param callable $tokenModifier
     */
    public function setIdTokenModifier(callable $tokenModifier)
    {
        $this->tokenModifier = $tokenModifier;
    }
}
