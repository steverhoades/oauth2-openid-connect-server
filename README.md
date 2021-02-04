# OAuth 2.0 OpenID Connect Server

[![Build Status](https://travis-ci.org/steverhoades/oauth2-openid-connect-server.svg?branch=master)](https://travis-ci.org/steverhoades/oauth2-openid-connect-server) [![Code Coverage](https://scrutinizer-ci.com/g/steverhoades/oauth2-openid-connect-server/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/steverhoades/oauth2-openid-connect-server/?branch=master) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/steverhoades/oauth2-openid-connect-server/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/steverhoades/oauth2-openid-connect-server/?branch=master)

This implements the OpenID Connect specification on top of The PHP League's [OAuth2 Server](https://github.com/thephpleague/oauth2-server).

## Requirements

* Requires PHP version 5.5 or greater.
* [league/oauth2-server](https://github.com/thephpleague/oauth2-server) 5.1 or greater.

Note: league/oauth2-server version may have a higher PHP requirement.

## Usage
The following classes will need to be configured and passed to the AuthorizationServer in order to provide OpenID Connect functionality.

1. IdentityRepository.  This MUST implement the OpenIDConnectServer\Repositories\IdentityProviderInterface and return the identity of the user based on the return value of $accessToken->getUserIdentifier().
   1. The IdentityRepository MUST return a UserEntity that implements the following interfaces
      1. OpenIDConnectServer\Entities\ClaimSetInterface
      1. League\OAuth2\Server\Entities\UserEntityInterface.
1. ClaimSet.  ClaimSet is a way to associate claims to a given scope.
1. ClaimExtractor. The ClaimExtractor takes an array of ClaimSets and in addition provides default claims for the OpenID Connect specified scopes of: profile, email, phone and address.
1. IdTokenResponse. This class must be passed to the AuthorizationServer during construction and is responsible for adding the id_token to the response.
1. ScopeRepository. The getScopeEntityByIdentifier($identifier) method must return a ScopeEntity for the `openid` scope in order to enable support. See examples.

### Example Configuration

```php
// Init Repositories
$clientRepository       = new ClientRepository();
$scopeRepository        = new ScopeRepository();
$accessTokenRepository  = new AccessTokenRepository();
$authCodeRepository     = new AuthCodeRepository();
$refreshTokenRepository = new RefreshTokenRepository();

$privateKeyPath = 'file://' . __DIR__ . '/../private.key';
$publicKeyPath = 'file://' . __DIR__ . '/../public.key';

// OpenID Connect Response Type
$responseType = new IdTokenResponse(new IdentityRepository(), new ClaimExtractor());

// Optionally configure the issued id token before it is signed
$responseType->setIdTokenModifier(function(\Lcobucci\JWT\Token\Builder $token) {
   return $token->issuedBy('Custom issuer')
                ->withClaim('customClaim', 'Custom claim')
                ->withHeader('kid', 'key-id');
});

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $publicKey,
    $responseType
);

$grant = new \League\OAuth2\Server\Grant\AuthCodeGrant(
    $authCodeRepository,
    $refreshTokenRepository,
    new \DateInterval('PT10M') // authorization codes will expire after 10 minutes
);

$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

// Enable the authentication code grant on the server
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);

return $server;
```
After the server has been configured it should be used as described in the [OAuth2 Server documentation](https://oauth2.thephpleague.com/).

## UserEntity
In order for this library to work properly you will need to add your IdentityProvider to the IdTokenResponse object.  This will be used internally to lookup a UserEntity by it's identifier.  Additionally your UserEntity must implement the ClaimSetInterface which includes a single method getClaims().  The getClaims() method should return a list of attributes as key/value pairs that can be returned if the proper scope has been defined.
```
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

class UserEntity implements UserEntityInterface, ClaimSetInterface
{
    use EntityTrait;

    protected $attributes;

    public function getClaims()
    {
        return $this->attributes;
    }
}

```

## ClaimSets
A ClaimSet is a scope that defines a list of claims.
```
// Example of the profile ClaimSet
$claimSet = new ClaimSetEntity('profile', [
        'name',
        'family_name',
        'given_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'profile',
        'picture',
        'website',
        'gender',
        'birthdate',
        'zoneinfo',
        'locale',
        'updated_at'
    ]);

```
As you can see from the above, profile lists a set of claims that can be extracted from our UserEntity if the profile scope is included with the authorization request.

### Adding Custom ClaimSets
At some point you will likely want to include your own group of custom claims. To do this you will need to create a ClaimSetEntity, give it a scope (the value you will include in the scope parameter of your OAuth2 request) and the list of claims it supports.
```
$extractor = new ClaimExtractor();
// Create your custom scope
$claimSet = new ClaimSetEntity('company', [
        'company_name',
        'company_phone',
        'company_address'
    ]);
// Add it to the ClaimExtract (this is what you pass to IdTokenResponse, see configuration above)
$extractor->addClaimSet($claimSet);
```
Now, when you pass the company scope with your request it will attempt to locate those properties from your UserEntity::getClaims().

## Install

Via Composer

``` bash
$ composer require steverhoades/oauth2-openid-connect-server
```

## Testing
To run the unit tests you will need to require league/oauth2-server from the source as this repository utilizes some of their existing test infrastructure.
```bash
$ composer require league/oauth2-server --prefer-source
```

Run PHPUnit from the root directory:
```bash
$ vendor/bin/phpunit
```
## License

The MIT License (MIT). Please see [License File](https://github.com/steverhoades/oauth2-openid-connect-client/blob/master/LICENSE) for more information.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
