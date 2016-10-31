# OAuth 2.0 OpenID Connect Server

This implements the OpenID Connect specification on top of The PHP League's [OAuth2 Server](https://github.com/thephpleague/oauth2-server).

## Requirements

The following versions of PHP are supported.

* PHP 5.5
* PHP 5.6
* PHP 7.0

## Usage
The following classes will need to be configured and passed to the AuthorizationServer in order to provide OpenID Connect functionality.  

1. IdentityRepository.  This should implement the IdentityRepositoryInterface and return the identity of the user based on the return value of $accessToken->getUserIdentifier().
1. ClaimSet.  ClaimSet is a way to associate claims to a given scope.
1. ClaimExtractor. The ClaimExtractor takes an array of ClaimSets and in addition provides default claims for the OpenID Connect specified scopes of: profile, email, phone and address.
1. IdTokenResponse. This class must be passed to the AuthorizationServer during construction and is responsible for adding the id_token to the response.

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

## Install

Via Composer

``` bash
$ composer require steverhoades/oauth2-openid-connect-server
```

## License

The MIT License (MIT). Please see [License File](https://github.com/steverhoades/oauth2-openid-connect-client/blob/master/LICENSE) for more information.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
