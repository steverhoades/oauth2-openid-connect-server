<?php

namespace OpenIDConnectServer\Test\ResponseTypes;

use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\Test\Stubs\IdentityProvider;
use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\CryptKey;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;

class IdTokenResponseTest extends TestCase
{
    /**
     * @dataProvider provideCryptKeys
     */
    public function testGeneratesDefaultHttpResponse($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
    }

    /**
     * @dataProvider provideCryptKeys
     */
    public function testOpenIDConnectHttpResponse($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey, ['openid']);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
        self::assertObjectHasAttribute('id_token', $json);
    }

    // test additional claims
    // test fails without claimsetinterface
    /**
     * @dataProvider provideCryptKeys
     */
    public function testThrowsRuntimeExceptionWhenMissingClaimSetInterface($privateKey)
    {
        $this->expectException(\RuntimeException::class);

        $_SERVER['HTTP_HOST'] = 'https://localhost';
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_CLAIMSET),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, $privateKey, ['openid']);
        self::fail('Exception should have been thrown');
    }

    // test fails without identityinterface
    /**
     * @dataProvider provideCryptKeys
     */
    public function testThrowsRuntimeExceptionWhenMissingIdentifierSetInterface($privateKey)
    {
        $this->expectException(\RuntimeException::class);
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_IDENTIFIER),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, $privateKey, ['openid']);
        self::fail('Exception should have been thrown');
    }

    /**
     * @dataProvider provideCryptKeys
     */
    public function testClaimsGetExtractedFromUserEntity($privateKey)
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, $privateKey, ['openid', 'email']);

        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('no-cache', $response->getHeader('pragma')[0]);
        self::assertEquals('no-store', $response->getHeader('cache-control')[0]);
        self::assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(),false);

        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasAttribute('expires_in', $json);
        self::assertObjectHasAttribute('access_token', $json);
        self::assertObjectHasAttribute('refresh_token', $json);
        self::assertObjectHasAttribute('id_token', $json);

        if (class_exists("\Lcobucci\JWT\Token\Parser")) {
            $parser = new \Lcobucci\JWT\Token\Parser(new \Lcobucci\JWT\Encoding\JoseEncoder, \Lcobucci\JWT\Encoding\ChainedFormatter::withUnixTimestampDates());
        } else {
            $parser = new \Lcobucci\JWT\Parser();
        }

        $token = $parser->parse($json->id_token);
        self::assertTrue($token->claims()->has("email"));
    }

    public static function provideCryptKeys()
    {
        return array(
            array(new CryptKey('file://'.__DIR__.'/../Stubs/private.key')),
            array(new CryptKey(
                <<<KEY
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDOBcFjGUlo3BJ9zjwQLgAHn6Oy5Si0uB7MublTiPob8rWTiCE4
weAFqzPoAB07vB0t0f8c1R8rmwHMD5ljWPBgJ8FewtwAUzprOBcau6DWukd/TKxX
WeVLAl/NZxijI+jR5QDBYLNBtj1G4LBVHMmINd3ryCycbf9ac3rcC8zhrQIDAQAB
AoGADfOJ0wIlXHp6rhZHLvlOezWuSjEGfqZxP3/cMvH1rerTrPfs+AD5AKlFTJKl
aCQm/bFYy0ULZVKL3pu30Wh2bo1nh/wLuLSI9Nz3O8jqAP3z0i07SoRoQmb8fRnn
dwoDFqnk3uGqcOenheSqheIgl9vdW/3avhD6nkMKZGxPYwECQQDoSj/xHogEzMqB
1Z2E5H/exeE9GQ7+dGITRR2MSgo9WvcKdRhGaQ44dsnTmqiZWAfqAPJjTQIIA/Cn
YRRTeBbNAkEA4w0iEvCIygGQOAnWuvVzlh+pxIB+BTeGkbiBG7nkYYc9b6B/Tw1B
GWGRddBr/FIfPvy1X2ip/TBpH+9bHnE2YQJBAIbZw/EYhmIy+UUSW9WwSUNsoOu1
Rm0V53HEZ/jvaq5fxpa9j5AgoO7KlzROzp3m6wE/93cKV6mLkAO7ae9jAekCQQCf
B6DZIS6+RrAMACAt3SOzf8P6BYG/B7Ayusd7cw2ang4S9JiW9xKkw2kN2wj3t1F5
XalwBTAjTdgj7ROmU+ehAkEAkOyXKONGBoVfaixRHgBP6jIBSSPbB2Aosi0QAURX
6GOY7wOS1pCSntTOBQxV7wVjqFwYAR10MSxFSNfpJ7RkzA==
-----END RSA PRIVATE KEY-----
KEY
            ),
        ));
    }

    private function processResponseType($responseType, $privateKey,  array $scopeNames = ['basic'])
    {
        $_SERVER['HTTP_HOST'] = 'https://localhost';

        $responseType->setPrivateKey($privateKey);

        // league/oauth2-server 5.1.0 does not support this interface
        if (method_exists($responseType, 'setEncryptionKey')) {
            $responseType->setEncryptionKey(base64_encode(random_bytes(36)));
        }

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $scopes = [];
        foreach ($scopeNames as $scopeName) {
            $scope = new ScopeEntity();
            $scope->setIdentifier($scopeName);
            $scopes[] = $scope;
        }

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');

        if (method_exists($accessToken, 'setPrivateKey')) {
            $accessToken->setPrivateKey($privateKey);
        }

        // Use DateTime for older libraries, DateTimeImmutable for new ones.
        try {
            $accessToken->setExpiryDateTime(
                (new \DateTime())->add(new \DateInterval('PT1H'))
            );
        } catch(\TypeError $e) {
            $accessToken->setExpiryDateTime(
                (new \DateTimeImmutable())->add(new \DateInterval('PT1H'))
            );
        }
        $accessToken->setClient($client);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);

        // Use DateTime for older libraries, DateTimeImmutable for new ones.
        try {
            $refreshToken->setExpiryDateTime(
                (new \DateTime())->add(new \DateInterval('PT1H'))
            );
        } catch(\TypeError $e) {
            $refreshToken->setExpiryDateTime(
                (new \DateTimeImmutable())->add(new \DateInterval('PT1H'))
            );
        }

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType->generateHttpResponse(new Response());
    }
}
