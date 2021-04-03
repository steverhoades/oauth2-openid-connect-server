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
    public function testGeneratesDefaultHttpResponse()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType);

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

    public function testOpenIDConnectHttpResponse()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, ['openid']);

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
    public function testThrowsRuntimeExceptionWhenMissingClaimSetInterface()
    {
        $this->expectException(\RuntimeException::class);

        $_SERVER['HTTP_HOST'] = 'https://localhost';
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_CLAIMSET),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, ['openid']);
        self::fail('Exception should have been thrown');
    }

    // test fails without identityinterface
    public function testThrowsRuntimeExceptionWhenMissingIdentifierSetInterface()
    {
        $this->expectException(\RuntimeException::class);
        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_IDENTIFIER),
            new ClaimExtractor()
        );
        $this->processResponseType($responseType, ['openid']);
        self::fail('Exception should have been thrown');
    }

    public function testClaimsGetExtractedFromUserEntity()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, ['openid', 'email']);

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

    private function processResponseType($responseType, array $scopeNames = ['basic'])
    {
        $_SERVER['HTTP_HOST'] = 'https://localhost';

        $privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');
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
