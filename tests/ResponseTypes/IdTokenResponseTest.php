<?php

namespace OpenIDConnectServer\Test\ResponseTypes;

use Zend\Diactoros\Response;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Builder;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\ClientEntity;
use Lcobucci\JWT\Encoding\JoseEncoder;
use OpenIDConnectServer\ClaimExtractor;
use Psr\Http\Message\ResponseInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use OpenIDConnectServer\IdTokenResponse;
use LeagueTests\Stubs\RefreshTokenEntity;
use OpenIDConnectServer\Test\Stubs\IdentityProvider;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LeagueTests\ResponseTypes\BearerTokenResponseWithParams;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;

class IdTokenResponseTest extends TestCase
{
    public function testGeneratesDefaultHttpResponse()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this->assertAttributeEquals('Bearer', 'token_type', $json);
        $this->assertObjectHasAttribute('expires_in', $json);
        $this->assertObjectHasAttribute('access_token', $json);
        $this->assertObjectHasAttribute('refresh_token', $json);
    }

    public function testOpenIDConnectHttpResponse()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $response = $this->processResponseType($responseType, ['openid']);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this->assertAttributeEquals('Bearer', 'token_type', $json);
        $this->assertObjectHasAttribute('expires_in', $json);
        $this->assertObjectHasAttribute('access_token', $json);
        $this->assertObjectHasAttribute('refresh_token', $json);
        $this->assertObjectHasAttribute('id_token', $json);
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
        $this->fail('Exception should have been thrown');
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
        $this->fail('Exception should have been thrown');
    }

    public function testClaimsGetExtractedFromUserEntity()
    {
        $responseType = new IdTokenResponse(new IdentityProvider(), new ClaimExtractor());
        $responseType->setIdTokenModifier(function ($token) {
            return $token->withClaim('test', 'testValue');
        });

        $response = $this->processResponseType($responseType, ['openid', 'email']);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents());
        $this->assertAttributeEquals('Bearer', 'token_type', $json);
        $this->assertObjectHasAttribute('expires_in', $json);
        $this->assertObjectHasAttribute('access_token', $json);
        $this->assertObjectHasAttribute('refresh_token', $json);
        $this->assertObjectHasAttribute('id_token', $json);

        $token = (new Parser(new JoseEncoder()))->parse($json->id_token);

        $this->assertTrue($token->claims()->has('email'));
        $this->assertEquals($token->claims()->get('test'), 'testValue');
    }

    public function testThrowsRuntimeExceptionWhenMissconfiguredTokenModifier()
    {
        $this->expectException(\RuntimeException::class);

        $responseType = new IdTokenResponse(
            new IdentityProvider(),
            new ClaimExtractor()
        );

        $responseType->setIdTokenModifier(function ($token) {
            return true; // does not return instance of Builder
        });
        
        $this->processResponseType($responseType, ['openid']);
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
        } catch (\TypeError $e) {
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
        } catch (\TypeError $e) {
            $refreshToken->setExpiryDateTime(
                (new \DateTimeImmutable())->add(new \DateInterval('PT1H'))
            );
        }

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType->generateHttpResponse(new Response());
    }
}
