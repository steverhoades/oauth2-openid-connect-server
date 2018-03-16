<?php

namespace OpenIDConnectServer\Test\ResponseTypes;

use Lcobucci\JWT\Parser;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\Test\Stubs\IdentityProvider;
use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\ResponseTypes\BearerTokenResponseWithParams;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

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

        $_SERVER['HTTP_HOST'] = 'http://localhost';
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

        $token = (new Parser())->parse($json->id_token);
        $this->assertTrue($token->hasClaim('email'));
    }

    private function processResponseType($responseType, array $scopeNames = ['basic'])
    {
        $_SERVER['HTTP_HOST'] = 'http://localhost';
        $responseType->setPrivateKey(
            new CryptKey('file://' . __DIR__ . '/../Stubs/private.key')
        );
        $responseType->setEncryptionKey(base64_encode(random_bytes(36)));

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
        $accessToken->setExpiryDateTime(
            (new \DateTime())->add(new \DateInterval('PT1H'))
        );
        $accessToken->setClient($client);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime(
            (new \DateTime())->add(new \DateInterval('PT1H'))
        );

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType->generateHttpResponse(new Response());
    }
}
