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
use Laminas\Diactoros\Response;

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

        $responseType = new IdTokenResponse(
            new IdentityProvider(IdentityProvider::NO_CLAIMSET),
            new ClaimExtractor(),
            'https://localhost'
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
MIIEpQIBAAKCAQEAzjgUbG97UD+bZwkceejvxkbcq/17YqmriWGpBu7etXAA2WZp
x7vLaQi6ygApfCsYDz13W27DyriH2kg56GOa2v9M88OORiW1rQMaGF4hn/L7agFc
cvdNAWBKD8ue+QUPz3prA3TLF+lSqMn5BgF+4j7XNlODvfOX3Tra1JQcVik4pyjg
QeTLaaBSf6KaCvDzVCcvVuYISC5oku5v6o+BIug8taRhcXN8/9gLQ9akrGG73z+u
dAoZ2+v1k7VZ704steLM9pf7aY+L6kR2Qmc7E4j/WM9Sv8CHUaJG41MRAbjdHtGh
zGcsZwf/mNjyjW3UalI1dih2muhPTSAZT0xL+wIDAQABAoIBAAFDBJT5RabjDL9f
peX1D+qFqnn+7g9XfG41w8QAGCrCCa9K2iDXvFHjNMlhoN9aoCYPuTg9AEOwR1yF
jp0mZt8qKr1fF/LD7k2ltDYr9Ua2ROWMJpWpf7YfcbSRCWL6rfMWC6uUvl1iFxhj
S/vGbJFT0xtI/YhfAjHfV1FvqpC4YwmKVe4/QqU0Kw+CjmYKLqeR0lvARP0aRfRm
GRIy/9ZtUzbcUSnLScNS8U2HhdKEOl/R9dSjHVG+rr+/sJmFRUiQWJx3UkDZ4lTd
lEIqj8i0CZMooARZjOIhIjP+wT9zr1sWFaxU81ourMnfoOQSKIrkUUYGc4rOk3Ao
DuqBx9ECgYEA5miGw2v+2YIm1XtmTRvLJiDgr8mTWydylPXxjTlghYNKts4bU5rh
EN/Ok+DUPLqPGQLnFgjcadT/clZfJXF3/gOS8V9hxVWI6Gwku1Ez7OqtCv3plA0i
46fxh0PmK6lFOzlbWMN1wpQ/mB3dWh4YaC6ERG1Z3L1DCIqYs/LVFsMCgYEA5R/A
dJAwtPWjdEjKFaajH7Z7iB/BSUydyPg++sMDjETbrV3wddO67LEkhH3vB4VDEKKt
FnD1iSyWprb94gDK0PTxQyHJ3JdzDP05L+7C+lwLqEKCrh2BZpScvub0FRgECNNO
OCuoMtX1HG/dGjkJsxB7e1lr7LGFMyPjR6I+0mkCgYEAzvcznpUCvnTX10naUgdW
SzCbQ6xJDkd3+HCYAuh4WFXgJicrisUDyHmRgWoim05lPe1KkJNzEim/MAB/xQ2Q
4H5rXx/zniPAMC78K7q8buM6fzYnu9K09VQldAC835lUU+eosyoYPKmYGlcxP0Lr
X6HxM9oaL1tevGxq0LGfUasCgYEA3R4ybouE5e61KxDgLdreTEmgl/MFZwbQs1WX
+grfzqvZUUt6N0v5dllSQ6cBWkGqQlCsOB8VZqeoUAYDp+tZ0CTC/SWLmR5zwtJS
MUb71f+kpGJjmUMSUXwUdUuPvRerNRUvxJelQEIpxaLTP25SRQQgFx9qP0fmoz78
JXKXrBkCgYEApBfmVsOTG5S+oO7WZFpndeofLnXYn9xRvlc738+dANY4mWwHJlBd
z2wzJ5wfjzlXsZoKcV0I6pRWLrgw3Gd5cwu3O5+MUN89cdQuVrfB77KQJHIF+S06
fHDgr/HSgH8LCXDq4DSd5XC0WxCPTDYrTN8iiHop2k35Ex0UXYeE+g0=
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
