<?php
namespace OpenIDConnectServer\Test;

use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetEntity;
use PHPUnit\Framework\TestCase;
use OpenIDConnectServer\Exception\InvalidArgumentException;

class ClaimExtractorTest extends TestCase
{
    public function testDefaultClaimSetsExist()
    {
        $extractor = new ClaimExtractor();
        self::assertTrue($extractor->hasClaimSet('profile'));
        self::assertTrue($extractor->hasClaimSet('email'));
        self::assertTrue($extractor->hasClaimSet('address'));
        self::assertTrue($extractor->hasClaimSet('phone'));
    }

    public function testCanAddCustomClaimSet()
    {
        $claims = new ClaimSetEntity('custom', ['custom_claim']);
        $extractor = new ClaimExtractor([$claims]);
        self::assertTrue($extractor->hasClaimSet('custom'));

        $result = $extractor->extract(['custom'], ['custom_claim' => 'test']);
        self::assertEquals($result['custom_claim'], 'test');
    }

    public function testCanNotOverrideDefaultScope()
    {
        $this->expectException(InvalidArgumentException::class);
        $claims = new ClaimSetEntity('profile', ['custom_claim']);
        $extractor = new ClaimExtractor([$claims]);
    }

    public function testCanGetClaimSet()
    {
        $extractor = new ClaimExtractor();
        $claimset = $extractor->getClaimSet('profile');
        self::assertEquals($claimset->getScope(), 'profile');
        $claimset = $extractor->getClaimSet('unknown');
        self::assertNull($claimset);
    }

    public function testExtract()
    {
        $extractor = new ClaimExtractor();
        // no result
        $result = $extractor->extract(['custom'], ['custom_claim' => 'test']);
        self::assertEmpty($result);

        // result
        $result = $extractor->extract(['profile'], ['name' => 'Steve']);
        self::assertEquals($result['name'], 'Steve');

        // no result
        $result = $extractor->extract(['profile'], ['invalid' => 'Steve']);
        self::assertEmpty($result);
    }
}
