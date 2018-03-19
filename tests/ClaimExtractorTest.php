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
        $this->assertTrue($extractor->hasClaimSet('profile'));
        $this->assertTrue($extractor->hasClaimSet('email'));
        $this->assertTrue($extractor->hasClaimSet('address'));
        $this->assertTrue($extractor->hasClaimSet('phone'));
    }

    public function testCanAddCustomClaimSet()
    {
        $claims = new ClaimSetEntity('custom', ['custom_claim']);
        $extractor = new ClaimExtractor([$claims]);
        $this->assertTrue($extractor->hasClaimSet('custom'));

        $result = $extractor->extract(['custom'], ['custom_claim' => 'test']);
        $this->assertEquals($result['custom_claim'], 'test');
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
        $this->assertEquals($claimset->getScope(), 'profile');
        $claimset = $extractor->getClaimSet('unknown');
        $this->assertNull($claimset);
    }

    public function testExtract()
    {
        $extractor = new ClaimExtractor();
        // no result
        $result = $extractor->extract(['custom'], ['custom_claim' => 'test']);
        $this->assertEmpty($result);

        // result
        $result = $extractor->extract(['profile'], ['name' => 'Steve']);
        $this->assertEquals($result['name'], 'Steve');

        // no result
        $result = $extractor->extract(['profile'], ['invalid' => 'Steve']);
        $this->assertEmpty($result);
    }
}
