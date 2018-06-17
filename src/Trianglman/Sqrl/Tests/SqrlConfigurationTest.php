<?php
declare(strict_types=1);
/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 John Judy
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Trianglman\Sqrl\Tests;

use PHPUnit\Framework\TestCase;
use Trianglman\Sqrl\SqrlConfiguration;

/**
 * Tests for SqrlConfiguration
 */
class SqrlConfigurationTest extends TestCase
{
    public function testLoadsMinimalJsonConfig()
    {
        $obj = new SqrlConfiguration();
        $obj->load(__DIR__.'/Resources/onlyReq.json');
        
        $this->assertEquals([1], $obj->getAcceptedVersions());
        $this->assertEquals('domain.com', $obj->getDomain());
        $this->assertEquals('login/sqrlauth.php', $obj->getAuthenticationPath());

        //check defaults are unchanged
        $this->assertFalse($obj->getSecure());
        $this->assertFalse($obj->getAnonAllowed());
        $this->assertEquals(5, $obj->getNonceMaxAge());
        $this->assertEquals(300, $obj->getQrHeight());
        $this->assertEquals(10, $obj->getQrPadding());
    }
    
    public function testLoadsFullJsonConfig()
    {
        $obj = new SqrlConfiguration();
        $obj->load(__DIR__.'/Resources/allOptional.json');
        
        $this->assertEquals([1], $obj->getAcceptedVersions());
        $this->assertEquals('otherdomain.com', $obj->getDomain());
        $this->assertEquals('sqrl.php', $obj->getAuthenticationPath());
        $this->assertTrue($obj->getSecure());
        $this->assertTrue($obj->getAnonAllowed());
        $this->assertEquals(9, $obj->getNonceMaxAge());
        $this->assertEquals(250, $obj->getQrHeight());
        $this->assertEquals(5, $obj->getQrPadding());
        $this->assertEquals('gibberish data', $obj->getNonceSalt());
    }
    
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Configuration data could not be parsed.
     */
    public function testExceptionOnFileNotExisting()
    {
        $obj = new SqrlConfiguration();
        $obj->load(__DIR__.'/Resources/file_does_not_exist.json');
    }
    
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Configuration data could not be parsed.
     */
    public function testExceptionOnInvalidJsonFormat()
    {
        $obj = new SqrlConfiguration();
        $obj->load(__DIR__.'/Resources/bad.json');
    }
    
    public function testSetAcceptedVersionsWithSingleValue()
    {
        $obj = new SqrlConfiguration();
        $obj->setAcceptedVersions(1);
        $this->assertEquals(array(1),$obj->getAcceptedVersions());
    }
}
