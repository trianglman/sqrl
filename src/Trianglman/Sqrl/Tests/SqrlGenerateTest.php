<?php

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

use Endroid\QrCode\QrCode;
use Trianglman\Sqrl\SqrlGenerate;

/**
 * Unit tests for the SqrlGenerate class
 *
 * @author johnj
 */
class SqrlGenerateTest extends \PHPUnit_Framework_TestCase
{
    public function testGeneratesUniqueNonce()
    {
        $createdNonces = array();
        $obj = new SqrlGenerate();
        $createdNonces[] = $obj->getNonce();
        for ($x = 0; $x < 10; $x++) {
            $checkObj = new SqrlGenerate();
            $checkNonce = $checkObj->getNonce();
            $this->assertFalse(in_array($checkNonce, $createdNonces));
            $createdNonces[] = $checkNonce;
        }
        $this->assertEquals($createdNonces[0], $obj->getNonce());
    }

    /**
     * @depends testGeneratesUniqueNonce
     */
    public function testGeneratesUrlNoQueryString()
    {
        $obj = new SqrlGenerate();
        $obj->setSecure(true);
        $obj->setKeyDomain('example.com');
        $obj->setAuthenticationPath('sqrl');
        $nonce = $obj->getNonce();
        $this->assertEquals('sqrl://example.com/sqrl?nut='.$nonce, $obj->getUrl());
    }

    /**
     * @depends testGeneratesUniqueNonce
     */
    public function testGeneratesUrlQueryString()
    {
        $obj = new SqrlGenerate();
        $obj->setSecure(false);
        $obj->setKeyDomain('example.com');
        $obj->setAuthenticationPath('sqrl?foo=bar');
        $nonce = $obj->getNonce();
        $this->assertEquals('qrl://example.com/sqrl?foo=bar&nut='.$nonce, $obj->getUrl());
    }

    /**
     * @depends testGeneratesUrlNoQueryString
     */
    public function testGeneratesUrlExpandedDomain()
    {
        $obj = new SqrlGenerate();
        $obj->setSecure(true);
        $obj->setKeyDomain('example.com/unique');
        $obj->setAuthenticationPath('sqrl');
        $nonce = $obj->getNonce();
        $this->assertEquals('sqrl://example.com/unique|sqrl?nut='.$nonce, $obj->getUrl());
    }

    /**
     * @depends testGeneratesUrlNoQueryString
     */
    public function testRenders()
    {
        $obj = new SQRLGenerate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $nonce = $obj->getNonce();
        $expected = new QrCode();
        $expected->setText('sqrl://domain.com/login/sqrlauth.php?nut='.$nonce);
        $expected->setSize(30);
        $expected->setPadding(1);
        $expected->render(dirname(__FILE__).'/expected.png');
        $obj->render(dirname(__FILE__).'/test.png');
        $this->assertEquals(
            file_get_contents(dirname(__FILE__).'/expected.png'),
            file_get_contents(dirname(__FILE__).'/test.png')
        );
        unlink(dirname(__FILE__).'/expected.png');
        unlink(dirname(__FILE__).'/test.png');
    }
}
