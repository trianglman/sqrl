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
        $config = $this->getMock('\Trianglman\Sqrl\SqrlConfiguration');
        $config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));

        $createdNonces = array();
        $obj = new SqrlGenerate();
        $obj->setConfiguration($config);
        $createdNonces[] = $obj->getNonce();
        for ($x = 0; $x < 10; $x++) {
            $checkObj = new SqrlGenerate();
            $checkObj->setConfiguration($config);
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
        $config = $this->getMock('\Trianglman\Sqrl\SqrlConfiguration');
        $config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));
        $config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        $config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com'));
        $config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('sqrl'));
        
        $obj = new SqrlGenerate();
        $obj->setConfiguration($config);
        $nonce = $obj->getNonce();
        $this->assertEquals('sqrl://example.com/sqrl?nut='.$nonce, $obj->getUrl());
    }

    /**
     * @depends testGeneratesUniqueNonce
     */
    public function testGeneratesUrlQueryString()
    {
        $config = $this->getMock('\Trianglman\Sqrl\SqrlConfiguration');
        $config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));
        $config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(false));
        $config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com/unique'));
        $config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('sqrl?foo=bar'));
        
        $obj = new SqrlGenerate();
        $obj->setConfiguration($config);
        $nonce = $obj->getNonce();
        $this->assertEquals('qrl://example.com/unique|sqrl?foo=bar&nut='.$nonce, $obj->getUrl());
    }

    /**
     * @depends testGeneratesUrlNoQueryString
     */
    public function testRenders()
    {
        $config = $this->getMock('\Trianglman\Sqrl\SqrlConfiguration');
        $config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));
        $config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        $config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('domain.com'));
        $config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('login/sqrlauth.php'));
        $config->expects($this->any())->method('getQrHeight')
                ->will($this->returnValue(30));
        $config->expects($this->any())->method('getQrPadding')
                ->will($this->returnValue(1));
        
        
        $obj = new SQRLGenerate();
        $obj->setConfiguration($config);
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
