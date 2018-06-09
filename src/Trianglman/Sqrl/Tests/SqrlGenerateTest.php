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

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Endroid\QrCode\QrCode;
use Trianglman\Sqrl\SqrlConfiguration;
use Trianglman\Sqrl\SqrlGenerate;
use Trianglman\Sqrl\SqrlStoreInterface;
use Trianglman\Sqrl\SqrlStoreStatelessAbstract;

/**
 * Unit tests for the SqrlGenerate class
 *
 * @author johnj
 */
class SqrlGenerateTest extends TestCase
{
    /**
     * @var MockObject|SqrlConfiguration
     */
    protected $config = null;
    /**
     * @var MockObject|SqrlStoreInterface
     */
    protected $storage = null;
    
    public function setup()
    {
        $this->config = $this->getMockBuilder(SqrlConfiguration::class)->getMock();
        $this->config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));
        $this->storage = $this->getMockBuilder(SqrlStoreInterface::class)->getMock();
    }
    
    /**
     * Tests the getNonce() function when called with no arguments
     * 
     * This should check the storage for an existing nonce, find nothing, 
     * generate a completely random nonce, and send it to the storage for stateful
     * saving
     */
    public function testGeneratesStatefulNonceInitialRequest()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue(null));
        $this->storage->expects($this->once())
                ->method('storeNonce')
                ->with($this->anything(),$this->equalTo(0),$this->equalTo(''),$this->equalTo(''))
                ->will($this->returnCallback(function($nut) {
                    $this->assertRegExp('/[a-z0-9]{64}/',$nut,'Nut is not properly formatted');
                }));
        $obj = new SqrlGenerate($this->config,$this->storage);
        $obj->getNonce();
    }
    
    /**
     * Tests the getNonce() function when called with no arguments where storage is
     * semi-stateless
     * 
     * This should check the storage for an existing nonce, find nothing, and
     * request a semi-stateless nut from storage
     */
    public function testGeneratesStatelessNonceInitialRequest()
    {
        /** @var MockObject|SqrlStoreStatelessAbstract $storage */
        $storage = $this->getMockBuilder(SqrlStoreStatelessAbstract::class)
                ->disableOriginalConstructor()
                ->setMethods(array('generateNut'))
                ->getMockForAbstractClass();
        $storage->expects($this->once())->method('generateNut')
                ->with($this->equalTo(0),$this->equalTo(''),$this->equalTo(''))
                ->will($this->returnValue('semi-stateless nut'));
        
        $obj = new SqrlGenerate($this->config,$storage);
        
        $this->assertEquals('semi-stateless nut',$obj->getNonce());
    }
    
    /**
     * Tests the getNonce() function when called with no arguments where storage 
     * already holds an active nonce
     * 
     * This should check the storage for an existing nonce and find it
     */
    public function testReloadsActiveNonce()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue('stored nut'));
        $this->storage->expects($this->never())->method('storeNonce');
        $obj = new SqrlGenerate($this->config,$this->storage);
        $this->assertEquals('stored nut', $obj->getNonce());
    }
    
    /**
     * Tests the getNonce() function when called with previous nut state arguments
     * 
     * This should generate a completely random nonce and store it and the previous
     * state information
     * @depends testGeneratesStatefulNonceInitialRequest
     */
    public function testGeneratesStatefulNonceSecondLoop()
    {
        $this->storage->expects($this->never())
                ->method('getSessionNonce')
                ->will($this->returnValue(null));
        $this->storage->expects($this->once())
                ->method('storeNonce')
                ->with($this->anything(),$this->equalTo(5),$this->equalTo('validkey'),$this->equalTo('previousNut'))
                ->will($this->returnCallback(function($nut) {
                    $this->assertRegExp('/[a-z0-9]{64}/',$nut,'Nut is not properly formatted');
                }));
        $obj = new SqrlGenerate($this->config,$this->storage);
        $obj->getNonce(5,'validkey','previousNut');
    }
    
    /**
     * Tests the getNonce() function when called with no arguments where storage is
     * semi-stateless when called with previous nut state arguments
     * 
     * This should request a semi-stateless nut from storage including the previous
     * state information
     * 
     * @depends testGeneratesStatelessNonceInitialRequest
     */
    public function testGeneratesStatelessNonceSecondLoop()
    {
        /** @var MockObject|SqrlStoreStatelessAbstract $storage */
        $storage = $this->getMockBuilder(SqrlStoreStatelessAbstract::class)
                ->disableOriginalConstructor()
                ->setMethods(array('generateNut'))
                ->getMockForAbstractClass();
        $storage->expects($this->once())->method('generateNut')
                ->with($this->equalTo(5),$this->equalTo('validkey'),$this->equalTo('previousNut'))
                ->will($this->returnValue('semi-stateless nut'));
        
        $obj = new SqrlGenerate($this->config,$storage);
        $this->assertEquals('semi-stateless nut',$obj->getNonce(5,'validkey','previousNut'));
    }
    
    /**
     * @depends testReloadsActiveNonce
     */
    public function testGeneratesQryNoQueryString()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue('storednut'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('/sqrl'));
        
        $obj = new SqrlGenerate($this->config,$this->storage);
        $this->assertEquals('/sqrl?nut=storednut', $obj->generateQry());
    }
    
    /**
     * @depends testReloadsActiveNonce
     */
    public function testGeneratesQryWithQueryString()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue('storednut'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('/sqrl?foo=bar'));
        
        $obj = new SqrlGenerate($this->config,$this->storage);
        $this->assertEquals('/sqrl?foo=bar&nut=storednut', $obj->generateQry());
    }
    
    /**
     * @depends testGeneratesQryNoQueryString
     */
    public function testGeneratesUrl()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue('storednut'));
        $this->config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        
        $obj = new SqrlGenerate($this->config,$this->storage);
        $this->assertEquals('sqrl://example.com/sqrl?nut=storednut', $obj->getUrl());
    }
    
    /**
     * @depends testGeneratesQryNoQueryString
     */
    public function testGeneratesUrlIncludingExtendedDomain()
    {
        $this->storage->expects($this->once())
                ->method('getSessionNonce')
                ->will($this->returnValue('storednut'));
        $this->config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com/~user'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('/~user/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        
        $obj = new SqrlGenerate($this->config,$this->storage);
        $this->assertEquals('sqrl://example.com/~user/sqrl?nut=storednut&d=6', $obj->getUrl());
    }


    /**
     * @depends testGeneratesUrl
     * @throws \Endroid\QrCode\Exceptions\ImageFunctionUnknownException
     */
    public function testRenders()
    {
        $this->storage->expects($this->once())->method('getSessionNonce')
                ->will($this->returnValue('storednut'));
        $this->config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('/sqrl'));
        $this->config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        $this->config->expects($this->any())->method('getQrHeight')
                ->will($this->returnValue(30));
        $this->config->expects($this->any())->method('getQrPadding')
                ->will($this->returnValue(1));
        
        $obj = new SQRLGenerate($this->config,$this->storage);
        $expected = new QrCode();
        $expected->setText('sqrl://example.com/sqrl?nut=storednut');
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
