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

use Trianglman\Sqrl\SqrlValidate;
use Trianglman\Sqrl\SqrlRequestHandler;

/**
 * Unit tests for the SqrlValidate class
 *
 * @author johnj
 */
class SqrlValidateTest extends \PHPUnit_Framework_TestCase
{
    protected $config = null;
    protected $val = null;
    
    public function setup()
    {
        $this->config = $this->getMock('\Trianglman\Sqrl\SqrlConfiguration');
        $this->config->expects($this->any())->method('getNonceSalt')
                ->will($this->returnValue('randomsalt'));
        $this->val = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
    }
    
    public function testMatchesUrlSuccess()
    {
        $this->config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        $this->config->expects($this->any())->method('getDomain')
                ->will($this->returnValue('example.com'));
        $this->config->expects($this->any())->method('getAuthenticationPath')
                ->will($this->returnValue('sqrl.php'));
        
        $obj = new SqrlValidate($this->config,$this->val);
        $obj->setNonce('test nonce');
        
        $this->assertTrue($obj->matchServerData(
                SqrlRequestHandler::INITIAL_REQUEST, 
                true, 
                'sqrl://example.com/sqrl.php?nut=test nonce'
                ));
        
    }
    
    public function testMatchesServerResponseSuccess()
    {
        $this->config->expects($this->any())->method('getSecure')
                ->will($this->returnValue(true));
        $this->config->expects($this->any())->method('getAcceptedVersions')
                ->will($this->returnValue(array(1)));
        $this->config->expects($this->any())->method('getFriendlyName')
                ->will($this->returnValue('Example Server'));
        $data = array();
        $data['ver'] = '1';
        $data['sfn'] = 'Example Server';
        
        $obj = new SqrlValidate($this->config,$this->val);
        $obj->setNonce('test nonce');
        $obj->setNonceAction(SqrlRequestHandler::ID_MATCH);
        
        $this->assertTrue($obj->matchServerData(SqrlRequestHandler::ID_MATCH, true, $data));
    }
    
    public function testValidatesSuccess()
    {
        $this->val->expects($this->any())->method('validateSignature')
                ->with(
                        $this->equalTo('server=datafromserver&client=datafromclient'),
                        $this->equalTo('the signature of the message'),
                        $this->equalTo('the test key')
                        )
                ->will($this->returnValue(true));
        
        $obj = new SqrlValidate($this->config,$this->val);
        $obj->setSignedServerVal('datafromserver');
        $obj->setSignedClientVal('datafromclient');
        $obj->setAuthenticateKey('the test key');
        $obj->setAuthenticateSignature('the signature of the message');
        $obj->setNonceIp('192.168.0.1');
        $obj->setRequestorIp('192.168.0.1');
        
        $this->assertTrue($obj->validate());
    }
    
}
