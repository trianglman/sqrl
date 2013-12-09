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

/**
 * Unit tests for the SqrlValidate class
 *
 * @author johnj
 */
class SqrlValidateTest extends \PHPUnit_Framework_TestCase
{
    public function testValidatesWithoutEnforceFlagAndNoDatabase()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $orig = 'clientval=ver=1&opt=&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
            .'&serverurl=sqrl://domain.com/login/sqrlauth.php?nut=a valid nut';
        $sig = 'valid signature';
        $pk = 'some key';
        $validator->expects($this->once())->method('validateSignature')->with($orig, $sig, $pk)->will(
            $this->returnValue(true)
        );
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=&authkey='.str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode('some key'))
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('valid signature'));
        $obj->setValidator($validator);
        $this->assertTrue($obj->validate());
    }

    public function testValidatesSecondarySignature()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $orig = 'clientval=ver=1&opt=&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
            .'&serverurl=sqrl://domain.com/login/sqrlauth.php?nut=a valid nut';
        $validator->expects($this->once())->method('validateSignature')->with($orig, 'otherSig', 'other key')->will(
            $this->returnValue(true)
        );
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=&authkey='.str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode('some key'))
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('valid signature'));
        $obj->setValidator($validator);
        $this->assertTrue($obj->validateSignature('other key', 'otherSig'));
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 1
     */
    public function testChecksEnforceIPWithNoDatabase()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=enforce&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('valid signature'));
        $obj->setRequestorIp('127.0.0.1');
        $obj->setEnforceIP(true);
        $obj->setNonceIp('192.168.0.1');
        $obj->setValidator($validator);
        $obj->validate();
    }

    public function testValidatesEnforceFlagGoodAndNoDatabase()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $orig = 'clientval=ver=1&opt=enforce&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
            .'&serverurl=sqrl://domain.com/login/sqrlauth.php?nut=a valid nut';
        $sig = 'valid signature';
        $pk = 'some key';
        $validator->expects($this->once())->method('validateSignature')->with($orig, $sig, $pk)->will(
            $this->returnValue(true)
        );
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=enforce&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('valid signature'));
        $obj->setRequestorIp('127.0.0.1');
        $obj->setEnforceIP(true);
        $obj->setNonceIp('127.0.0.1');
        $obj->setValidator($validator);
        $obj->validate();
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 4
     */
    public function testValidatesInvalidSignature()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $orig = 'clientval=ver=1&opt=&authkey='.str_replace(
                array('+', '/', '='),
                array('-', '_', ''),
                base64_encode('some key')
            )
            .'&serverurl=sqrl://domain.com/login/sqrlauth.php?nut=a valid nut';
        $sig = 'invalid signature';
        $pk = 'some key';
        $validator->expects($this->once())->method('validateSignature')->with($orig, $sig, $pk)->will(
            $this->returnValue(false)
        );
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=&authkey='.str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode('some key'))
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('invalid signature'));
        $obj->setRequestorIp('127.0.0.1');
        $obj->setValidator($validator);
        $this->assertTrue($obj->validate());
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 2
     */
    public function testValidatesUrlsMatch()
    {
        $validator = $this->getMock('\Trianglman\Sqrl\NonceValidatorInterface');
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
        $obj->setSignedClientVal(
            'ver=1&opt=&authkey='.str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode('some key'))
        );
        $obj->setClientVer('1');
        $obj->setNonce('a valid nut');
        $obj->setAuthenticateKey(base64_encode('some key'));
        $obj->setSignedUrl('qrl://domain.com/login/sqrlauth.php?nut=a valid nut');
        $obj->setAuthenticateSignature(base64_encode('invalid signature'));
        $obj->setRequestorIp('127.0.0.1');
        $obj->setValidator($validator);
        $this->assertTrue($obj->validate());
    }
}
