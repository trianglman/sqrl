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

use Trianglman\Sqrl\SqrlStoreInterface;
use Trianglman\Sqrl\SqrlException;
use Trianglman\Sqrl\SqrlRequestHandler;

/**
 * Unit tests for the SqrlRequestHandler class
 *
 * @author johnj
 */
class SqrlRequestHandlerTest extends \PHPUnit_Framework_TestCase
{
    public function testChecksForClientVal()
    {
        $get = array('nut' => 'some 192 delivered nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+client+response+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksForVersion()
    {
        $get = array('nut' => 'some 192 delivered nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce',
            'clientval' => 'opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+version+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksForNonce()
    {
        $get = array();
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+nonce+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksNonceFound()
    {
        $get = array('nut' => 'some never delivered nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some never delivered nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some never delivered nonce')->will(
            $this->throwException(new SqrlException('Nonce not found', SqrlException::NONCE_NOT_FOUND))
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+nonce+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksNonceNotExpired()
    {
        $get = array('nut' => 'some expired nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some expired nonce')->will(
            $this->throwException(new SqrlException('Nonce has expired', SqrlException::EXPIRED_NONCE))
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+nonce+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksForPublicKey()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce',
            'clientval' => 'ver=1&opt=enforce',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with('ver=1&opt=enforce');
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+public+key+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksForServerUrl()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+server+URL+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testChecksForAuthSig()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce'
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=2&display=No+signature+was+included+in+the+request'),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testHandlesFailedEnforceIp()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '127.0.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with(
            'FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag=='
        );
        $validator->expects($this->any())->method('setRequestorIp')->with('127.0.0.1');
        $validator->expects($this->any())->method('validate')->will(
            $this->throwException(
                new SqrlException('IPs do not match: 192.168.0.1 vs. 127.0.0.1', SqrlException::ENFORCE_IP_FAIL)
            )
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode("ver=1&result=3&display=IP+check+failed."),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testHandlesFailedUrlMatch()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'FdmG45-Rkx25y5qTbOU1LWTKG4_pqD2UnBRywqNJ-O0BitxFU1ZC2EggAEXvJqx85-iP6QL-eLAFoK6Q6C43Ag'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some expired nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with(
            'FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag=='
        );
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will(
            $this->throwException(
                new SqrlException('Requested URL doesn\'t match expected URL', SqrlException::SIGNED_URL_DOESNT_MATCH)
            )
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode(
                "ver=1&result=4&display=The+returned+URL+does+not+match+the+initial+SQRL+challenge."
            ),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testHandlesFailedSignatureMatch()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will(
            $this->throwException(new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID))
        );
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode("ver=1&result=5&display=The+signature+is+not+valid."),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    public function testHandlesSuccessfulValidation()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $obj = new SqrlRequestHandler($validator);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode("ver=1&result=1&display=Successfully+authenticated."),
            $obj->getResponseMessage()
        );
        $this->assertEquals('200', $obj->getResponseCode());
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testRequestsSecondLoopNewAuthenticationNoGenerate()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->any())->method('retrieveAuthenticationRecord')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', SqrlStoreInterface::ID)
            ->will($this->returnValue(array()));
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode(
                "ver=1&result=6&display=No+matching+account+found.+Please+supply+Identity+Lock+information."
            ),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testRequestsSecondLoopNewAuthenticationNoGenerate
     */
    public function testRequestsSecondLoopNewAuthenticationWithGenerate()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->any())->method('retrieveAuthenticationRecord')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', SqrlStoreInterface::ID)
            ->will($this->returnValue(array()));
        $gen = $this->getMock('\Trianglman\Sqrl\SqrlGenerateInterface');
        $gen->expects($this->once())->method('getNonce')
            ->with(SqrlRequestHandler::NEW_ACCOUNT_REQUEST, 'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $gen->expects($this->once())->method('getUrl')->will(
            $this->returnValue('sqrl://domain.com/login/sqrlauth.php?nut=some new nonce')
        );
        $obj = new SqrlRequestHandler($validator, $store, $gen);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode(
                "ver=1&result=6&display=No+matching+account+found.+Please+supply+Identity+Lock+information."
                ."&serverurl=sqrl%3A%2F%2Fdomain.com%2Flogin%2Fsqrlauth.php%3Fnut%3Dsome+new+nonce"
            ),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesNewAccountRequest()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::NEW_ACCOUNT_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->any())->method('storeIdentityLock')
            ->with(
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
            );
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode("ver=1&result=1&display=New+account+successfully+created."),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesDisableRequest()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce disable&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce disable&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->any())->method('disableKey')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=1&display=Account+locked.'),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesReKeyRequestNoGenerate()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce rekey&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce rekey&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode("ver=1&result=6&display=Second+loop+required+to+perform+the+re-key+request."),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesReKeyRequestNoGenerate
     */
    public function testHandlesReKeyRequestGenerate()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce rekey&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce rekey&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::AUTHENTICATION_REQUEST)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $gen = $this->getMock('\Trianglman\Sqrl\SqrlGenerateInterface');
        $gen->expects($this->once())->method('getNonce')
            ->with(SqrlRequestHandler::REKEY_REQUEST_LOOP2, 'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $gen->expects($this->once())->method('getUrl')->will(
            $this->returnValue('sqrl://domain.com/login/sqrlauth.php?nut=some new nonce')
        );
        $obj = new SqrlRequestHandler($validator, $store, $gen);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode(
                "ver=1&result=6&display=Second+loop+required+to+perform+the+re-key+request."
                ."&serverurl=sqrl%3A%2F%2Fdomain.com%2Flogin%2Fsqrlauth.php%3Fnut%3Dsome+new+nonce"
            ),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesReKeyLoop2Unlock()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!',
            'urssig' => 'open sesame'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::REKEY_REQUEST_LOOP2)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $validator->expects($this->once())->method('validateSignature')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'open sesame==')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->once())->method('migrateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=1&display=Account+Re-enabled.'),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesReKeyLoop2Migrate()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&newkey=zzzjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!',
            'urssig' => 'open sesame',
            'newkeysig' => 'something new'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&newkey=zzzjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::REKEY_REQUEST_LOOP2)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $validator->expects($this->at(9))->method('validateSignature')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'open sesame==')->will($this->returnValue(true));
        $validator->expects($this->at(10))->method('validateSignature')
            ->with('zzzjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'something new==')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->once())->method('migrateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
            'zzzjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=1&display=Authentication+key+migrated.'),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesReKeyLoop2ReLock()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!',
            'urssig' => 'open sesame',
            'newkeysig' => 'something new'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::REKEY_REQUEST_LOOP2)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $validator->expects($this->once())->method('validateSignature')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'open sesame==')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->any())->method('storeIdentityLock')
            ->with(
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
                'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
            );
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=1&display=Identity+Lock+key+migrated.'),
            $obj->getResponseMessage()
        );
    }

    /**
     * @depends testHandlesSuccessfulValidation
     */
    public function testHandlesReKeyLoop2Replace()
    {
        $get = array('nut' => 'some valid nonce');
        $post = array(
            'serverurl' => 'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce',
            'clientval' => 'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&newkey=zzzjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
                .'&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs',
            'authsig' => 'mwa-haha!',
            'urssig' => 'open sesame',
            'newkeysig' => 'something new'
        );
        $server = array('REMOTE_ADDR' => '192.168.0.1');
        $validator = $this->getMock('\Trianglman\Sqrl\SqrlValidateInterface');
        $validator->expects($this->any())->method('setSignedClientVal')->with(
            'ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&urskey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&newkey=zzzjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
            .'&suk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&vuk=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs'
        );
        $validator->expects($this->any())->method('setClientVer')->with('1');
        $validator->expects($this->any())->method('setNonce')->with('some valid nonce')->will(
            $this->returnValue(SqrlRequestHandler::REKEY_REQUEST_LOOP2)
        );
        $validator->expects($this->any())->method('setEnforceIP')->with(true);
        $validator->expects($this->any())->method('setAuthenticateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $validator->expects($this->any())->method('setSignedUrl')->with(
            'sqrl://domain.com/login/sqrlauth.php?nut=some valid nonce'
        );
        $validator->expects($this->any())->method('setAuthenticateSignature')->with('mwa+haha!==');
        $validator->expects($this->any())->method('setRequestorIp')->with('192.168.0.1');
        $validator->expects($this->any())->method('validate')->will($this->returnValue(true));
        $validator->expects($this->at(9))->method('validateSignature')
            ->with('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'open sesame==')->will($this->returnValue(true));
        $validator->expects($this->at(10))->method('validateSignature')
            ->with('zzzjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=', 'something new==')->will($this->returnValue(true));
        $store = $this->getMock('\Trianglman\Sqrl\SqrlStoreInterface');
        $store->expects($this->once())->method('migrateKey')->with(
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
            'zzzjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=',
            'xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs='
        );
        $obj = new SqrlRequestHandler($validator, $store);
        $obj->parseRequest($get, $post, $server);
        $this->assertEquals(
            'sqrlreply='.urlencode('ver=1&result=1&display=Authentication+keys+migrated.'),
            $obj->getResponseMessage()
        );
    }
}
