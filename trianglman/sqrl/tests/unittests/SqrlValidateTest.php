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

namespace trianglman\sqrl\src;

/**
 * Unit tests for the SqrlValidate class
 *
 * @author johnj
 */
class SqrlValidateTest extends \PHPUnit_Framework_TestCase{
    
    public function setup()
    {
        
    }
    
    public function teardown()
    {
        
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 1
     */
    public function testChecksForSignature()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','sqrlkey'=>'some key','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array();
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 2
     */
    public function testChecksForNonce()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','sqrlkey'=>'some key','ilk'=>'some identity lock key','kv'=>'key verifier');
        $requestPOST = array('sqrlsig'=>'valid signature');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 3
     */
    public function testChecksForPUWK()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>'valid signature');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 5
     */
    public function testChecksSecurity()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','sqrlkey'=>'some key','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>'valid signature');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/unittest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new testValidator());
        $obj->validate();
    }
    
    public function testValidatesWithoutEnforceFlagAndNoDatabase()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','sqrlkey'=>str_replace(array('+','/','='), array('-','_',''), base64_encode('some key')),'ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>str_replace(array('+','/','='), array('-','_',''), base64_encode('valid signature')));
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/unittest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new testValidator());
        $this->assertTrue($obj->validate());
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 4
     */
    public function testChecksEnforceIPWithNoDatabase()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'some key','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>'valid signature');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=enforce&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/unittest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setNonceIp('192.168.0.1');
        $obj->setValidator(new testValidator());
        $obj->validate();
    }
    
    public function testValidatesEnforceFlagGoodAndNoDatabase()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>str_replace(array('+','/','='), array('-','_',''), base64_encode('some key')),'ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>str_replace(array('+','/','='), array('-','_',''), base64_encode('valid signature')));
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=enforce&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/unittest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setNonceIp('127.0.0.1');
        $obj->setValidator(new testValidator());
        $obj->validate();
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 7
     */
    public function testValidatesInvalidSignature()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'','sqrlkey'=>'some key','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'a valid nut');
        $requestPOST = array('sqrlsig'=>'invalid signature');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/unittest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new testValidator());
        $this->assertTrue($obj->validate());
    }
    
}

class testValidator implements \trianglman\sqrl\interfaces\NonceValidator{
    
    public function validateSignature($orig, $sig, $pk) {
        var_dump($orig);
        var_dump($sig);
        var_dump($pk);
        return (($orig=='sqrl://domain.com/login/sqrlauth.php?nut=a valid nut&sqrlver=1&sqrlopt=&sqrlkey=some key&ilk=some identity lock key&kv=key verifier'
                    || $orig=='sqrl://domain.com/login/sqrlauth.php?nut=a valid nut&sqrlver=1&sqrlopt=enforce&sqrlkey=some key&ilk=some identity lock key&kv=key verifier')
                && $sig == 'valid signature'
                && $pk == 'some key');
    }    
}