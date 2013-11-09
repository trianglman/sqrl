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
require_once "PHPUnit/Extensions/Database/TestCase.php";
require_once dirname(__FILE__).'/../DbUnit_Array_DataSet.php';
use \trianglman\sqrl\DbUnit_Array_DataSet;

require_once "PHPUnit/Extensions/Database/TestCase.php";
/**
 * Description of SqrlValidateIntegrationTest
 *
 * @author johnj
 */
class SqrlValidateIntegrationTest extends \PHPUnit_Extensions_Database_TestCase{
    
    /**
     * @return PHPUnit_Extensions_Database_DB_IDatabaseConnection
     */
    public function getConnection()
    {
        if(file_exists('/tmp/sqrl_test_db.db')){
            unlink('/tmp/sqrl_test_db.db');
        }
        $pdo = new \PDO('sqlite:/tmp/sqrl_test_db.db');
        $pdo->exec(file_get_contents(dirname(__FILE__).'/../databaseStructure/base.sql'));
        return $this->createDefaultDBConnection($pdo, 'sqrl_test');
    }
 
    /**
     * @return PHPUnit_Extensions_Database_DataSet_IDataSet
     */
    public function getDataSet()
    {
        return new DbUnit_Array_DataSet(include dirname(__FILE__).'/../databaseStructure/SqrlIntegrationInitialState.php');
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 6
     */
    public function testChecksNonceDb()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'not a valid nut');
        $requestPOST = array('sqrlsig'=>'G-jZkH9_aOZ8_giAZrlxqZJkS0zlUJHx5xb6F_btl2XeOpQlLedXYIfqseJvfOywRdM_a7uHqh2OcXY094mZAw');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=not a valid nut&sqrlver=1&sqrlopt=enforce&sqrlkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 4
     */
    public function testChecksEnforceDb()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some 192 delivered nonce');
        $requestPOST = array('sqrlsig'=>'G-jZkH9_aOZ8_giAZrlxqZJkS0zlUJHx5xb6F_btl2XeOpQlLedXYIfqseJvfOywRdM_a7uHqh2OcXY094mZAw');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'127.0.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some 192 delivered nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
    }
    
    public function testValidatesSignature()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some 192 delivered nonce');
        $requestPOST = array('sqrlsig'=>'G-jZkH9_aOZ8_giAZrlxqZJkS0zlUJHx5xb6F_btl2XeOpQlLedXYIfqseJvfOywRdM_a7uHqh2OcXY094mZAw');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'192.168.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some 192 delivered nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($obj->validate());
    }
    
    /**
     * @depends testValidatesSignature
     */
    public function testValidatesSignature2()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some 192 delivered nonce');
        $requestPOST = array('sqrlsig'=>'UCWHuHe6WhCLIE9xoiN3J-3d0nQ2GsWxNvifR1dOIzSRLhiQlfpLVjNesXhRDsA1SNycaXxkKQ3eYKWEvZIXAg');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'192.168.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some 192 delivered nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($obj->validate());
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 7
     */
    public function testChecksInvalidSignature()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some 192 delivered nonce');
        $requestPOST = array('sqrlsig'=>'G-jZkH9_aOZ8_giAZrlxqZJkS0zlUJHx5xb6F_btl2XeOpQlLedXYIfqseJvfOywRdM_a7uHqh3OcXY094mZAw');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'192.168.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some 192 delivered nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 8
     */
    public function testChecksStaleNonce()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some stale nonce');
        $requestPOST = array('sqrlsig'=>'wRd-ihDitG8m-_vcciWZii2bFd28VfXxtFG0H3xHs4avqrutZedQ4ZgMc6tYirborQYkiuVFDOxY6bnlEbKZBg');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'192.168.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some stale nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
    }
    
    /**
     * @depends testValidatesSignature
     */
    public function testChecksExistingPublicKey()
    {
        $requestGET = array('sqrlver'=>'1','sqrlopt'=>'enforce','sqrlkey'=>'xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs','ilk'=>'some identity lock key','kv'=>'key verifier','nut'=>'some 192 delivered nonce');
        $requestPOST = array('sqrlsig'=>'G-jZkH9_aOZ8_giAZrlxqZJkS0zlUJHx5xb6F_btl2XeOpQlLedXYIfqseJvfOywRdM_a7uHqh2OcXY094mZAw');
        $requestHEADERS = array('SERVER_NAME'=>'domain.com','REQUEST_URI'=>'/login/sqrlauth.php','REMOTE_ADDR'=>'192.168.0.1','HTTPS'=>'1',
             'QUERY_STRING' =>'nut=some 192 delivered nonce&sqrlver=1&sqrlopt=enforce&sqrlkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs&ilk=some identity lock key&kv=key verifier');
        
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->parseSQRLRequest($requestGET, $requestPOST, $requestHEADERS);
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
        $this->assertEquals(1,$obj->storePublicKey());
    }
    
}
