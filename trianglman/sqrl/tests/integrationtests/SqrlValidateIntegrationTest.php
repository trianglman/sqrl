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
     * @expectedExceptionCode 3
     */
    public function testChecksNonceDb()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $obj->setClientVer('1');
        $obj->setNonce('not a valid nut');
    }
    
    /**
     * @depends testChecksNonceDb
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 5
     */
    public function testChecksStaleNonce()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg');
        $obj->setClientVer('1');
        $obj->setNonce('some stale nonce');
        
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 1
     */
    public function testChecksEnforceDb()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $obj->setClientVer('1');
        $obj->setNonce('some 192 delivered nonce');
        $obj->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $obj->setAuthenticateSignature('G+jZkH9/aOZ8/giAZrlxqZJkS0zlUJHx5xb6F/btl2XeOpQlLedXYIfqseJvfOywRdM/a7uHqh2OcXY094mZAw==');
        $obj->setRequestorIp('127.0.0.1');
        $obj->setEnforceIP(true);
        
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
    }
    
    public function testValidatesSignature()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $obj->setClientVer('1');
        $obj->setNonce('some 192 delivered nonce');
        $obj->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $obj->setAuthenticateSignature('FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag==');
        $obj->setRequestorIp('192.168.0.1');
        $obj->setEnforceIP(true);
        
        $obj->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($obj->validate());
    }
    
    /**
     * @depends testValidatesSignature
     */
    public function testValidatesSignature2()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg');
        $obj->setClientVer('1');
        $obj->setNonce('some 192 delivered nonce');
        $obj->setAuthenticateKey('W/yg+zTXTp/9fGnkMfRYYpNZLTD+0TDmFcLK7r3fyZg=');
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $obj->setAuthenticateSignature('ZBL2xqxJHl/CvxtLlqkUG/2hgoslS1G4SGpslReW68EN6xLo0vFdoPFSz/hTFt3sJQI56RsfpMGhTEu9UtOPDQ==');
        $obj->setRequestorIp('192.168.0.1');
        $obj->setEnforceIP(true);
        
        $obj->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($obj->validate());
    }
    
    /**
     * @expectedException \trianglman\sqrl\src\SqrlException
     * @expectedExceptionCode 4
     */
    public function testChecksInvalidSignature()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $obj->setClientVer('1');
        $obj->setNonce('some 192 delivered nonce');
        $obj->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $obj->setAuthenticateSignature('FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag==');
        $obj->setRequestorIp('192.168.0.1');
        
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
    }
    
    /**
     * @depends testValidatesSignature
     */
    public function testChecksExistingPublicKey()
    {
        $obj = new SqrlValidate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/../resources/functionaltest.json');
        
        $obj->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $obj->setClientVer('1');
        $obj->setNonce('some 192 delivered nonce');
        $obj->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $obj->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $obj->setAuthenticateSignature('FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag==');
        $obj->setRequestorIp('192.168.0.1');
        $obj->setEnforceIP(true);
        
        $obj->setValidator(new Ed25519NonceValidator());
        $obj->validate();
        $this->assertEquals(1,$obj->getPublicKeyIdentifier());
    }
    
}
