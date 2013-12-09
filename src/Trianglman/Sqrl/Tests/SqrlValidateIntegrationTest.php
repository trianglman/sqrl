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

use Trianglman\Sqrl\SqrlException;
use Trianglman\Sqrl\SqrlStore;
use Trianglman\Sqrl\SqrlValidate;
use Trianglman\Sqrl\Ed25519NonceValidator;

/**
 * Description of SqrlValidateIntegrationTest
 *
 * @author johnj
 */
class SqrlValidateIntegrationTest extends \PHPUnit_Extensions_Database_TestCase
{
    /**
     * @return \PHPUnit_Extensions_Database_DB_IDatabaseConnection
     */
    public function getConnection()
    {
        $sysTemp = sys_get_temp_dir();
        $file = $sysTemp.'/sqrl_test_db.db';
        if (file_exists($file)) {
            unlink($file);
        }

        $pdo = new \PDO('sqlite:'.$file);
        $pdo->exec(file_get_contents(dirname(__FILE__).'/Resources/databaseStructure/base.sql'));

        return $this->createDefaultDBConnection($pdo, 'sqrl_test');
    }

    /**
     * @return \PHPUnit_Extensions_Database_DataSet_IDataSet
     */
    public function getDataSet()
    {
        return new DbUnitArrayDataSet(include dirname(
                __FILE__
            ).'/Resources/databaseStructure/SqrlIntegrationInitialState.php');
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 3
     */
    public function testChecksNonceDb()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $val->setClientVer('1');
        $val->setNonce('not a valid nut');
    }

    /**
     * @depends               testChecksNonceDb
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 5
     */
    public function testChecksStaleNonce()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=enforce&authkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg');
        $val->setClientVer('1');
        $val->setNonce('some stale nonce');
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 1
     */
    public function testChecksEnforceDb()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $val->setClientVer('1');
        $val->setNonce('some 192 delivered nonce');
        $val->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $val->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $val->setAuthenticateSignature(
            'G+jZkH9/aOZ8/giAZrlxqZJkS0zlUJHx5xb6F/btl2XeOpQlLedXYIfqseJvfOywRdM/a7uHqh2OcXY094mZAw=='
        );
        $val->setRequestorIp('127.0.0.1');
        $val->setEnforceIP(true);
        $val->setValidator(new Ed25519NonceValidator());
        $val->validate();
    }

    public function testValidatesSignature()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=enforce&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $val->setClientVer('1');
        $val->setNonce('some 192 delivered nonce');
        $val->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $val->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $val->setAuthenticateSignature(
            'FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag=='
        );
        $val->setRequestorIp('192.168.0.1');
        $val->setEnforceIP(true);
        $val->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($val->validate());
    }

    /**
     * @depends testValidatesSignature
     */
    public function testValidatesSignature2()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=enforce&authkey=W_yg-zTXTp_9fGnkMfRYYpNZLTD-0TDmFcLK7r3fyZg');
        $val->setClientVer('1');
        $val->setNonce('some 192 delivered nonce');
        $val->setAuthenticateKey('W/yg+zTXTp/9fGnkMfRYYpNZLTD+0TDmFcLK7r3fyZg=');
        $val->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $val->setAuthenticateSignature(
            'ZBL2xqxJHl/CvxtLlqkUG/2hgoslS1G4SGpslReW68EN6xLo0vFdoPFSz/hTFt3sJQI56RsfpMGhTEu9UtOPDQ=='
        );
        $val->setRequestorIp('192.168.0.1');
        $val->setEnforceIP(true);
        $val->setValidator(new Ed25519NonceValidator());
        $this->assertTrue($val->validate());
    }

    /**
     * @expectedException \Trianglman\Sqrl\SqrlException
     * @expectedExceptionCode 4
     */
    public function testChecksInvalidSignature()
    {
        $val = new SqrlValidate();
        $val->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $store = new SqrlStore();
        $store->loadConfigFromJSON(dirname(__FILE__).'/Resources/functionaltest.json');
        $val->setStorage($store);
        $val->setSignedClientVal('ver=1&opt=&authkey=xLOjlTKNdYFkCx-OMQT7hSoK7Ta54ioKZgWrh2ig0Fs');
        $val->setClientVer('1');
        $val->setNonce('some 192 delivered nonce');
        $val->setAuthenticateKey('xLOjlTKNdYFkCx+OMQT7hSoK7Ta54ioKZgWrh2ig0Fs=');
        $val->setSignedUrl('sqrl://domain.com/login/sqrlauth.php?nut=some 192 delivered nonce');
        $val->setAuthenticateSignature(
            'FdmG45+Rkx25y5qTbOU1LWTKG4/pqD2UnBRywqNJ+O0BitxFU1ZC2EggAEXvJqx85+iP6QL+eLAFoK6Q6C43Ag=='
        );
        $val->setRequestorIp('192.168.0.1');
        $val->setValidator(new Ed25519NonceValidator());
        $val->validate();
    }
}
