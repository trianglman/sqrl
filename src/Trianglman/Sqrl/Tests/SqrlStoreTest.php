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

use Trianglman\Sqrl\SqrlRequestHandlerInterface;
use Trianglman\Sqrl\SqrlStore;
use Trianglman\Sqrl\SqrlStoreInterface;

/**
 * Description of SqrlStoreTest
 *
 * @author johnj
 */
class SqrlStoreTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PDO
     */
    protected $db;

    /**
     * @var \PDOStatement
     */
    protected $stmt;

    /**
     * @var SqrlStoreInterface
     */
    protected $obj;

    public function setUp()
    {
        parent::setUp();

        $this->db = $this->getMock('Trianglman\Sqrl\Tests\TestPDO');
        $this->stmt = $this->getMock('PDOStatement');
        $this->obj = new SqrlStore();
        $this->obj->setDatabaseConnection($this->db);
    }

    public function tearDown()
    {
        $this->obj = null;
        $this->stmt = null;
        $this->db = null;

        parent::tearDown();
    }



    public function testStoresNonceNoPubKey()
    {
        $sql = 'INSERT INTO `nonces` (`nonce`,`ip`,`action`) VALUES (?,?,?)';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('123456', '654322', '1')))
            ->will($this->returnValue(true));
        $this->obj->setNonceTable('nonces');
        $this->obj->storeNut('123456', '654322');
    }

    /**
     * @depends testStoresNonceNoPubKey
     */
    public function testStoresNonceWithPubKey()
    {
        $sql = 'INSERT INTO `nonces` (`nonce`,`ip`,`action`,`related_public_key`) VALUES (?,?,?,?)';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('123456', '654322', '2', 'pubkey')))
            ->will($this->returnValue(true));
        $this->obj->setNonceTable('nonces');
        $this->obj->storeNut('123456', '654322', SqrlRequestHandlerInterface::NEW_ACCOUNT_REQUEST, 'pubkey');
    }

    public function testRetrievesNutInfo()
    {
        $sql = 'SELECT `id`,`created`,`action`,`ip`,`related_public_key` FROM `nonces` WHERE `nonce` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('a nonce')))
            ->will($this->returnValue(true));
        $result = array(
            'id' => '1',
            'created' => '2013-11-18 00:00:00',
            'action' => SqrlRequestHandlerInterface::AUTHENTICATION_REQUEST,
            'ip' => '654322',
            'related_public_key' => 'pubkey'
        );
        $this->stmt->expects($this->once())->method('fetchAll')->with($this->equalTo(\PDO::FETCH_ASSOC))
            ->will($this->returnValue(array($result)));
        $this->obj->setNonceTable('nonces');
        $this->assertEquals($result, $this->obj->retrieveNutRecord('a nonce'));
    }

    public function testStoresAuthenticationKey()
    {
        $sql = 'INSERT INTO `pubkeys` (`public_key`) VALUES (?)';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('pubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->storeAuthenticationKey('pubkey');
    }

    public function testRetrievesAuthenticationRecord()
    {
        $sql = 'SELECT `id`,`public_key`,`disabled`,`suk`,`vuk` FROM `pubkeys` WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('pubkey')))
            ->will($this->returnValue(true));
        $result = array(
            'id' => '1',
            'public_key' => 'pubkey',
            'disabled' => '0',
            'suk' => 'serverkey',
            'vuk' => 'verifyunlock'
        );
        $this->stmt->expects($this->once())->method('fetchAll')->with($this->equalTo(\PDO::FETCH_ASSOC))
            ->will($this->returnValue(array($result)));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->assertEquals($result, $this->obj->retrieveAuthenticationRecord('pubkey'));
    }

    /**
     * @depends testRetrievesAuthenticationRecord
     *
     * Wrote a dedicated test for this function since this is the most likely
     * scenario for a single column select to happen
     */
    public function testRetrievesAuthenticationRecordId()
    {
        $sql = 'SELECT `id` FROM `pubkeys` WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('pubkey')))
            ->will($this->returnValue(true));
        $result = array('id' => '1');
        $this->stmt->expects($this->once())->method('fetchAll')->with($this->equalTo(\PDO::FETCH_ASSOC))
            ->will($this->returnValue(array($result)));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->assertEquals('1', $this->obj->retrieveAuthenticationRecord('pubkey', array(SqrlStoreInterface::ID)));
    }

    public function testStoresIdentityLock()
    {
        $sql = 'UPDATE `pubkeys` SET `suk` = ?, `vuk` = ? WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('serverkey', 'verifyunlock', 'pubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->storeIdentityLock('pubkey', 'serverkey', 'verifyunlock');
    }

    public function testLocksKey()
    {
        $sql = 'UPDATE `pubkeys` SET `disabled` = 1 WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('pubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->lockKey('pubkey');
    }

    public function testMigratesAllKeyData()
    {
        $sql = 'UPDATE `pubkeys` SET `public_key` = ?, `disabled` = ?, `suk` = ?, `vuk` = ? WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('newpubkey', 0, 'serverkey', 'verifyunlock', 'oldpubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->migrateKey('oldpubkey', 'newpubkey', 'serverkey', 'verifyunlock');
    }

    /**
     * @depends testMigratesAllKeyData
     */
    public function testMigratesKeyOnly()
    {
        $sql = 'UPDATE `pubkeys` SET `public_key` = ?, `disabled` = ? WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('newpubkey', 0, 'oldpubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->migrateKey('oldpubkey', 'newpubkey');
    }

    /**
     * @depends testMigratesAllKeyData
     */
    public function testMigratesIdentityLockOnly()
    {
        $sql = 'UPDATE `pubkeys` SET `suk` = ?, `vuk` = ? WHERE `public_key` = ?';
        $this->db->expects($this->once())->method('prepare')
            ->with($this->equalTo($sql))->will($this->returnValue($this->stmt));
        $this->stmt->expects($this->once())->method('execute')
            ->with($this->equalTo(array('serverkey', 'verifyunlock', 'oldpubkey')))
            ->will($this->returnValue(true));
        $this->obj->setPublicKeyTable('pubkeys');
        $this->obj->migrateKey('oldpubkey', null, 'serverkey', 'verifyunlock');
    }
}

class TestPDO extends \PDO
{
    public function __construct($dsn = null)
    {
    }
}