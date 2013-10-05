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
 * Unit tests for the SqrlGenerate class
 *
 * @author johnj
 */
class SqrlGenerateTest extends \PHPUnit_Framework_TestCase{
    
    public function setup()
    {
        
    }
    
    public function teardown()
    {
        
    }
    
    
    public function testGeneratesUniqueNonce()
    {
        $createdNonces = array();
        
        $obj = new SqrlGenerate();
        $createdNonces[] = $obj->getNonce();
        for($x=0;$x<10;$x++){
            $checkObj = new SqrlGenerate();
            $checkNonce = $checkObj->getNonce();
            $this->assertFalse(in_array($checkNonce, $createdNonces));
            $createdNonces[]=$checkNonce;
        }
        $this->assertEquals($createdNonces[0],$obj->getNonce());
    }
    
    public function testChecksNonceDb()
    {
        $this->markTestIncomplete('Database mock issues');
        $chkStmt = $this->getMock('\PDOStatement',array('execute','fetchColumn','fetchAll'));
        $chkStmt->expects($this->once())->method('execute')->with($this->anything());
        $chkStmt->expects($this->once())->method('fetchColumn')->will($this->returnValue(0));
        $chkStmt->expects($this->once())->method('fetchAll');
        
        $insStmt = $this->getMock('\PDOStatement',array('execute'));
        $insStmt->expects($this->once())->method('execute')->with($this->anything());
        
        $db = new testDB('');
        $db->setPrepareExpectation('SELECT COUNT(*) FROM `testtable` WHERE `nonce` = ?',
                $this->returnValue($chkStmt));
        $db->setPrepareExpectation('INSERT INTO `testtable` (`nonce`) VALUES (?)',
                $this->returnValue($insStmt));
        $obj = new SqrlGenerate();
        $obj->setDatabaseConnection($db,'testtable');
        $obj->getNonce();
    }
    
    /**
     * @depends testGeneratesUniqueNonce
     */
    public function testGeneratesUrlNoQueryString()
    {
        $obj = new SqrlGenerate();
        $obj->setPath('sqrl://example.com/sqrl');
        $nonce = $obj->getNonce();
        
        $this->assertEquals('sqrl://example.com/sqrl?'.$nonce,$obj->getUrl());
    }
    
    /**
     * @depends testGeneratesUniqueNonce
     */
    public function testGeneratesUrlQueryString()
    {
        $obj = new SqrlGenerate();
        $obj->setPath('sqrl://example.com/sqrl?foo=bar');
        $nonce = $obj->getNonce();
        
        $this->assertEquals('sqrl://example.com/sqrl?foo=bar&'.$nonce,$obj->getUrl());
    }
    
    /**
     * @depends testGeneratesUrlNoQueryString
     */
    public function testRenders()
    {
        require dirname(__FILE__).'/../../../vendor/autoload.php';
        $obj = new SQRLGenerate();
        $obj->loadConfigFromJSON(dirname(__FILE__).'/rendertest.json');
        $nonce = $obj->getNonce();
        
        $expected = new \Endroid\QrCode\QrCode();
        $expected->setText('sqrl://example.com/sqrl?'.$nonce);
        $expected->setSize(30);
        $expected->setPadding(1);
        $expected->render(dirname(__FILE__).'/expected.png');
        $obj->render(dirname(__FILE__).'/test.png');
        $this->assertEquals(file_get_contents(dirname(__FILE__).'/expected.png'),
                file_get_contents(dirname(__FILE__).'/test.png'));
        unlink(dirname(__FILE__).'/expected.png');
        unlink(dirname(__FILE__).'/test.png');
    }
}


class testDB extends \PDO{
    public $expectations = array();
    public function __construct($dsn,$user='',$pass=''){
        //don't actually do anything
    }
    
    public function setPrepareExpectation($sql,$returnObj){
        $this->expectations[$sql] = $returnObj;
    }
    
    public function prepare($sql,$options=null){
        if(isset($this->expectations[$sql])){
            return $this->expectations[$sql];
        }
        else{
            throw new Exception('No prepare handler for '.$sql);
        }
    }
}