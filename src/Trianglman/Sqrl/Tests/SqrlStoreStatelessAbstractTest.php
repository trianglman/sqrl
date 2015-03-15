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

/**
 * Tests for  SqrlStoreStatelessAbstract
 *
 * @author johnj
 */
class SqrlStoreStatelessAbstractTest extends \PHPUnit_Framework_TestCase
{
    protected $testStub = null;
    
    public function setup()
    {
        $this->testStub = $this->getMockBuilder('\Trianglman\Sqrl\SqrlStoreStatelessAbstract')
                ->disableOriginalConstructor()
                ->disableArgumentCloning()
                ->getMockForAbstractClass();
        $this->testStub->expects($this->any())->method('getCurrentSessionId')
                ->will($this->returnValue('currentSessionID of long length'));
        $this->testStub->expects($this->any())->method('getIP')
                ->will($this->returnValue('192.168.0.105'));
        $this->testStub->setNonceSalt('123456789');
    }
    
    public function testGeneratesAndReadsNewNut()
    {
        $sessionData = array();
        $this->testStub->expects($this->exactly(3))->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnCallback(function($sessId) use (&$sessionData) {
                    return $sessionData;
                }));
        $this->testStub->expects($this->once())->method('setSessionValue')
                ->with(
                        $this->equalTo('currentSessionID of long length'),
                        $this->equalTo('sqrl_nuts'),
                        $this->anything()
                        );
        $nut = $this->testStub->generateNut();
        
        $sessionData['sqrl_nuts']=$nut;
        
        $info = $this->testStub->getNutDetails($nut);
        
        $this->assertTrue(is_array($info));
        $this->assertEquals(0,$info['tif']);
        $this->assertEquals('',$info['originalKey']);
        $this->assertEquals($nut,$info['originalNut']);
        $this->assertInstanceOf('\DateTime',$info['createdDate']);
        $this->assertEquals('192.168.0.105',$info['nutIP']);
        $this->assertEquals('currentSessionID of long length',$info['sessionId']);
        return $nut;
    }
    
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     */
    public function testLogsSessionIn($nut)
    {
        $this->testStub->expects($this->once())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnValue(array('sqrl_nuts'=>$nut)));
        $this->testStub->expects($this->once())->method('setSessionValue')
                ->with(
                        $this->equalTo('currentSessionID of long length'),
                        $this->equalTo('sqrl_authenticated'),
                        $this->equalTo('1')
                        );
        $this->testStub->logSessionIn($nut);
    }
    
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     */
    public function testGeneratesAndReadsSecondLoopNut($nut)
    {
        $sessionData = array('sqrl_nuts'=>$nut);
        $this->testStub->expects($this->any())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnCallback(function($sessId) use (&$sessionData) {
                    return $sessionData;
                }));
        $this->testStub->expects($this->exactly(2))->method('setSessionValue')
                ->with(
                        $this->equalTo('currentSessionID of long length'),
                        $this->anything(),
                        $this->anything()
                        )
                ->will($this->returnCallback(function($sesId,$sessKey,$value) use ($nut) {
                    if ($sessKey === 'sqrl_nuts') {
                        $this->assertTrue(strpos($value, $nut.';')===0);
                    } elseif ($sessKey === 'sqrl_key') {
                        $this->assertEquals('some valid key',$value);
                    } else {
                        $this->assertFalse(true,$sessKey.' not an expected key.');
                    }
                }));
        $newNut = $this->testStub->generateNut(0x5,'some valid key',$nut);
        
        $sessionData['sqrl_nuts']=$nut.';'.$newNut;
        $sessionData['sqrl_key']='some valid key';
        
        $info = $this->testStub->getNutDetails($newNut);
        
        $this->assertTrue(is_array($info));
        $this->assertEquals(0x5,$info['tif']);
        $this->assertEquals('some valid key',$info['originalKey']);
        $this->assertEquals($nut,$info['originalNut']);
        $this->assertInstanceOf('\DateTime',$info['createdDate']);
        $this->assertEquals('192.168.0.105',$info['nutIP']);
        $this->assertEquals('currentSessionID of long length',$info['sessionId']);
        return $newNut;
    }
    
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     */
    public function testGeneratesAndReadsNewNutDoesntCreateNewIfOneExists($nut)
    {
        $this->testStub->expects($this->any())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnValue(array('sqrl_nuts'=>$nut)));
        $this->assertEquals($nut, $this->testStub->generateNut());
    }
    
    public function testRejectsBadNut()
    {
        $this->testStub->expects($this->never())->method('getSessionInfo');
        $this->assertNull($this->testStub->getNutDetails('gibberishnonsense'));
    }
    
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     */
    public function testRejectsUnknownNut($nut)
    {
        $this->testStub->expects($this->any())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnValue(null));
        $this->assertNull($this->testStub->getNutDetails($nut));
    }
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     */
    public function testRejectsNutNotFromSession($nut)
    {
        $this->testStub->expects($this->any())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnValue(array('sqrl_nuts'=>'someothernut')));
        $this->assertNull($this->testStub->getNutDetails($nut));
    }
    /**
     * 
     * @depends testGeneratesAndReadsNewNut
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Old nut was not found.
     */
    public function testGeneratesAndReadsSecondLoopNutBadOldNut($nut)
    {
        $sessionData = array('sqrl_nuts'=>'someothernut');
        $this->testStub->expects($this->any())->method('getSessionInfo')
                ->with($this->equalTo('currentSessionID of long length'))
                ->will($this->returnCallback(function($sessId) use (&$sessionData) {
                    return $sessionData;
                }));
        $this->testStub->expects($this->never())->method('setSessionValue');
        $this->testStub->generateNut(0x5,'some valid key',$nut);
    }
    
}
