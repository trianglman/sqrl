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

namespace trianglman\sqrl\src\ed25519;

/**
 * Unit tests for the Crypto class
 *
 * @author johnj
 */
class CryptoTest extends \PHPUnit_Framework_TestCase{
    
    public function setup()
    {
        
    }
    
    public function teardown()
    {
        
    }
    
    public function testGeneratesPublicKey()
    {
        $testData = file_get_contents(dirname(__FILE__).'/../../resources/sign.input');
        //use only a subset of the total data because of how long it takes to run each test
        $fullDataSet = explode("\n", $testData);
        $startofTestSet = rand(0, count($fullDataSet)-10);
        echo "Starting test set at row $startofTestSet\n";
        $dataRows = array_slice($fullDataSet,$startofTestSet,10);
        foreach($dataRows as $set){
            list($skconcat,$pktest) = explode(':',$set);
            $sk = hex2bin(substr($skconcat, 0,64));
            
            
            $obj = new Crypto();
            $pk = $obj->publickey($sk);
            $this->assertEquals($skconcat,  bin2hex($sk.$pk));
            $this->assertEquals($pktest,bin2hex($pk));
        }
    }
    
    
    public function testSigns()
    {
        $testData = file_get_contents(dirname(__FILE__).'/../../resources/sign.input');
        //use only a subset of the total data because of how long it takes to run each test
        $fullDataSet = explode("\n", $testData);
        $startofTestSet = rand(0, count($fullDataSet)-10);
        echo "Starting test set at row $startofTestSet\n";
        $dataRows = array_slice($fullDataSet,$startofTestSet,10);
        foreach($dataRows as $set){
            list($skconcat,$pktest,$m,$sigConcat) = explode(':',$set);
            $sk = hex2bin(substr($skconcat, 0,64));
            $binM = hex2bin($m);
            $obj = new Crypto();
            $sig = $obj->signature($binM, $sk, hex2bin($pktest));
            $this->assertEquals(hex2bin(substr($sigConcat, 0, 128)), $sig);
        }
    }
    
    public function testVerify()
    {
        $testData = file_get_contents(dirname(__FILE__).'/../../resources/sign.input');
        //use only a subset of the total data because of how long it takes to run each test
        $fullDataSet = explode("\n", $testData);
        $startofTestSet = rand(0, count($fullDataSet)-10);
        echo "Starting test set at row $startofTestSet\n";
        $dataRows = array_slice($fullDataSet,$startofTestSet,10);
        foreach($dataRows as $set){
            list($skconcat,$pktest,$m,$sigConcat) = explode(':',$set);
            $binM = hex2bin($m);
            $sig = hex2bin(substr($sigConcat, 0, 128));
            $obj = new Crypto();
            $this->assertTrue($obj->checkvalid($sig, $binM, hex2bin($pktest)));
        }
    }
}
