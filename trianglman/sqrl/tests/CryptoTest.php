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
    
    public function testValidatesSignature()
    {
        $testData = file_get_contents(dirname(__FILE__).'/sign.input');
        $dataRows = array_slice(explode("\n", $testData),0,10);
        foreach($dataRows as $set){
            list($skconcat,$pk,$m,$concat) = explode(':',$set);
            $sk = hex2bin(substr($skconcat, 0,64));
            
            
            $obj = new Crypto();
            $pk = $obj->publickey($sk);
            $this->assertEquals($skconcat,  bin2hex($sk.$pk));
        }
    }
}