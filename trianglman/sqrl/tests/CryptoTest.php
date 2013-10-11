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
class CryptoTest extends \PHPUnit_Framework_TestCase
{
    protected $dataRows = array();

    public function setup()
    {
        $testData = file_get_contents(dirname(__FILE__).'/sign.input');
        $this->dataRows = array_slice(explode("\n", $testData),0,1);
    }
    
    public function teardown()
    {
        
    }
    
    public function testCheckSignature()
    {
        foreach($this->dataRows as $set){
            list($skconcat,$pk,$m,$concat) = explode(':',$set);
            // Public key
            $pk = hex2bin($pk);
            // Message
            $m = hex2bin($m);
            // Signed message is 64 bytes long with message appended
            $sig = hex2bin(substr($concat, 0, 128));

            $obj = new Crypto();

            $this->assertEquals(true, $obj->checkValid($sig, $m, $pk), 'checkValid failed');
        }
    }

    public function testGenerateSignature()
    {
        foreach($this->dataRows as $set){
            list($skconcat,$pk,$m,$concat) = explode(':',$set);
            // Secret key is 32 bytes long with public key appended
            $sk = hex2bin(substr($skconcat, 0, 64));
            // Public key
            $pk = hex2bin($pk);
            // Message
            $m = hex2bin($m);
            // Signed message is 64 bytes long with message appended
            $sig = hex2bin(substr($concat, 0, 128));
            
            $obj = new Crypto();

            $this->assertEquals(bin2hex($sig), bin2hex(substr($obj->signature($m, $sk, $pk), 0, 64)), 'Generating Signature failed');
        }
    }

    public function testGeneratePublicKey()
    {
        foreach($this->dataRows as $set){
            list($skconcat,$pk,$m,$concat) = explode(':',$set);
            // Secret key is 32 bytes long with public key appended
            $sk = hex2bin(substr($skconcat, 0, 64));
            // Public key
            $pk = hex2bin($pk);
            
            $obj = new Crypto();

            $genpk = $obj->publickey($sk);
            $this->assertEquals(bin2hex($pk), bin2hex($genpk), 'Generating Public key failed');
        }
    }
}
