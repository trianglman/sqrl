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
namespace Trianglman\Sqrl\Test\Ed25519;

use Trianglman\Sqrl\Ed25519\Crypto;

/**
 * Unit tests for the Crypto class
 *
 * @author johnj
 */
class CryptoTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider publicKeyProvider
     */
    public function testGeneratesPublicKey($skConcat, $pktest, $binM, $sigConcat, $sk)
    {
        if (version_compare(phpversion(), '5.4.0', '<')) {
            $this->markTestSkipped('Test only works in PHP >=5.4.0');
        }

        $obj = new Crypto();
        $pk = $obj->publickey($sk);
        $this->assertEquals($skConcat, bin2hex($sk.$pk));
        $this->assertEquals($pktest, bin2hex($pk));
    }

    /**
     * @dataProvider publicKeyProvider
     */
    public function testSigns($skConcat, $pktest, $binM, $sigConcat, $sk)
    {
        if (version_compare(phpversion(), '5.4.0', '<')) {
            $this->markTestSkipped('Test only works in PHP >=5.4.0');
        }

        $obj = new Crypto();
        $sig = $obj->signature($binM, $sk, hex2bin($pktest));
        $this->assertEquals(hex2bin(substr($sigConcat, 0, 128)), $sig);
    }

    /**
     * @dataProvider publicKeyProvider
     */
    public function testVerify($skConcat, $pktest, $binM, $sigConcat, $sk)
    {
        if (version_compare(phpversion(), '5.4.0', '<')) {
            $this->markTestSkipped('Test only works in PHP >=5.4.0');
        }

        $sig = hex2bin(substr($sigConcat, 0, 128));
        $obj = new Crypto();
        $this->assertTrue($obj->checkvalid($sig, $binM, hex2bin($pktest)));
    }

    public function publicKeyProvider()
    {
        if (version_compare(phpversion(), '5.4.0', '<')) {
            return array(array(0,0,0,0,0));
        }

        $testData = file_get_contents(dirname(__FILE__).'/../Resources/sign.input');
        //use only a subset of the total data because of how long it takes to run each test
        $fullDataSet = explode("\n", $testData);
        $startofTestSet = rand(0, count($fullDataSet)-10);
        $dataRows = array_slice($fullDataSet, $startofTestSet, 10);
        $array = array();
        foreach ($dataRows as $set) {
            list($skConcat, $pktest, $m, $sigConcat) = explode(':', $set);
            $sk = hex2bin(substr($skConcat, 0, 64));
            $binM = hex2bin($m);
            $array[] = array($skConcat, $pktest, $binM, $sigConcat, $sk);
        }

        return $array;
    }
}
