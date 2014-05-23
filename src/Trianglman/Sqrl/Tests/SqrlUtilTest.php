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

use Trianglman\Sqrl\SqrlUtil;
use \Exception;

/**
 * Unit tests for the SqrlUtil class
 *
 * @author johnj
 */
class SqrlUtilTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Happy path -- config loads fine
     */
    public function testLoadConfigFromJSON()
    {
        try {
            $config = SqrlUtil::loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.json');
            $this->assertObjectHasAttribute('secure', $config);
            $this->assertObjectHasAttribute('key_domain', $config);
            $this->assertObjectHasAttribute('authentication_path', $config);
            $this->assertObjectHasAttribute('height', $config);
            $this->assertObjectHasAttribute('padding', $config);
            $this->assertObjectHasAttribute('nonce_salt', $config);
        }
        catch (Exception $e) {
            $this->fail('Configuration file was not loaded or was not a JSON file.');
        }
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testFileDoesNotExistException()
    {
        SqrlUtil::loadConfigFromJSON(dirname(__FILE__).'/Resources/notafile.json');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testFileIsNotJSONException()
    {
        SqrlUtil::loadConfigFromJSON(dirname(__FILE__).'/Resources/unittest.txt');
    }
}