<?php
declare(strict_types=1);
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

use PHPUnit\Framework\TestCase;
use Trianglman\Sqrl\SodiumNonceValidator;

class SodiumNonceValidatorTest extends TestCase
{
    /**
     * @var SodiumNonceValidator
     */
    private $validator;

    public function setUp()/* The :void return type declaration that should be here would cause a BC issue */
    {
        parent::setUp();
        if (!function_exists('sodium_crypto_sign_open')) {
            $this->markTestSkipped('sodium_crypto_sign_open not supported');
        }
        $this->validator = new SodiumNonceValidator();
    }

    /**
     * Test data taken from https://www.grc.com/dev/sqrl/Four-phase-update.txt
     */
    public function testValidatesTrue()
    {
        $idk = base64_decode('3DoDRDKwrLAQmpa/6YNQFwq0wZyN5uEChbGYzRGs+jM==');
        //$urlencode = str_replace(array('+','/'), array('-','_'), $base64);
        $ids = base64_decode(
            'viqGSMvzIf7y8OHGec4X9zC4IQUQQbbAIWujvPp4uVtsv5sHNfxZCjZh1UoJIVPgJLHXOr3Z+Cu8tUKqPJVjAw='
        );
        $msg = 'dmVyPTENCmNtZD1xdWVyeQ0KaWRrPTNEb0RSREt3ckxBUW1wYV82WU5RRndxMHdaeU41dUVDaGJHWXpSR3Mtak0NCm9wdD1zdWsNCn'
            .'BpZGs9MGVnMUd0ZVlMNnN3Sy13RnJhR0NQNnJUOE9GbF9DbEpCcXRybjc2ZFgtaw0Kc3FybDovL3d3dy5zdGV2ZS9zcXJsP251dD1pbV'
            .'RUUE1FVV9WM3VUamc3MldDMmNnJnNmbj1SMUpE';
        $this->assertTrue($this->validator->validateSignature($msg, $ids, $idk), 'Signature failed to validate');
    }

    /**
     * Modified two characters of the above message
     * @depends testValidatesTrue
     */
    public function testValidatesFalse()
    {
        $idk = base64_decode('3DoDRDKwrLAQmpa/6YNQFwq0wZyN5uEChbGYzRGs+jM==');
        $ids = base64_decode(
            'viqGSMvzIf7y8OHGec4X9zC4IQUQQbbAIWujvPp4uVtsv5sHNfxZCjZh1UoJIVPgJLHXOr3Z+Cu8tUKqPJVjAw='
        );
        $msg = 'dmVyPTENCmNtZD1xdWVyeiiKaWRrPTNEb0RSREt3ckxBUW1wYV82WU5RRndxMHdaeU41dUVDaGJHWXpSR3Mtak0NCm9wdD1zdWsNCn'
            .'BpZGs9MGVnMUd0ZVlMNnN3Sy13RnJhR0NQNnJUOE9GbF9DbEpCcXRybjc2ZFgtaw0Kc3FybDovL3d3dy5zdGV2ZS9zcXJsP251dD1pbV'
            .'RUUE1FVV9WM3VUamc3MldDMmNnJnNmbj1SMUpE';
        $this->assertFalse($this->validator->validateSignature($msg, $ids, $idk), 'Signature incorrectly validated');
    }
}