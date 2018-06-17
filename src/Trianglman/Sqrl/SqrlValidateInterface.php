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
namespace Trianglman\Sqrl;

/**
 * Validates a nonce/public key pair
 *
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 */
interface SqrlValidateInterface
{
    const VALID_NUT = 0;
    const EXPIRED_NUT = 1;
    const INVALID_NUT = 2;
    const KEY_MISMATCH = 3;
    /**
     * Validates the returned server value
     * 
     * @param string $server The returned server value
     * @param string $nut The nut from the request
     * @param bool $secure Whether the request was secure
     * 
     * @return boolean
     */
    public function validateServer($server, string $nut, bool $secure): bool;
    
    /**
     * Validates a supplied nut
     * 
     * @param string $nut
     * @param string $signingKey The key used to sign the current request
     * 
     * @return int One of the nut class constants
     */
    public function validateNut(string $nut, string $signingKey = null): int;

    /**
     * Validates a secondary request signature (Unlock Request or New Key)
     *
     * @param string $orig
     * @param string $key 
     * @param string $sig 
     *
     * @return boolean
     */
    public function validateSignature(string $orig, string $key, string $sig): bool ;
    
    /**
     * Verifies the original nut's IP matches the current IP
     * 
     * @param string $nut
     * @param string $ip
     * 
     * @return boolean
     */
    public function nutIPMatches(string $nut, string $ip): bool;
}
