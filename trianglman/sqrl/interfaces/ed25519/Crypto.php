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

namespace trianglman\sqrl\interfaces\ed25519;

/**
 *
 * @author johnj
 */
interface Crypto {
    /**
     * Generates the public key of a given private key
     * 
     * @param string $sk the secret key
     * @return string
     */
    public function publickey($sk);
    
    /**
     * Signs a string with the private key
     * 
     * @param string $m The message to sign
     * @param string $sk The secret key to sign the message with
     * @param string $pk The public key that will be able to verify the signature
     * 
     * @return string
     */
    public function signature($m,$sk,$pk);
    
    /**
     * Validates a signature matches a given message
     * 
     * @param string $s The message signature
     * @param string $m The original message
     * @param string $pk The public key to verify the signature
     * 
     * @return boolean
     * 
     * @throws \Exception
     */
    public function checkvalid($s,$m,$pk);
    
}
