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

namespace trianglman\sqrl\interfaces;

/**
 * Validates a nonce/public key pair
 * 
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 * 
 * @author johnj
 */
interface SqrlValidate {
    
    /**
     * Loads a configuration file from the supplied path
     * 
     * @param string $filePath Path to a JSON formatted configuration file
     * 
     * @return void
     * 
     * @throws \InvalidArgumentException If the file does not exist
     * @throws \InvalidArgumentException If the file is not JSON formatted
     */
    public function loadConfigFromJSON($filePath);
    
    /**
     * Parses out the SQRL authentication request into the key(s), signature(s) and other meta data required for validation
     * 
     * @param array $getParam The _GET request array
     * @param array $postParam The _POST request array
     * @param array $headers The request headers (_SERVER)
     * 
     * @return void
     * 
     * @throws \trianglman\sqrl\src\SqrlException If the required SQRL parameters are not found
     */
    public function parseSQRLRequest($getParam,$postParam,$headers);
    
    /**
     * Sets the nonce being validated
     * 
     * @param string $nonce
     * 
     * @return void
     * 
     * @throws \trianglman\sqrl\src\SqrlException If the nonce is not valid (either expired or not found in the database)
     */
    public function setNonce($nonce);
    
    /**
     * Sets the class that will handle the validation
     * 
     * @param \trianglman\sqrl\interfaces\NonceValidator $validator
     * 
     * @return void
     */
    public function setValidator(\trianglman\sqrl\interfaces\NonceValidator $validator);
    
    /**
     * Validates that the supplied signature matches the public key
     * 
     * @return boolean
     */
    public function validate();
    
    /**
     * Checks to see if the public key has already been used on this site.
     * 
     * If it matches, the matching identifier will be returned, otherwise null will
     * be stored.
     * 
     * @return int|NULL The databases unique identifier for the public key
     * 
     * @throws \RuntimeException If no database has been configured
     */
    public function getPublicKeyIdentifier();
    
    /**
     * Gets the public key parsed from the request
     * 
     * @return string
     * 
     * @throws \RuntimeException if no request information has been parsed
     */
    public function getPublicKey();
    
    /**
     * Gets the nonce being returned in the request
     * 
     * @return string
     * 
     * @throws \RuntimeException if no request information has been parsed
     */
    public function getNonce();
    
    /**
     * Sets the IP of the user who requested the SQRL image
     * 
     * @param string $ip
     * 
     * @return void
     */
    public function setRequestorIp($ip);
    
 }
