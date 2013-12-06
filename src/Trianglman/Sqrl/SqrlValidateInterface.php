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
 *
 * @author johnj
 */
interface SqrlValidateInterface
{
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
     * Sets an object to be used to store and retrieve SQRL information
     *
     * @param SqrlStoreInterface $storage
     *
     * @return void
     */
    public function setStorage(SqrlStoreInterface $storage);

    /**
     * Sets the authenticating key
     *
     * @param string $key The base64 encoded key
     *
     * @return void
     */
    public function setAuthenticateKey($key);

    /**
     * Sets the signature of the authenticating key
     *
     * @param string $sig The base64 encoded signature
     *
     * @return void
     */
    public function setAuthenticateSignature($sig);

    /**
     * Sets the URL that was signed by the key(s)
     *
     * @param string $url
     *
     * @return void
     */
    public function setSignedUrl($url);

    /**
     * Sets the clientval value that was signed by the key(s)
     *
     * @param string $val
     *
     * @return void
     */
    public function setSignedClientVal($val);

    /**
     * Sets the client's SQRL version
     *
     * @param int $version The client's version
     *
     * @return void
     */
    public function setClientVer($version);

    /**
     * Sets the nonce being validated
     *
     * @param string $nonce
     *
     * @return void
     *
     * @throws SqrlException If the nonce is not valid (either expired or not found in the database)
     */
    public function setNonce($nonce);

    /**
     * Sets the class that will handle the validation
     *
     * @param NonceValidatorInterface $validator
     *
     * @return void
     */
    public function setValidator(NonceValidatorInterface $validator);

    /**
     * Validates that the supplied signature matches the public key
     *
     * @return boolean
     */
    public function validate();

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
     * Sets whether to enforce the same IP check
     *
     * @param boolean $bool
     *
     * @return void
     */
    public function setEnforceIP($bool);

    /**
     * Sets the IP of the user who requested the SQRL image
     *
     * @param string $ip
     *
     * @return void
     */
    public function setRequestorIp($ip);

    /**
     * Validates a secondary request signature (Unlock Request or New Key)
     *
     * @param string $key Base 64 encoded key
     * @param string $sig Base 64 encoded signature
     *
     * @return boolean
     */
    public function validateSignature($key, $sig);
}
