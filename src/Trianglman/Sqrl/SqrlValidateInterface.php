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
    const VALID_NUT = 0;
    const EXPIRED_NUT = 1;
    const INVALID_NUT = 2;
    /**
     * Sets an object to be used to store and retrieve SQRL information
     *
     * @param SqrlStoreInterface $storage
     *
     * @return void
     */
    public function setStorage(SqrlStoreInterface $storage);
    
    /**
     * Validates the returned server value
     * 
     * @param string $server The returned server value
     * @param string $nut The nut from the request
     * @param string $secure Whether the request was secure
     * 
     * @return boolean
     */
    public function validateServer($server,$nut,$secure);
    
    /**
     * Validates a supplied nut
     * 
     * @param string $nut
     * 
     * @return int One of the nut class constants
     */
    public function validateNut($nut);

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
     * Sets the server data that was signed by the key(s)
     *
     * @param string $val
     *
     * @return void
     */
    public function setSignedServerVal($val);

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
     * Verifies that the server data sent back by the requestor matches
     * the data that was originally sent with the nonce
     * 
     * @param int $requestType The request type the nut is claimed to be sent for
     * @param boolean $https Whether the request was secure
     * @param string|array $serverData The server= information sent by the client
     * 
     * @return boolean
     */
    public function matchServerData($requestType,$https,$serverData);

    /**
     * Validates that the supplied signature matches the public key
     *
     * @return boolean
     */
    public function validate();

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
     * @param string $orig
     * @param string $key 
     * @param string $sig 
     *
     * @return boolean
     */
    public function validateSignature($orig,$key, $sig);
    
    /**
     * Verifies the original nut's IP matches the current IP
     * 
     * @param string $nut
     * @param string $ip
     * 
     * @return boolean
     */
    public function nutIPMatches($nut,$ip);
}
