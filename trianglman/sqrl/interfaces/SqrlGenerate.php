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
 * Generates a SQRL QR image, URL and nonce.
 * 
 * @author johnj
 */
interface SqrlGenerate {
    
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
     * Sets whether to require an HTTPS response
     * 
     * Switches the URL scheme between sqrl:// and qrl://
     * 
     * @param boolean $sec
     * 
     * @return void
     */
    public function setSecure($sec);
    
    /**
     * Sets the domain the client should use to generate it's private/public key pair
     * 
     * If the domain includes a /, this will cause the final URL to include d=
     * 
     * @param string $domain
     * 
     * @return void
     */
    public function setKeyDomain($domain);
    
    /**
     * Sets the path to the file that will authenticate client responses
     * 
     * @param string $path
     * 
     * @return void
     */
    public function setAuthenticationPath($path);
    
    /**
     * Sets the height of the QR image that will be generatated
     * 
     * @param int $height The height in pixels
     * 
     * @return void
     */
    public function setHeight($height);
    
    /**
     * Sets the internal padding between the edge of the image and the QR code
     * 
     * @param int $pad The size of the padding in pixels
     * 
     * @return void
     */
    public function setPadding($pad);
    
    /**
     * Sets the salt to be used as part of generating the nonce
     * 
     * @param string $salt
     * 
     * @return void
     */
    public function setSalt($salt);
    
    /**
     * Sets the IP of the user who requested the SQRL image
     * 
     * @param string $ip
     * 
     * @return void
     */
    public function setRequestorIp($ip);
    
    /**
     * Sets the database configuration details
     * 
     * @param string $dsn A connection string that PDO can parse
     * @param string $username The connection user name to use
     * @param string $pass The connection password
     * @param string $nonceTable The table to store nonces in. It must have a nonce column and generate a unique ID on insert
     * 
     * @return void
     * 
     * @link http://us2.php.net/manual/en/pdo.connections.php Details for the $dsn variable configuration
     */
    public function configureDatabase($dsn,$username,$pass,$nonceTable);
    
    /**
     * Sets the database connection directly
     * 
     * @param \PDO $db The database connection
     * @param string $nonceTable The table to store the nonce in
     * 
     * @return void
     */
    public function setDatabaseConnection(\PDO $db,$nonceTable);
    
    /**
     * Generates the QR code image
     * 
     * @param string $outputFile
     * 
     * @return void
     */
    public function render($outputFile);

    /**
     * Returns the generated nonce
     * 
     * @return string The one time use number for the QR link
     */
    public function getNonce();
    
    /**
     * Gets the validation URL including the nonce
     * 
     * @return string
     */
    public function getUrl();
}
