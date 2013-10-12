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

namespace trianglman\sqrl\src;

/**
 * Generates a SQRL QR image, URL and nonce.
 *
 * @author johnj
 */
class SqrlGenerate implements \trianglman\sqrl\interfaces\SqrlGenerate {
    
    protected $_dsn='';
    
    protected $_dbUserName='';
    
    protected $_dbPass='';
    
    protected $_nonceTable='';
    
    protected $_db=null;
    
    protected $_secure=false;
    
    protected $_domain='';
    
    protected $_authPath='';
    
    protected $_d = 0;
    
    protected $_qrHeight=300;
    
    protected $_qrPad=10;
    
    protected $_salt='asWB^<O]3>H*`a`h_b$XX6r*^6WkNV!;hAgL,X}:#mag"pq)lpUFuj^d5R3i?;X';
    
    protected $_nonce='';

    public function getNonce()
    {
        if(empty($this->_nonce)){
            $this->_generateNonce();
        }
        return $this->_nonce;
    }
    
    public function getUrl()
    {
        return $this->_buildUrl();
    }

    public function loadConfigFromJSON($filePath)
    {
        if(!file_exists($filePath)){
            throw new \InvalidArgumentException('Configuration file not found');
        }
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if(is_null($decoded)){
            throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');
        }
        if(!empty($decoded->secure)){
            $this->setSecure($decoded->secure>0);
        }
        if(!empty($decoded->key_domain)){
            $this->setKeyDomain($decoded->key_domain);
        }
        if(!empty($decoded->authentication_path)){
            $this->setAuthenticationPath($decoded->authentication_path);
        }
        if(!empty($decoded->height)){
            $this->setHeight($decoded->height);
        }
        if(!empty($decoded->padding)){
            $this->setPadding($decoded->padding);
        }
        if(!empty($decoded->nonce_salt)){
            $this->setSalt($decoded->nonce_salt);
        }
        if(!empty($decoded->dsn)
                && !empty($decoded->username)
                && !empty($decoded->nonce_table)){
            $this->configureDatabase($decoded->dsn, $decoded->username, $decoded->password, $decoded->nonce_table);
        }
    }

    public function render($outputFile) 
    {
        $qrCode = new \Endroid\QrCode\QrCode();
        $qrCode->setText($this->getUrl());
        $qrCode->setSize($this->_qrHeight);
        $qrCode->setPadding($this->_qrPad);
        $qrCode->render($outputFile);
    }

    public function setHeight($height)
    {
        if(is_numeric($height)){
            $this->_qrHeight = $height;
        }
    }

    public function setPadding($pad) 
    {
        if(is_numeric($pad)){
            $this->_qrPad = $pad;
        }
    }

    public function setSalt($salt) 
    {
        $this->_salt = $salt;
    }
    
    public function configureDatabase($dsn,$username,$pass,$nonceTable)
    {
        $this->_dsn = $dsn;
        $this->_dbUserName = $username;
        $this->_dbPass = $pass;
        $this->_nonceTable = $nonceTable;
    }
    
    public function setDatabaseConnection(\PDO $db,$nonceTable)
    {
        $this->_db = $db;
        $this->_nonceTable = $nonceTable;
    }
    
    /**
     * A wrapper function to either get an existing or generate a new database connection
     * 
     * @return \PDO
     */
    protected function _connectToDatabase()
    {
        if(!is_null($this->_db)){
            return $this->_db;
        }
        if(empty($this->_dsn)){
            return null;
        }
        try{
            $this->_db = new \PDO($this->_dsn,$this->_dbUserName,$this->_dbPass);
        } catch (\PDOException $ex) {
            return null;
        }
        return $this->_db;
    }
    
    /**
     * Generates a random, one time use key to be used in the sqrl validation
     * 
     * The implementation of this may get more complicated depending on the 
     * requirements detailed in any reference implementation. Users wanting to 
     * make this library more (or less) secure should override this function 
     * to strengthen (or weaken) the randomness of the generation.
     * 
     * If there is a database connection available, this function will also 
     * verify the uniqueness of the nonce.
     * 
     * @param int $recursion [Optional] Tracks how often this function has been recursively called to prevent a DOS
     * 
     * @return string
     */
    protected function _generateNonce($recursion=0)
    {
        if($recursion>10){
            throw new \LogicException('Unable to generate unique nonce for this user');
        }
        $this->_nonce = hash_hmac('sha256', uniqid('',true), $this->_salt);
        if(!is_null($this->_connectToDatabase())){
            $check = 'SELECT COUNT(*) FROM `'.$this->_nonceTable.'` WHERE `nonce` = ?';
            $stmt = $this->_connectToDatabase()->prepare($check);
            $stmt->execute();
            if($stmt->fetchColumn()>0){
                $stmt->fetchAll();//clean up
                $this->_generateNonce($recursion+1);
            }
            $stmt->fetchAll();//clean up
            $insert = 'INSERT INTO `'.$this->_nonceTable.'` (`nonce`) VALUES (?)';
            $insertStmt = $this->_connectToDatabase()->prepare($insert);
            $insertStmt->execute(array($this->_nonce));
        }
        return $this->_nonce;
    }
    
    /**
     * Generates the URL to display in the QR code
     * 
     * Separated this out to break out the logic that determines how to append 
     * to the URL. This can be extended to add extra SQRL validation to add
     * requests for user information if that is determined to be valid in the
     * standard.
     * 
     * @return string
     */
    protected function _buildUrl()
    {
        $url = ($this->_secure?'s':'').'qrl://'.$this->_domain.$this->_authPath;
        $currentPathParts = parse_url($url);
        if(!empty($currentPathParts['query'])){
            $pathAppend = '&nut=';
        }
        else{
            $pathAppend = '?nut=';
        }
        return $url.$pathAppend.$this->getNonce().($this->_d>0?'&d='.$this->_d:'');
    }

    public function setAuthenticationPath($path) 
    {
        $this->_authPath = $path;
    }

    public function setKeyDomain($domain) {
        $this->_domain = $domain;
        $slashPos = strpos($domain, '/');
        if($slashPos!==false){
            $this->_d = strlen($domain)-$slashPos;
        }
    }

    public function setSecure($sec) {
        $this->_secure = (bool)$sec;
    }
}
