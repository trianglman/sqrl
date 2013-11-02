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
 * Validates a nonce/public key pair
 * 
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 * 
 * @author johnj
 */
class SqrlValidate implements \trianglman\sqrl\interfaces\SqrlValidate{

    protected $_dsn='';
    
    protected $_dbUserName='';
    
    protected $_dbPass='';
    
    protected $_nonceTable='';
    
    protected $_pubKeyTable='';
    
    protected $_sig='';
    
    protected $_nonce='';
    
    protected $_key='';
    
    protected $_clientVer = 1;
    
    protected $_enforceIP = false;
    
    protected $_db=null;
    
    protected $_validator = null;
    
    
    
    public function loadConfigFromJSON($filePath) {
        if(!file_exists($filePath)){
            throw new \InvalidArgumentException('Configuration file not found');
        }
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if(is_null($decoded)){
            throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');
        }
        if(!empty($decoded->dsn)
                && !empty($decoded->username)){
            $this->configureDatabase($decoded->dsn, $decoded->username, $decoded->password);
            if(!empty($decoded->nonce_table)){
                $this->setNonceTable($decoded->nonce_table);
            }
            if(!empty($decoded->pubkey_table)){
                $this->setPublicKeyTable($decoded->pubkey_table);
            }
        }
        
    }

    public function setCryptoSignature($signature) {
        $this->_sig = $signature;
    }

    public function setNonce($nonce) {
        if(!is_null($this->_connectToDatabase())){
            //verify the nonce exists, otherwise we have to trust it was already done
        }
        $this->_nonce = $nonce;
    }

    public function setPublicKey($publicKey) {
        $this->_key = $publicKey;
    }

    public function storePublicKey() {
        if(is_null($this->_connectToDatabase())){
            throw new \RuntimeException('No database connection has been configured.');
        }
        if(empty($this->_pubKeyTable)){
            throw new \RuntimeException('No public key table has been configured.');
        }
        $checkSql = 'SELECT id FROM `'.$this->_pubKeyTable.'` WHERE `public_key` = ?';
        $checkStmt = $this->_connectToDatabase()->prepare($checkSql);
        $checkStmt->execute(array($this->_key));
        $id = $checkStmt->fetchColumn();
        if($id === false){
            $insertSql = 'INSERT INTO `'.$this->_pubKeyTable.'` (`public_key`) VALUES (?)';
            $insertStmt = $this->_connectToDatabase()->prepare($insertSql);
            $insertStmt->execute(array($this->_key));
            $id = $this->_connectToDatabase()->lastInsertId();
        }
        return $id;
    }

    public function validate() {
        if(empty($this->_sig) || empty($this->_key) || empty($this->_nonce)){
            return false;
        }
    }
    
    public function configureDatabase($dsn,$username,$pass)
    {
        $this->_dsn = $dsn;
        $this->_dbUserName = $username;
        $this->_dbPass = $pass;
    }
    
    public function setDatabaseConnection(\PDO $db)
    {
        $this->_db = $db;
    }
    
    public function setPublicKeyTable($table)
    {
        $this->_pubKeyTable = $table;
    }
    
    public function setNonceTable($table)
    {
        $this->_nonceTable = $table;
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

    public function getPublicKey() {
        if(empty($this->_key)){
            throw new \RuntimeException('No request information has been parsed');
        }
        return $this->_key;
    }

    public function parseSQRLRequest($getParam, $postParam, $headers) {
        if(isset($postParam['sqrlsig'])){
            $this->setCryptoSignature($postParam['sqrlsig']);
        }
        else{
            throw new \IllegalArgumentException('No signature was included in the request');
        }
        if(isset($getParam['nut'])){
            $this->setNonce($getParam['nut']);
        }
        else{
            throw new \IllegalArgumentException('No nonce was included in the request');
        }
        if(isset($getParam['sqrlkey'])){
            $this->_clientVer = $getParam['sqrlkey'];
        }
        else{
            throw new \IllegalArgumentException('No public key was included in the request');
        }
        if(isset($getParam['sqrlver'])){
            $this->_clientVer = $getParam['sqrlver'];
        }
        if(isset($getParam['sqrlopt'])){
            $options = explode(',', $getParam['sqrlopt']);
            if(in_array('enforce', $options)){
                $this->_enforceIP = true;
            }
        }
        
    }

    public function setValidator(\trianglman\sqrl\interfaces\NonceValidator $validator) {
        $this->_validator = $validator;
    }
    
    public function getNonce()
    {
        if(empty($this->_nonce)){
            throw new \RuntimeException('No request information has been parsed');
        }
        return $this->_nonce;
    }

    public function getIdentityLockKey() {
        
    }

    public function getKeyVerifier() {
        
    }

    /**
     * Sets the IP of the user who requested the SQRL image
     * 
     * @param string $ip
     * 
     * @return void
     */
    public function setRequestorIp($ip)
    {
        if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)){throw new \InvalidArgumentException('Not a valid IPv4');}
        $this->_requestorIP = ip2long($ip);
    }

    public function verifyIdentityUnlock() {
        
    }
    
}
