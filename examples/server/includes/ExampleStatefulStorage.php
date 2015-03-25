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
    namespace sqrlexample;
    use Trianglman\Sqrl\SqrlStoreInterface;

/**
 * An example implementation of the stateful SqrlStorageInterface
 *
 * @author johnj
 */
class ExampleStatefulStorage implements SqrlStoreInterface
{
    /**
     *
     * @var \PDO
     */
    private $conn = null;
    
    private $session = array();
    
    private $reqIp = '';
    
    public function __construct(\PDO $conn, $reqIp, &$session)
    {
        $this->session = &$session;
        $this->conn = $conn;
        $this->reqIp = $reqIp;
    }
    
    public function checkIdentityKey($key) 
    {
        $sql = "SELECT disabled FROM sqrl_pubkey WHERE public_key = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key));
        $result = $stmt->fetchColumn();
        if ($result === false) {
            return self::IDENTITY_UNKNOWN;
        } else {
            return $result === '1'?self::IDENTITY_LOCKED:self::IDENTITY_ACTIVE;
        }
    }

    public function createIdentity($key, $suk, $vuk) 
    {
        $sql = "INSERT INTO sqrl_pubkey (public_key,vuk,suk) VALUES (?,?,?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key,$suk,$vuk));
    }

    public function endSession($requestNut) 
    {
        $sql = 'UPDATE sqrl_nonce SET kill_session = 1 WHERE nonce = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($requestNut));
    }

    public function getIdentitySUK($key) 
    {
        $sql = 'SELECT suk FROM sqrl_pubkey WHERE public_key = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key));
        return $stmt->fetchColumn();
    }

    public function getIdentityVUK($key) 
    {
        $sql = 'SELECT vuk FROM sqrl_pubkey WHERE public_key = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key));
        return $stmt->fetchColumn();
    }

    public function getNutDetails($nut) 
    {
        $sql = 'SELECT action,related_public_key,orig_nonce,created,ip '
                . 'FROM sqrl_nonce WHERE nonce = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($nut));
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        if (empty($result)) {
            return null;
        } else {
            return array (
                'tif'=> $result['action'],
                'originalKey'=> $result['related_public_key'],
                'originalNut'=> $result['orig_nonce'],
                'createdDate'=> new \DateTime($result['created']),
                'nutIP'=> long2ip($result['ip'])
            );
        }
    }

    public function getSessionNonce() 
    {
        return isset($this->session['sqrl_nut'])?$this->session['sqrl_nut']:'';
    }

    public function lockIdentityKey($key) 
    {
        $sql = 'UPDATE sqrl_pubkey SET disabled = 1 WHERE public_key = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key));
    }

    public function logSessionIn($requestNut) 
    {
        $sql = 'UPDATE sqrl_nonce SET verified = 1 WHERE nonce = ? OR orig_nonce = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($requestNut,$requestNut));
    }

    public function storeNonce($nonce, $action, $key = '', $previousNonce = '') 
    {
        $sql = 'INSERT INTO sqrl_nonce (nonce,ip,action,related_public_key) '
                . 'VALUES (?,?,?,?)';
        $longIp = ip2long($this->reqIp);
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($nonce,$longIp,$action,$key));
        if (empty($previousNonce)) {
            if (empty($this->session['sqrl_nut'])) {
                $this->session['sqrl_nut'] = $nonce;
            }
        }
    }

    public function unlockIdentityKey($key) 
    {
        $sql = 'UPDATE sqrl_pubkey SET disabled = 0 WHERE public_key = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($key));
    }

    public function updateIdentityKey($oldKey, $newKey, $newSuk, $newVuk) 
    {
        $sql = 'UPDATE sqrl_pubkey SET public_key = ?, vuk = ?, suk = ? WHERE public_key = ?';
        $stmt = $this->conn->prepare($sql);
        $stmt->execute(array($newKey, $newSuk, $newVuk, $oldKey));
    }
}

/**
 * Database schema for this file:
 * 
 * CREATE TABLE `sqrl_nonce` (
 *      `id` INT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
 *      `nonce` CHAR(64) NOT NULL,
 *      `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *      `ip` INT UNSIGNED NOT NULL,
 *      `action` INT UNSIGNED NOT NULL,
 *      `related_public_key` CHAR(44) DEFAULT NULL,
 *      `verified` TINYINT NOT NULL DEFAULT 0,
 *      `kill_session` TINYINT NOT NULL DEFAULT 0,
 *      `orig_nonce` CHAR(64) DEFAULT NULL,
 *      UNIQUE (`nonce`)
 * );
 * 
 * CREATE TABLE `sqrl_pubkey` (
 *      `id` INT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
 *      `public_key` CHAR(44) NOT NULL,
 *      `vuk` CHAR(44) NOT NULL,
 *      `suk` CHAR(44) NOT NULL,
 *      `disabled` TINYINT NOT NULL DEFAULT 0,
 *      UNIQUE (`public_key`)
 * );
 */