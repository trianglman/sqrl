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
 * An implementation of the SqrlStore interface
 *
 * @author johnj
 */
class SqrlStore implements SqrlStoreInterface
{
    /**
     *
     * @var SqrlConfiguration
     */
    protected $configuration = null;

    /**
     * @var \PDO
     */
    protected $dbConn;

    public function setConfiguration(SqrlConfiguration $config)
    {
        $this->configuration = $config;
    }


    /**
     * Directly set the database connection rather than letting SqrlStore create one
     *
     * @param \PDO $db The database connection
     *
     * @return void
     */
    public function setDatabaseConnection(\PDO $db)
    {
        $this->dbConn = $db;
    }

    /**
     * Gets a connection to the database
     *
     * @return \PDO
     *
     * @throws SqrlException If it fails to connect to the database
     */
    protected function getDbConn()
    {
        if (!is_null($this->dbConn)) {
            return $this->dbConn;
        }
        if ($this->configuration->getDsn() === '') {
            throw new SqrlException('No datbase configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        try {
            $this->dbConn = new \PDO(
                    $this->configuration->getDsn(), 
                    $this->configuration->getUsername(), 
                    $this->configuration->getPassword()
                    );

            return $this->dbConn;
        } catch (\Exception $ex) {
            throw new SqrlException('Database connection error', SqrlException::DATABASE_EXCEPTION, $ex);
        }
    }

    /**
     * Stores a nonce and the related information
     *
     * @param string $nut  The nonce to store
     * @param int    $ip   The IP of the user the nonce is associated with
     * @param int    $type [Optional] The action this nonce is associated with
     *
     * @see SqrlRequestHandler
     *
     * @param string $key  [Optional] The authentication key associated with the nonce action
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeNut($nut, $ip, $type = SqrlRequestHandlerInterface::INITIAL_REQUEST, $key = null)
    {
        if ($this->configuration->getNonceTable() === '') {
            throw new SqrlException('No nonce table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        $columns = array('`nonce`', '`ip`', '`action`');
        $values = array($nut, $ip, $type);
        if (!empty($key)) {
            $columns[] = '`related_public_key`';
            $values[] = $key;
            $placeholders = implode(',', array_fill(0, count($columns), '?'));
        }
        else {
            $columns[] = '`related_public_key`';
            $placeholders = implode(',', array_fill(0, count($columns)-1, '?')).', NULL';
        }
        $sql = 'INSERT INTO `'.$this->configuration->getNonceTable().'` ('.implode(',', $columns).')'
            .' VALUES ('.$placeholders.')';
        $stmt = $this->getDbConn()->prepare($sql);
        $check = false;
        if ($stmt instanceof \PDOStatement) {
            $check = $stmt->execute($values);
        }
        if ($check === false) {
            throw new SqrlException('Failed to insert nonce', SqrlException::DATABASE_EXCEPTION);
        }
    }

    /**
     * Retrieves information about the supplied nut
     *
     * @param string $nut    The nonce to retrieve information on
     * @param array  $values [Optional] an array of data columns to return
     *                       Defaults to all if left null
     *
     * @return array
     *
     * @throws SqrlException If there is a database issue
     */
    public function retrieveNutRecord($nut, $values = null)
    {
        if ($this->configuration->getNonceTable() === '') {
            throw new SqrlException('No nonce table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        if (is_null($values)) {
            $colVals = self::ID | self::CREATED | self::TYPE | self::IP | self::KEY;
        } else {
            $colVals = array_sum($values);
        }
        $columns = array();
        if ($colVals & self::ID) {
            $columns[] = '`id`';
        }
        if ($colVals & self::CREATED) {
            $columns[] = '`created`';
        }
        if ($colVals & self::TYPE) {
            $columns[] = '`action`';
        }
        if ($colVals & self::IP) {
            $columns[] = '`ip`';
        }
        if ($colVals & self::KEY) {
            $columns[] = '`related_public_key`';
        }
        $sql = 'SELECT '.implode(',', $columns).' FROM `'.$this->configuration->getNonceTable()
            .'` WHERE `nonce` = ?';
        $stmt = $this->getDbConn()->prepare($sql);
        $stmt->execute(array($nut));
        $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        if (count($results) == 0) {
            return array();
        } elseif (count($results) == 1) {
            if (count($columns) == 1) {
                return array_shift($results[0]);
            }

            return $results[0];
        } else {
            throw new SqrlException('Error retrieving nonce', SqrlException::DATABASE_EXCEPTION);
        }
    }

    /**
     * Stores a user's authentication key
     *
     * @param string $key The authentication key to store
     *
     * @return int The authentication key's ID
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeAuthenticationKey($key)
    {
        if ($this->configuration->getPubKeyTable() === '') {
            throw new SqrlException('No public key table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        $columns = array('`public_key`');
        $values = array($key);
        $sql = 'INSERT INTO `'.$this->configuration->getPubKeyTable().'` ('.implode(',', $columns).')'
            .' VALUES ('.implode(',', array_fill(0, count($columns), '?')).')';
        $stmt = $this->getDbConn()->prepare($sql);
        $check = false;
        if ($stmt instanceof \PDOStatement) {
            $check = $stmt->execute($values);
        }
        if ($check === false) {
            throw new SqrlException('Failed to insert authentication key', SqrlException::DATABASE_EXCEPTION);
        }

        return $this->getDbConn()->lastInsertId();
    }

    /**
     * Returns information about a supplied authentication key
     *
     * @param string $key    The base64 encoded key to retrieve information on
     * @param array  $values [Optional] an array of data columns to return
     *                       Defaults to all if left null
     *
     * @return array
     *
     * @throws SqrlException If there is a database issue
     */
    public function retrieveAuthenticationRecord($key, $values = null)
    {
        if ($this->configuration->getPubKeyTable() === '') {
            throw new SqrlException('No public key table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        if (is_null($values)) {
            $colVals = self::ID | self::KEY | self::DISABLED | self::SUK | self::VUK;
        } else {
            $colVals = array_sum($values);
        }
        $columns = array();
        if ($colVals & self::ID) {
            $columns[] = '`id`';
        }
        if ($colVals & self::KEY) {
            $columns[] = '`public_key`';
        }
        if ($colVals & self::DISABLED) {
            $columns[] = '`disabled`';
        }
        if ($colVals & self::SUK) {
            $columns[] = '`suk`';
        }
        if ($colVals & self::VUK) {
            $columns[] = '`vuk`';
        }
        $sql = 'SELECT '.implode(',', $columns).' FROM `'.$this->configuration->getPubKeyTable()
            .'` WHERE `public_key` = ?';
        $stmt = $this->getDbConn()->prepare($sql);
        $stmt->execute(array($key));
        $results = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        if (count($results) == 0) {
            return array();
        } elseif (count($results) == 1) {
            if (count($columns) == 1) {
                return array_shift($results[0]);
            }

            return $results[0];
        } else {
            throw new SqrlException('Error retrieving public key', SqrlException::DATABASE_EXCEPTION);
        }
    }

    /**
     * Attaches a server unlock key and verify unlock key to an authentication key
     *
     * @param string $key The authentication key to associate the data with
     * @param string $suk The server unlock key to associate
     * @param string $vuk the verify unlock key to associate
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeIdentityLock($key, $suk, $vuk)
    {
        if ($this->configuration->getPubKeyTable() === '') {
            throw new SqrlException('No public key table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        $columns = array('`suk`', '`vuk`');
        $values = array($suk, $vuk, $key);
        $sql = 'UPDATE `'.$this->configuration->getPubKeyTable().'` SET '.implode(' = ?, ', $columns).' = ? '
            .'WHERE `public_key` = ?';
        $stmt = $this->getDbConn()->prepare($sql);
        $check = false;
        if ($stmt instanceof \PDOStatement) {
            $check = $stmt->execute($values);
        }
        if ($check === false) {
            throw new SqrlException('Failed to insert identity lock information', SqrlException::DATABASE_EXCEPTION);
        }
    }

    /**
     * Locks an authentication key against further use until a successful unlock
     *
     * @param string $key The authentication key to lock
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function lockKey($key)
    {
        if ($this->configuration->getPubKeyTable() === '') {
            throw new SqrlException('No public key table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        $sql = 'UPDATE `'.$this->configuration->getPubKeyTable().'` SET `disabled` = 1 WHERE `public_key` = ?';
        $stmt = $this->getDbConn()->prepare($sql);
        $check = false;
        if ($stmt instanceof \PDOStatement) {
            $check = $stmt->execute(array($key));
        }
        if ($check === false) {
            throw new SqrlException('Failed to insert identity lock information', SqrlException::DATABASE_EXCEPTION);
        }
    }

    /**
     * Updates a user's key information after an identity unlock action
     *
     * Any value set to null will not get replaced. If newKey is updated, any disable
     * locks on the key will be reset
     *
     * @param string $oldKey The key getting new information
     * @param string $newKey [Optional] The authentication key replacing the old key
     * @param string $newSuk [Optional] The replacement server unlock key
     * @param string $newVuk [Optional] The replacement verify unlock key
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function migrateKey($oldKey, $newKey = null, $newSuk = null, $newVuk = null)
    {
        if ($this->configuration->getPubKeyTable() === '') {
            throw new SqrlException('No public key table configured', SqrlException::DATABASE_NOT_CONFIGURED);
        }
        $columns = array();
        $values = array();
        if (!is_null($newKey)) {
            $columns[] = '`public_key`';
            $columns[] = '`disabled`';
            $values[] = $newKey;
            $values[] = 0;
        }
        if (!is_null($newSuk)) {
            $columns[] = '`suk`';
            $values[] = $newSuk;
        }
        if (!is_null($newVuk)) {
            $columns[] = '`vuk`';
            $values[] = $newVuk;
        }
        $values[] = $oldKey;
        $sql = 'UPDATE `'.$this->configuration->getPubKeyTable().'` SET '.implode(' = ?, ', $columns).' = ? '
            .'WHERE `public_key` = ?';
        $stmt = $this->getDbConn()->prepare($sql);
        $check = false;
        if ($stmt instanceof \PDOStatement) {
            $check = $stmt->execute($values);
        }
        if ($check === false) {
            throw new SqrlException('Failed to migrate key information', SqrlException::DATABASE_EXCEPTION);
        }
    }
}
