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

use Trianglman\Sqrl\SqrlException;

/**
 * An object to handle storing and retrieving SQRL data
 *
 * @author johnj
 */
interface SqrlStoreInterface
{
    /**
     * The table ID column
     */
    const ID = 1;

    /**
     * The nonce table's created column
     */
    const CREATED = 2;

    /**
     * The nonce table's IP column
     */
    const IP = 4;

    /**
     * The nonce table's action column
     */
    const TYPE = 8;

    /**
     * The authentication key column in both the nonce table and the public key table
     */
    const KEY = 16;

    /**
     * Whether the authentication key has been disabled, in the public key table
     */
    CONST DISABLED = 128;

    /**
     * The server unlock key in the public key table
     */
    const SUK = 32;

    /**
     * The verify unlock key in the public key table
     */
    const VUK = 64;
    
    /**
     * Whether a nonce has been verified
     */
    const VERIFIED = 256;

    /**
     * Directly set the database connection rather than letting SqrlStore create one
     *
     * @param \PDO $db The database connection
     *
     * @return void
     */
    public function setDatabaseConnection(\PDO $db);

    /**
     * Stores a nonce and the related information
     *
     * @param string $nut  The nonce to store
     * @param int    $ip   The IP of the user the nonce is associated with
     * @param int    $type [Optional] The action this nonce is associated with
     *
     * @see SqrlRequestHandlerInterface
     *
     * @param string $key  [Optional] The authentication key associated with the nonce action
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeNut($nut, $ip, $type = SqrlRequestHandlerInterface::INITIAL_REQUEST, $key = null);

    /**
     * Retrieves information about the supplied nut
     *
     * @param string $nut    The nonce to retrieve information on
     * @param array  $values [Optional] an array of data columns to return
     *                       Defaults to all if left null
     *
     * @return array
     */
    public function retrieveNutRecord($nut, $values = null);

    /**
     * Stores a user's authentication key
     *
     * @param string $key The authentication key to store
     *
     * @return int The authentication key's ID
     *
     * @throws SqrlException If there is a database issue
     */
    public function storeAuthenticationKey($key);

    /**
     * Returns information about a supplied authentication key
     *
     * @param string $key    The key to retrieve information on
     * @param array  $values [Optional] an array of data columns to return
     *                       Defaults to all if left null
     *
     * @return array
     */
    public function retrieveAuthenticationRecord($key, $values = null);

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
    public function storeIdentityLock($key, $suk, $vuk);

    /**
     * Locks an authentication key against further use until a successful unlock
     *
     * @param string $key The authentication key to lock
     *
     * @return void
     *
     * @throws SqrlException If there is a database issue
     */
    public function lockKey($key);

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
    public function migrateKey($oldKey, $newKey = null, $newSuk = null, $newVuk = null);
}
