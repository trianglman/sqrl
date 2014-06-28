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
 * A handler to process the authentication of SQRL clients
 *
 * This class will process a request, send it to the validator, then depending on
 * the type of request, send a success message, send an error message, or send a
 * request for more information (e.g. initiate the second loop to create a new user)
 *
 * @author johnj
 */
interface SqrlRequestHandlerInterface
{
    /**
     * A basic SQRL authentication request, no special parameters
     *
     * @const
     * @var int
     */
    const INITIAL_REQUEST = 1;

    /**
     * A second loop response from a user who's public key was not recognized
     *
     * @const
     * @var int
     */
    const FOLLOW_UP_REQUEST = 2;

    //TIF Codes
    /**
     * 	When set, this bit indicates that the web server has 
     * found an identity association for the user based upon the default (current) 
     * identity credentials supplied by the client: the IDentity Key (IDK) and 
     * the IDentity Signature (IDS).
     *
     * @const
     * @var int
     */
    const ID_MATCH = 0x01;

    /**
     * When set, this bit indicates that the web server has found an identity 
     * association for the user based upon the previous identity credentials 
     * supplied by the client: the previous IDentity Key (pIDK) and the previous 
     * IDentity Signature (pIDS).
     *
     * @const
     * @var int
     */
    const PREVIOUS_ID_MATCH = 0x02;

    /**
     * When set, this bit indicates that the IP address of the entity which 
     * requested the initial logon web page containing the SQRL link URL (and 
     * probably encoded into the SQRL link URL's “nut”) is the same IP address 
     * from which the SQRL client's query was received for this reply.
     *
     * @const
     * @var int
     */
    const IP_MATCH = 0x04;

    /**
     * When set, the account associated with the identified user is enabled for 
     * SQRL-initiated login. This is the normal default case, so this bit will 
     * be set unless a “disable” command (see below) has most recently been 
     * received from the identified user.
     *
     * @const
     * @var int
     */
    const SQRL_ENABLED = 0x08;

    /**
     * When set, the account associated with the identified user has one or more 
     * active logged in sessions. In the typical case, this bit would be cleared 
     * in the first status-collection client query and set in the reply to a 
     * subsequent successful query containing any of the login commands. If it 
     * was set before the receipt of a successful logout command, it would then 
     * be reset.
     *
     * @const
     * @var int
     */
    const USER_LOGGED_IN = 0x10;

    /**
     * When set, the website is indicating that it supports SQRL-initiated, 
     * anonymous account creation. If the SQRL client received a reply with this 
     * bit set, and the user was not already known to the server, and the user 
     * affirmatively indicated that they wished to create an account using their 
     * SQRL credentials, the client could then issue a “create” command, 
     * probably accompanied with one of the login commands, to create an account 
     * and login the user.
     *
     * @const
     * @var int
     */
    const ACCOUNT_CREATION_ALLOWED = 0x20;

    /**
     * When set, this bit indicates that the web server had an unspecified 
     * problem fully processing the client's query. In any such case, no change 
     * will be made to the user's account status. All SQRL server-side actions 
     * are atomic. This means that either everything succeeds or nothing is 
     * changed. This is important since clients can request multiple updates and 
     * changes at once.
     *
     * @const
     * @var int
     */
    const COMMAND_FAILED = 0x40;

    /**
     * This bit only has meaning when the preceding “Command failed” bit is set. 
     * When both bits are set, the web server in indicating that the reason for 
     * the command failure indicated by that bit was some failure in the SQRL 
     * protocol sent by the client and not a problem at its end with completing 
     * the requested command(s). Since the SQRL client will have previously 
     * obtained everything from the client which is necessary to formulate valid 
     * and legal command queries, this bit should never be expected to be set. 
     * So it would typically indicate a logical problem with either the web 
     * server of the client, a transmission error, or the presence of third-party 
     * tampering.
     *
     * @const
     * @var int
     */
    const SQRL_SERVER_FAILURE = 0x80;

    /**
     * Initializes the Request Handler
     *
     * @param SqrlValidateInterface $val   Sets the validator that will check the response
     * @param SqrlStoreInterface    $store [Optional] Sets storage for submitted authorization keys
     * @param SqrlGenerateInterface $gen   [Optional] Sets the nonce generator for loop two
     *
     * @return SqrlRequestHandlerInterface
     */
    public function __construct(
        SqrlConfiguration $config,
        SqrlValidateInterface $val,
        SqrlStoreInterface $store = null,
        SqrlGenerateInterface $gen = null
    );

    /**
     * Parses a user request
     *
     * This will determine what type of request is being performed and set values
     * up for use in validation and creating the response.
     *
     * @param array $get    The user's GET request
     * @param array $post   The user's POST body
     * @param array $server Server level variables (the _SERVER array)
     *
     * @return void
     */
    public function parseRequest($get, $post, $server);

    /**
     * Gets the type of request the user made
     *
     * The return value will be one of the predefined constants
     *
     * @return int
     */
    public function getRequestType();

    /**
     * Gets the text message to be returned to the SQRL client
     *
     * @return string
     */
    public function getResponseMessage();

    /**
     * Gets the numeric HTTP code to return to the SQRL client
     *
     * Currently the spec only uses the 200 code and any error message is in the
     * test message response
     *
     * @return int
     */
    public function getResponseCode();

    /**
     * A helper function to send the response message and code to the SQRL client
     *
     * @return void
     */
    public function sendResponse();
}
