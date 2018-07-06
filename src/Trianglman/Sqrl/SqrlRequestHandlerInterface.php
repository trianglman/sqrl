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
     * When set, the account associated with the identified user is disabled for 
     * SQRL-initiated authentication without the additional Rescue Code-derived 
     * unlock request signature (urs). If the 'query' command returns with this 
     * tif bit set, and the SQRL client does not already have the Rescue Code in 
     * RAM, it should inform its user that they will need to supply their 
     * identity' Rescue Code in order to proceed with the authentication 
     * operation.
     *
     * @const
     * @var int
     */
    const SQRL_DISABLED = 0x08;

    /**
     * This bit indicates that the client requested one or more standard SQRL 
     * functions (through command verbs) that the server does not currently 
     * support. The client will likely need to advise its user that whatever 
     * they were trying to do is not possible at the target website. The SQRL 
     * server will fail this query, thus also setting the “40h” Command Failed 
     * bit.
     *
     * @const
     * @var int
     */
    const FUNCTION_NOT_SUPPORTED = 0x10;

    /**
     * The server replies with this bit set to indicate that the client's 
     * signature(s) are correct, but something about the client's query 
     * prevented the command from completing. This is the server's way of 
     * instructing the client to retry and reissue the immediately previous 
     * command using the fresh ‘nut=’ crypto material and ‘qry=’ url the server 
     * has also just returned in its reply. Although we don't want to overly 
     * restrict the specification of this error, the trouble is almost certainly 
     * static, expired, or previously used nut= or qry= data. Thus, reissuing 
     * the previous command under the newly supplied server parameters would be 
     * expected to succeed. The “0x40” “Command failed” bit (shown next) will 
     * also be set since the client's command will not have been processed.
     *
     * @const
     * @var int
     */
    const TRANSIENT_ERROR = 0x20;

    /**
     * When set, this bit indicates that the web server had a problem 
     * successfully processing the client's query. In any such case, no change 
     * will be made to the user's account status. All SQRL server-side actions 
     * are atomic. This means that either everything succeeds or nothing is 
     * changed. This is important since clients can request multiple updates and 
     * changes at once.
     * 
     * If this bit is set without the 80h bit set (see below) the trouble was 
     * not with the client's provided data, protocol, etc. but with some other 
     * aspect of completing the client's request. With the exception of the 
     * following “Client failure” status bit, the SQRL semantics do not attempt 
     * to enumerate every conceivable web server failure reason. The web server 
     * is free to use the “ask” command without arguments to explain the problem 
     * to the client's user.
     *
     * @const
     * @var int
     */
    const COMMAND_FAILED = 0x40;

    /**
     * This bit is set by the server when some aspect of the client's submitted 
     * query ‑ other than expired but otherwise valid transaction state 
     * information ‑ was incorrect and prevented the server from understanding 
     * and/or completing the requested action. This could be the result of a 
     * communications error, a mistake in the client's SQRL protocol, a 
     * signature that doesn't verify, or required signatures for the requested
     * actions which are not present. And more specifically, this is NOT an 
     * error that the server knows would likely be fixed by having the client 
     * silently reissue it previous command . . . although that might still be 
     * the first recouse for the client. This is NOT an error Since any such 
     * client failure will also result in a failure of the command, the 40h bit 
     * will also be set.
     *
     * @const
     * @var int
     */
    const CLIENT_FAILURE = 0x80;
    
    /**
     * This bit is set by the server when a SQRL identity which may be associated 
     * with the query nut does not match the SQRL ID used to submit the query. 
     * If the server is maintaining session state, such as a logged on session, 
     * it may generate SQRL query nuts associated with that logged-on session's 
     * SQRL identity. If it then receives a SQRL query using that nut, but issued 
     * with a different SQRL identity, it should fail the command (with the 0x40 
     * bit) and also return this 0x100 error bit so that the client may inform 
     * its user that the wrong SQRL identity was used with a nut that was 
     * already associated with a different identity.
     * 
     * @const
     * @var int
     */
    const BAD_ID_ASSOCIATION = 0x100;

    /**
     * Initializes the Request Handler
     *
     * @param SqrlConfiguration $config
     * @param SqrlValidateInterface $val Sets the validator that will check the response
     * @param SqrlStoreInterface $store [Optional] Sets storage for submitted authorization keys
     * @param SqrlGenerateInterface $gen [Optional] Sets the nonce generator for loop two
     *
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
     * Gets the text message to be returned to the SQRL client
     *
     * @return string
     */
    public function getResponseMessage();

    /**
     * Gets the numeric HTTP code to return to the SQRL client
     *
     * Currently the spec only uses the 200 code with the TIF containing a protocol status code
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
