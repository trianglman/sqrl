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
namespace Trianglman\Sqrl\Tests;

use PHPUnit\Framework\TestCase;
use Trianglman\Sqrl\SqrlStoreInterface;
use Trianglman\Sqrl\SqrlValidateInterface;
use Trianglman\Sqrl\Traits\Base64Url;

/**
 * Unit tests for the SqrlRequestHandler class
 *
 * @author johnj
 */
class SqrlRequestHandlerTest extends TestCase
{
    use Base64Url;

    /**
     * @var RequestHandlerScenario
     */
    protected $scenario;

    public function setup()
    {
        $this->scenario = new RequestHandlerScenario($this);
    }

    /**
     * tests the server responding to a cmd=query when the idk is known
     *
     * this will generally be the first step of most authentication, so the server value
     * will be the (s)qrl:// URL
     */
    public function testRespondsToQueryKnownIdentityKey()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(5);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the idk is known and the IPs do not match
     *
     * this will be both a MITM check and a common case when using a separate device
     * to authenticate so no temporary or permantent failure should be returned
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryKnownIdentityKeyIPMismatch()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.6');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(1);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query with the idk is not known
     *
     * this is in the instance where the server does not allow previously unknown
     * identities to authenticate to the server
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryUnknownIdentityKeyHardFailure()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
            $this->scenario->serverAcceptsNewAccounts(false);
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validNewIdentityKey']);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0x54);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query with the idk is not known
     *
     * this is in the instance where the server will allow the authentication to proceed
     * generally this will be on a create account or associate account with SQRL page
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryUnknownIdentityKeyAuthenticationProceeds()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
            $this->scenario->serverAcceptsNewAccounts();
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validNewIdentityKey']);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(4);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=ident with a known idk
     *
     * this should connect the session with the identity key, authorizing the
     * transaction (log-in, purchase authentication, etc.)
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToIdent()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent(['ver'=>'1', 'nut'=>'newNut', 'tif'=>'5', 'qry'=>'sqrl?nut=newNut']);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validIdentityKey');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'ident', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(5);
            $this->scenario->expectNewNut('newerNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=ident with an unknown idk
     *
     * this should connect the session with the identity key, authorizing the
     * transaction (generally a log in or account creation/association) and that
     * the suk and vuk have been stored
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToIdentWhenCreatingAccount()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent(['ver'=>'1', 'nut'=>'newNut', 'tif'=>'4', 'qry'=>'sqrl?nut=newNut']);
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validNewIdentityKey');
            $this->scenario->nutConnectedToIp('192.168.0.5');
            $this->scenario->serverAcceptsNewAccounts();
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validNewIdentityKey',
                'suk'=>'validSUK',
                'vuk'=>'validVUK'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(5);
            $this->scenario->expectNewNut('newerNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin();
            $this->scenario->expectRegistration('validNewIdentityKey', 'validSUK', 'validVUK');
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the nut has expired
     *
     * this should cause the client to sign the response with a new query in order
     * to continue authentication
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryExpiredNutSoftFailure()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::EXPIRED_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0x60);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the nut has expired, is unknown,
     * or in some other way is invalid, causing a hard failure
     *
     * this will end the authentication transaction
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryBadNutHardFailure()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::INVALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC0);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the nut has expired, is unknown,
     * or in some other way is invalid, causing a hard failure
     *
     * this will end the authentication transaction
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryNutKeyMismatch()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('mismatchIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::KEY_MISMATCH, 'other idk');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'mismatchIdentityKey']);
            $this->scenario->clientSendsSignature('mismatchIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0x1C0);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=lock
     *
     * this will lock the user's identity key against further authentication
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToLock()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent(['ver'=>'1', 'nut'=>'newNut', 'tif'=>'5', 'qry'=>'sqrl?nut=newNut']);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validIdentityKey');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'lock', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xD);
            $this->scenario->expectNewNut('newerNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLock('validIdentityKey');
            $this->scenario->expectLogout('newNut');
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the account has previously been locked
     *
     * this should return the suk value previously supplied by the user in order
     * for the client to complete the identity unlock process
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryWhenAccountLocked()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_LOCKED);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->serverKnowsSuk('validIdentityKey', 'validSUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xD);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectAdditionalResponseParams(['suk'=>$this->base64UrlEncode('validSUK')]);
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=ident when the account has previously been locked
     * when the user is supplying the Identity Lock credentials
     *
     * this will validate both the identity and the vuk/urs process was completed then
     * unlock the idk for future authentication
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToUnlockRequest()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'D',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_LOCKED);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validIdentityKey',
                'suk'=>'validSUK',
                'vuk'=>'validVUK'
            ]);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientSendsSignature('validVUK', 'valid urs', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(5);
            $this->scenario->expectNewNut('newerNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectUnlock('validIdentityKey');
            $this->scenario->expectLogin();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=query when the user is supplying a pidk
     * in order to update their account.
     *
     * This should return the user's suk value in order to do the full identity unlock
     * process and update the records
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToQueryDuringIdentityUpdate()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->serverKnowsSuk('validIdentityKey', 'validSUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'query',
                'idk'=>'validNewIdentityKey',
                'pidk'=>'validIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid new key signature', true);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid old key signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(6);
            $this->scenario->expectNewNut('newNut');
            $this->scenario->expectAdditionalResponseParams(['suk'=>$this->base64UrlEncode('validSUK')]);
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * tests the server responding to a cmd=setkey when the user is supplying a pidk
     * in order to update their account.
     *
     * This should cause the server to replace the previous idk with the newly supplied idk
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToIdentDuringIdentityUpdate()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'6',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validNewIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validNewIdentityKey',
                'suk'=>'newSUK',
                'vuk'=>'newVUK',
                'pidk'=>'validIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid new key signature', true);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid old key signature', true);
            $this->scenario->clientSendsSignature('validVUK', 'valid old vuk signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(7);
            $this->scenario->expectNewNut('newerNut');
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin();
            $this->scenario->expectIdentityKeyUpdate('validIdentityKey', 'validNewIdentityKey', 'newSUK', 'newVUK');
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client fails
     * to send all the information needed to make a basic request.
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesIncompleteRequest()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC0);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client fails
     * to send all the information needed to make a basic request.
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWithInvalidClient()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['no'=>'thing', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC0);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client
     * sends a server value that doesn't match what the server sent
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWhereServerValueDoesntValidate()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsServerParam('sqrl://example.com/sqrl?nut=randomnut&fuzz=test');
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC0);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid(false);
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client
     * sends an invalid IDS signature
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWithInvalidIDS()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest(['ver'=>'1', 'cmd'=>'query', 'idk'=>'validIdentityKey']);
            $this->scenario->clientSendsSignature('validIdentityKey', 'invalid signature', false);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client
     * sends an invalid URS signature
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWithInvalidURS()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'D',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_LOCKED);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validIdentityKey',
                'suk'=>'validSUK',
                'vuk'=>'validVUK'
            ]);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientSendsSignature('validVUK', 'invalid urs', false);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin(false);
            $this->scenario->expectNoUnlock();
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client
     * sends an invalid URS signature
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWithInvalidURSDuringIDUpdate()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'6',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validNewIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validNewIdentityKey',
                'suk'=>'newSUK',
                'vuk'=>'newVUK',
                'pidk'=>'validIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid new key signature', true);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid old key signature', true);
            $this->scenario->clientSendsSignature('validVUK', 'invalid old vuk signature', false);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin(false);
            $this->scenario->expectNoUnlock();
            $this->scenario->checkResponse();
        });
    }

    /**
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToUnlockRequestMismathedVUK()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'D',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_LOCKED);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validIdentityKey',
                'suk'=>'validSUK',
                'vuk'=>'otherVUK'
            ]);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid signature', true);
            $this->scenario->clientSendsSignature('otherVUK', 'valid urs', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->expectNoUnlock();
            $this->scenario->expectLogin(false);
            $this->scenario->checkResponse();
        });
    }

    /**
     * Tests that the server responds with a client failure flag if the client
     * sends an invalid pIDS signature
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testHandlesRequestWithInvalidPIDS()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent('sqrl://example.com/sqrl?nut=randomnut');
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('randomnut', SqrlValidateInterface::VALID_NUT);
            $this->scenario->serverKnowsSuk('validIdentityKey', 'validSUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('randomnut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'query',
                'idk'=>'validNewIdentityKey',
                'pidk'=>'validIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid new key signature', true);
            $this->scenario->clientSendsSignature('validIdentityKey', 'invalid old key signature', false);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->checkResponse();
        });
    }

    /**
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToIdentDuringIdentityUpdateMissingNewSUK()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent([
                'ver'=>'1',
                'nut'=>'newNut',
                'tif'=>'6',
                'qry'=>'sqrl?nut=newNut',
                'suk'=>$this->base64UrlEncode('validSUK')
            ]);
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsKey('validIdentityKey', SqrlStoreInterface::IDENTITY_ACTIVE);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validNewIdentityKey');
            $this->scenario->serverKnowsVuk('validIdentityKey', 'validVUK');
            $this->scenario->nutConnectedToIp('192.168.0.5');
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validNewIdentityKey',
                'vuk'=>'newVUK',
                'pidk'=>'validIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid new key signature', true);
            $this->scenario->clientSendsSignature('validIdentityKey', 'valid old key signature', true);
            $this->scenario->clientSendsSignature('validVUK', 'valid old vuk signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin(false);
            $this->scenario->expectNoIdentityKeyUpdate();
            $this->scenario->checkResponse();
        });
    }

    /**
     * Test that the server returns a failure when the user attempts to create an account
     * without all required information (suk and vuk)
     * @throws \Trianglman\Sqrl\SqrlException
     */
    public function testRespondsToIdentIncompleteAccountInformation()
    {
        $this->scenario->given(function () {
            $this->scenario->serverLastSent(['ver'=>'1', 'nut'=>'newNut', 'tif'=>'4', 'qry'=>'sqrl?nut=newNut']);
            $this->scenario->serverKnowsKey('validNewIdentityKey', SqrlStoreInterface::IDENTITY_UNKNOWN);
            $this->scenario->serverKnowsNut('newNut', SqrlValidateInterface::VALID_NUT, 'validNewIdentityKey');
            $this->scenario->nutConnectedToIp('192.168.0.5');
            $this->scenario->serverAcceptsNewAccounts();
        })->when(function () {
            $this->scenario->clientSendsNut('newNut');
            $this->scenario->clientSendsOriginalServer();
            $this->scenario->clientSendsRequest([
                'ver'=>'1',
                'cmd'=>'ident',
                'idk'=>'validNewIdentityKey'
            ]);
            $this->scenario->clientSendsSignature('validNewIdentityKey', 'valid signature', true);
            $this->scenario->clientRequestsFromIp('192.168.0.5');
            $this->scenario->clientRequestIsSecure();
        })->then(function () {
            $this->scenario->expectTif(0xC4);
            $this->scenario->expectFailedNut();
            $this->scenario->expectServerParamValid();
            $this->scenario->expectLogin(false);
            $this->scenario->expectNoRegistration();
            $this->scenario->checkResponse();
        });
    }
}
