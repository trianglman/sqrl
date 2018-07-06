<?php
namespace Trianglman\Sqrl\Tests;

use PHPUnit\Framework\TestCase;
use Trianglman\Sqrl\SqrlConfiguration;
use Trianglman\Sqrl\SqrlException;
use Trianglman\Sqrl\SqrlGenerateInterface;
use Trianglman\Sqrl\SqrlRequestHandler;
use Trianglman\Sqrl\SqrlStoreInterface;
use Trianglman\Sqrl\SqrlValidateInterface;
use Trianglman\Sqrl\Traits\Base64Url;

class RequestHandlerScenario extends TestScenario
{
    use Base64Url;
    protected $serverOriginalReply;
    protected $serverKeys = [];
    protected $nut = [];
    protected $clientServerParam;
    protected $clientNut;
    protected $clientSignatures = [];
    protected $expectedTif;
    protected $expectedNut;
    protected $clientRequest = [];
    protected $serverParamValid;
    protected $originalIp;
    protected $clientIp;
    protected $clientSecure;
    protected $additionalExpectedResponseParams = [];
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject |SqrlGenerateInterface
     */
    protected $generator;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject |SqrlValidateInterface
     */
    protected $validator;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject | SqrlStoreInterface
     */
    protected $storage;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject | SqrlConfiguration
     */
    protected $config;
    protected $handler;

    public function __construct(TestCase $test)
    {
        parent::__construct($test);
        $this->generator = $this->test->getMockBuilder(SqrlGenerateInterface::class)->getMock();
        $this->validator = $this->test->getMockBuilder(SqrlValidateInterface::class)->getMock();
        $this->storage = $this->test->getMockBuilder(SqrlStoreInterface::class)->getMock();

        $this->config = $this->test->getMockBuilder(SqrlConfiguration::class)->getMock();
        $this->config->expects($this->test->any())
            ->method('getAcceptedVersions')
            ->will($this->test->returnValue(array('1')));
        $this->handler = new SqrlRequestHandler($this->config,$this->validator,$this->storage,$this->generator);
    }

    /* GIVENS */

    /**
     * Sets the response the server last sent
     *
     * This can be formatted as either a URL string if the server's last response was the initial SQRL QR
     * or an array of key=>value parameters that were the last reply in an authentication chain
     *
     * @param array|string $originalReply
     */
    public function serverLastSent($originalReply): void
    {
        $this->serverOriginalReply = $originalReply;
    }

    /**
     * Sets what the server knows about a key
     *
     * @param string $key
     * @param int $keyStatus Must be a SqrlStoreInterface::IDENTITY_* value
     */
    public function serverKnowsKey(string $key, int $keyStatus)
    {
        $this->serverKeys[$key]=$keyStatus;
    }

    /**
     * Sets what the server knows about a nut
     * @param string $nut
     * @param int $nutStatus Must be a SqrlValidateInterface constant
     * @param null|string $associatedKey
     */
    public function serverKnowsNut(string $nut, int $nutStatus, ?string $associatedKey = null)
    {
        $this->nut = ['nut'=>$nut, 'status'=>$nutStatus, 'oldKey'=>$associatedKey];
    }

    /**
     * Sets what IP the server thinks the nut is connected to
     *
     * @param string $ip
     */
    public function nutConnectedToIp(string $ip)
    {
        $this->originalIp = $ip;
    }

    /**
     * Sets whether the server has been configured to accept new account creations
     * @param bool $accept
     */
    public function serverAcceptsNewAccounts(bool $accept = true): void
    {
        $this->config->expects($this->test->any())->method('getAnonAllowed')->will($this->test->returnValue($accept));
    }

    public function serverKnowsSuk(string $idk, string $suk)
    {
        $this->storage->expects($this->test->any())
            ->method('getIdentitySUK')
            ->with($this->test->equalTo($idk))
            ->will($this->test->returnValue($suk));
    }

    public function serverKnowsVuk(string $idk, string $vuk)
    {
        $this->storage->expects($this->test->any())
            ->method('getIdentityVUK')
            ->with($this->test->equalTo($idk))
            ->will($this->test->returnValue($vuk));
    }

    /* WHENS */
    /**
     * Sets what nut the client sends in the GET parameters
     *
     * @param string $nut
     */
    public function clientSendsNut(string $nut)
    {
        $this->clientNut = $nut;
    }

    /**
     * Says that the client sent back the same server value the server last sent
     */
    public function clientSendsOriginalServer()
    {
        $this->clientServerParam = $this->serverOriginalReply;
    }

    /**
     * Sets what the client says the server last sent
     *
     * @param string $server
     */
    public function clientSendsServerParam(string $server)
    {
        $this->clientServerParam = $server;
    }

    /**
     * Sets the parameters the client is sending in their request
     *
     * @param array $requestParams
     */
    public function clientSendsRequest(array $requestParams)
    {
        $this->clientRequest = $requestParams;
    }

    /**
     * Sets a signature the client sends
     *
     * @param string $key Should match a key in the client request
     * @param string $signature
     * @param bool $valid
     */
    public function clientSendsSignature(string $key, string $signature, bool $valid = true)
    {
        $this->clientSignatures[$key] = ['sig'=>$signature, 'valid'=>$valid];
    }

    /**
     * Sets what IP the client request is from
     *
     * @param string $ip
     */
    public function clientRequestsFromIp(string $ip)
    {
        $this->clientIp = $ip;
    }

    public function clientRequestIsSecure(bool $secure = true)
    {
        $this->clientSecure = $secure;
    }

    /* THENS */

    /**
     * Set the TIF the server should respond with
     *
     * @param int $tif
     */
    public function expectTif(int $tif)
    {
        $this->expectedTif = $tif;
    }

    /**
     * Set the new nut the server should respond with
     *
     * @param string $nut
     */
    public function expectNewNut(string $nut)
    {
        $this->expectedNut = $nut;
    }

    /**
     * Set the new nut the server should respond with to the fail state nut
     */
    public function expectFailedNut()
    {
        $this->expectedNut = 'failnut';
    }

    /**
     * Sets whether the validator should say the server parameter is valid
     *
     * @param bool $isValid
     */
    public function expectServerParamValid(bool $isValid = true)
    {
        $this->serverParamValid = $isValid;
    }

    /**
     * Sets additional parameters that should be expeccted in the server's response (ask, sin, etc.)
     * @param array $params
     */
    public function expectAdditionalResponseParams(array $params)
    {
        $this->additionalExpectedResponseParams = $params;
    }

    /**
     * Finalizes configuration and checks that the server response matches the expected response
     *
     * @throws SqrlException
     */
    public function checkResponse()
    {
        $this->setUpValidator();
        $this->setUpStorage();
        $this->setUpGenerator();
        $this->sendClientRequest();
        $this->validateResponse();
    }

    /* Helpers */

    protected function convertServerReplyToString(): string
    {
        if (is_string($this->serverOriginalReply)) {
            return $this->serverOriginalReply;
        }
        return $this->paramArrayToSqrlString($this->serverOriginalReply);
    }

    protected function paramArrayToSqrlString(array $params): string
    {
        $combinedData = array_map(function ($key, $val) {
            return $key.'='.$val;
        }, array_keys($params), $params);
        return implode("\r\n", $combinedData);
    }

    private function getClientString()
    {
        $encodedFields = ['idk', 'pidk', 'suk', 'vuk'];
        $result = [];
        foreach ($this->clientRequest as $key=>$value) {
            if (in_array($key, $encodedFields)) {
                $result[$key] = $this->base64UrlEncode($value);
            } else {
                $result[$key] = $value;
            }
        }
        return $this->paramArrayToSqrlString($result);
    }

    protected function setUpValidator(): void
    {
        $this->validator->expects($this->test->any())
            ->method('validateServer')
            ->with(
                $this->test->equalTo($this->clientServerParam),
                $this->test->equalTo($this->clientNut),
                $this->test->equalTo($this->clientSecure)
            )
            ->will($this->test->returnValue($this->serverParamValid));

        if (!empty($this->nut)) {
            $this->validator->expects($this->test->any())
                ->method('validateNut')
                ->with($this->test->equalTo($this->clientNut), $this->test->equalTo($this->getClientKey('idk')))
                ->will($this->test->returnValue($this->nut['status']));
        }

        $request = $this->base64UrlEncode($this->getClientString())
            .$this->base64UrlEncode($this->convertServerReplyToString());
        $this->validator->expects($this->test->any())
            ->method('validateSignature')
            ->with($this->test->equalTo($request), $this->test->anything(), $this->test->anything())
            ->will($this->test->returnCallback(
                function ($message, $key, $sig) {
                    $this->test->assertTrue(isset($this->clientSignatures[$key]), 'Key not found');
                    $this->test->assertEquals($this->clientSignatures[$key]['sig'], $sig);
                    return $this->clientSignatures[$key]['valid'];
                }
            ));

        $this->validator->expects($this->test->any())
            ->method('nutIPMatches')
            ->with($this->test->equalTo($this->clientNut), $this->test->equalTo($this->clientIp))
            ->will($this->test->returnValue($this->clientIp === $this->originalIp));
    }

    protected function getClientKey(string $keyId): ?string
    {
        if (isset($this->clientRequest[$keyId])) {
            return $this->clientRequest[$keyId];
        }
        return null;
    }

    protected function setUpStorage(): void
    {
        $this->storage->expects($this->test->any())
            ->method('checkIdentityKey')
            ->with($this->test->anything())
            ->will($this->test->returnCallback(
                function ($key) {
                    $this->test->assertTrue(isset($this->serverKeys[$key]), 'Key not found');
                    return $this->serverKeys[$key];
                }
            ));
    }

    protected function setUpGenerator(): void
    {
        if (!empty($this->nut)) {
            $this->generator->expects($this->test->any())
                ->method('getNonce')
                ->with(
                    $this->test->equalTo($this->expectedTif),
                    $this->expectedNut === 'failnut' ?
                        $this->test->anything() ://when the nut is for a failure response, it doesn't get tied to a key
                        $this->test->equalTo($this->getClientKey('idk')),
                    $this->test->equalTo($this->nut['nut'])
                )->will($this->test->returnValue($this->expectedNut));
            $this->generator->expects($this->test->any())
                ->method('generateQry')
                ->will($this->test->returnValue('sqrl?nut=' . $this->expectedNut));
        } else {
            $this->generator->expects($this->test->any())
                ->method('getNonce')
                ->with(
                    $this->test->equalTo($this->expectedTif),
                    $this->test->equalTo(''),
                    $this->test->equalTo('')
                )->will($this->test->returnValue($this->expectedNut));
            $this->generator->expects($this->test->any())
                ->method('generateQry')
                ->will($this->test->returnValue('sqrl?nut=' . $this->expectedNut));
        }
    }

    /**
     * @throws SqrlException
     */
    protected function sendClientRequest(): void
    {
        $body = [
            'server' => $this->base64UrlEncode(
                is_array($this->clientServerParam) ?
                    $this->paramArrayToSqrlString($this->clientServerParam) :
                    $this->clientServerParam
            ),
            'client' => $this->base64UrlEncode($this->getClientString())
        ];
        $keyPosMap = ['idk'=>'ids', 'pidk'=>'pids', 'vuk'=>'urs'];
        foreach ($this->clientSignatures as $key=>$sigData) {
            $param = $keyPosMap[$this->findClientKeyPos($key)];
            $body[$param] = $this->base64UrlEncode($sigData['sig']);
        }

        $this->handler->parseRequest(
            ['nut' => $this->clientNut],
            $body,
            ['REMOTE_ADDR' => $this->clientIp, 'HTTPS' => $this->clientSecure ? '1' : '0']
        );
    }

    protected function findClientKeyPos($key): string
    {
        $pos = array_search($key, $this->clientRequest);
        if ($pos === false) {
            return 'vuk';
        }
        return $pos;
    }

    /**
     * @param array $expectedResponse
     * @throws SqrlException
     */
    protected function validateResponse()
    {
        $expectedResponse = array_merge([
            'ver'=>'1',
            'nut'=>$this->expectedNut,
            'tif'=>strtoupper(dechex( $this->expectedTif)),
            'qry'=>'sqrl?nut='.$this->expectedNut
        ], $this->additionalExpectedResponseParams);
        $this->test->assertEquals(
            $this->paramArrayToSqrlString($expectedResponse),
            $this->base64UrlDecode($this->handler->getResponseMessage())
        );
    }

    public function expectLogin(bool $shouldHappen = true): void
    {
        $this->storage->expects($shouldHappen ? $this->test->once() : $this->test->never())
            ->method('logSessionIn')
            ->with($this->test->equalTo($this->nut['nut']));
    }

    public function expectRegistration(string $idk, string $suk, string $vuk): void
    {
        $this->storage->expects($this->test->once())
            ->method('createIdentity')
            ->with($this->test->equalTo($idk), $this->test->equalTo($suk), $this->test->equalTo($vuk));
    }

    public function expectNoRegistration()
    {
        $this->storage->expects($this->test->never())->method('createIdentity');
    }

    public function expectLock(string $idk): void
    {
        $this->storage->expects($this->test->once())->method('lockIdentityKey')->with($this->test->equalTo($idk));
    }

    public function expectLogout(string $nut)
    {
        $this->storage->expects($this->test->once())->method('endSession')->with($this->test->equalTo($nut));
    }

    public function expectUnlock(string $idk)
    {
        $this->storage->expects($this->test->once())->method('unlockIdentityKey')->with($this->test->equalTo($idk));
    }

    public function expectNoUnlock()
    {
        $this->storage->expects($this->test->never())->method('unlockIdentityKey');
    }

    public function expectIdentityKeyUpdate(string $oldIdk, string $newIdk, string $newSuk, string $newVuk)
    {
        $this->storage->expects($this->test->once())
            ->method('updateIdentityKey')
            ->with(
                $this->test->equalTo($oldIdk),
                $this->test->equalTo($newIdk),
                $this->test->equalTo($newSuk),
                $this->test->equalTo($newVuk)
            );
    }

    public function expectNoIdentityKeyUpdate()
    {
        $this->storage->expects($this->test->never())->method('updateIdentityKey');
    }
}