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

use Trianglman\Sqrl\SqrlStore;
use Trianglman\Sqrl\SqrlValidate;
use Trianglman\Sqrl\SqrlGenerate;
use Trianglman\Sqrl\SqrlRequestHandler;
//use Trianglman\Sqrl\Tests\Resources\AlwaysTrueSignatureValidator as Ed25519NonceValidator;

/**
 * Description of SqrlValidateIntegrationTest
 *
 * @author johnj
 */
class SqrlClientInteractionsIntegrationTest extends \PHPUnit_Extensions_Database_TestCase
{
    protected $dbInitialState = null;
    protected $conn = null;
    protected $nonceData = array();
    protected $userdata = array();
    protected $config = null;
    protected $storage = null;
    protected $nonceValidatorName = '';
    /**
     * @return \PHPUnit_Extensions_Database_DB_IDatabaseConnection
     */
    public function getConnection()
    {
        if(is_null($this->conn)){
            $sysTemp = sys_get_temp_dir();
            $file = $sysTemp.'/sqrl_test_db.db';
            if (file_exists($file)) {
                unlink($file);
            }

            $pdo = new \PDO('sqlite:'.$file);
            $pdo->exec(file_get_contents(dirname(__FILE__).'/Resources/databaseStructure/base.sql'));

            $this->conn = $this->createDefaultDBConnection($pdo, 'sqrl_test');
        }
        return $this->conn;
    }

    /**
     * @return \PHPUnit_Extensions_Database_DataSet_IDataSet
     */
    public function getDataSet()
    {
        if(is_null($this->dbInitialState)){
            $this->dbInitialState = include dirname(__FILE__)
                .'/Resources/databaseStructure/SqrlIntegrationInitialState.php';
        }
        $this->nonceData = array('sqrl_nonce'=>$this->dbInitialState['sqrl_nonce']);
        $this->userdata = array('sqrl_pubkey'=>$this->dbInitialState['sqrl_pubkey']);
        return new DbUnitArrayDataSet($this->dbInitialState);
    }
    
    public function setup()
    {
        parent::setup();
        $this->config = new \Trianglman\Sqrl\SqrlConfiguration();
        $this->config->load(__DIR__.'/Resources/functionaltest.json');
        if(extension_loaded("ellipticCurveSignature")) {
            $this->nonceValidatorName = 'Trianglman\Sqrl\EcEd25519NonceValidator';
        } else {
            $this->nonceValidatorName = 'Trianglman\Sqrl\Ed25519NonceValidator';
        }
        $this->storage = new SqrlStore($this->config);
    }
    
    public function testStandardValidAuthentication()
    {
        $pub = 'MmDImzNYkpmVk7_Bjw4_WEBWec4rSlOjQvJLfYfGdBs';//secret = "primary test user key"
        
        //client will request a SQRL URL
        $sqrlUrl = $this->createInitialSqrlUrl(new SqrlGenerate($this->config,$this->storage), '192.168.0.5');
        
        //client will sign the URL, supply the IDK, and return the values
        //  server=base64url({SQRL URL})&
        //  client=base64url(ver=1
        //  idk={blob}
        //  cmd=login)&
        //  ids={blob}
        $clientResp = array(
            'server'=>$this->base64UrlEncode($sqrlUrl),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>'HbsndEmALLJpgdIOu1qRCGZ4Ix87oVsF1v6D6e5uIXMHVPT1Gk83xaQYGlMymkrXDSB-hI0rFmbh_jqTOZ-6Bw'
            );
        
        //server will verify the client response
        $gen2 = new SqrlGenerate($this->config,$this->storage);
        $gen2->setRequestorIp('192.168.0.5');
        $gen2->setNonce(
                'interactionsTestNonce2', 
                (0x0D), 
                'MmDImzNYkpmVk7/Bjw4/WEBWec4rSlOjQvJLfYfGdBs=');
        //do this here to keep the created time lined up
        $this->addNonce(
            array(
                'id'=>5,
                'nonce'=>'interactionsTestNonce2',
                'created'=>date('Y-m-d H:i:s'),
                'ip'=>ip2long('192.168.0.5'),
                'action'=>  (0x0D),
                'related_public_key'=>'MmDImzNYkpmVk7/Bjw4/WEBWec4rSlOjQvJLfYfGdBs=',
                'verified'=>0
            )
        );
        $requestResponse = new SqrlRequestHandler(
                $this->config,
                new SqrlValidate($this->config,new $this->nonceValidatorName(),$this->storage),
                $this->storage,
                $gen2);
        $requestResponse->parseRequest(
                array('nut'=>'interactionsTestNonce1'), 
                $clientResp, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        //verify the server response includes a new nut, current ID match (0x01), 
        //IP match (0x04), SQRL enabled (0x08), and the friendly name
        //Also verify the database was updated with new data
        $expectedResp1 = "ver=1\r\ntif=".(0x0D)."\r\nsfn=Example Server\r\nnut=interactionsTestNonce2";
        $this->assertEquals($expectedResp1,$requestResponse->getResponseMessage());
        $this->changeNonce(4,array('verified'=>1));
        $this->validateNonceTable();
        
        //the user will sign the server response and send a login command
        $clientResp2 = array(
            'server'=>$this->base64UrlEncode($expectedResp1),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>'bdoqyr4Mx8Tc9RDhZ9-s4pytITTBAEa1XFVs-1BDCg3rbtw_MO4rWQAnr3ElnfgoapTRh73ShYEiVvnal5lsDg'
            );
        
        //verify the server responds with ID match(0x01), IP match(0x04), SQRL enabled(0x08), and 
        //user logged in(0x10)
        $requestResponse2 = new SqrlRequestHandler(
                $this->config,
                new SqrlValidate($this->config,new $this->nonceValidatorName(),$this->storage),
                $this->storage,
                new \Trianglman\Sqrl\SqrlGenerate($this->config,$this->storage));
        $requestResponse2->parseRequest(
                array('nut'=>'interactionsTestNonce1'), //request is made back to original URL since no qry= was supplied
                $clientResp2, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        $this->assertEquals("ver=1\r\ntif=".(0x1D)."\r\nsfn=Example Server",$requestResponse2->getResponseMessage());
        $this->validateNonceTable();
    }

    public function testNewUserAuthenticationAccountCreationAllowed()
    {
        $pub = 'ZWWeSJZAUvcim2IGizK755D0gkOkP3dluiAywyIhmyI';//secret = "another test key"
        $suk = '123456';
        $vuk = 'BUT6BeRSuWpxmcH2yZrLFvGOfE2y11bmozBPm1V5hnM';//secret = "another test idlock key"
        
        $this->config->setAnonAllowed(true);
        
        //client will request a SQRL URL
        $sqrlUrl = $this->createInitialSqrlUrl(new SqrlGenerate($this->config,$this->storage), '192.168.0.5');
        
        //client will sign the URL, supply the IDK, and return the values
        //  server=base64url({SQRL URL})&
        //  client=base64url(ver=1
        //  idk={blob}
        //  cmd=login)&
        //  ids={blob}
        $sig = 'MPffpsQ44_ioOpCEVVN9_3h9BtMch9o4OKKzbZH9uiLORZLom4SOhzJl4fRQeZEXGXr-xM1Rt5yukH905nl0Dw';
        $clientResp = array(
            'server'=>$this->base64UrlEncode($sqrlUrl),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>$sig
            );
        
        
        //server will verify the client response
        $gen2 = new SqrlGenerate($this->config,$this->storage);
        $gen2->setRequestorIp('192.168.0.5');
        $gen2->setNonce(
                'interactionsTestNonce2', 
                (0x2C), 
                'ZWWeSJZAUvcim2IGizK755D0gkOkP3dluiAywyIhmyI=');
        //do this here to keep the created time lined up
        $this->addNonce(
            array(
                'id'=>5,
                'nonce'=>'interactionsTestNonce2',
                'created'=>date('Y-m-d H:i:s'),
                'ip'=>ip2long('192.168.0.5'),
                'action'=>  (0x2C),
                'related_public_key'=>'ZWWeSJZAUvcim2IGizK755D0gkOkP3dluiAywyIhmyI=',
                'verified'=>0
            )
        );
        $requestResponse = new SqrlRequestHandler(
                $this->config,
                new SqrlValidate($this->config,new $this->nonceValidatorName(),$this->storage),
                $this->storage,
                $gen2);
        $requestResponse->parseRequest(
                array('nut'=>'interactionsTestNonce1'), 
                $clientResp, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        //verify the basic server response includes a the new nut, no current 
        //ID match,  IP match(0x04), SQRL enabled(0x08), account creation allowed(0x20), 
        //and the friendly name
        $expectedResp1 = "ver=1\r\ntif=".(0x2C)."\r\nsfn=Example Server\r\nnut=interactionsTestNonce2";
        $this->assertEquals($expectedResp1,$requestResponse->getResponseMessage());
        $this->changeNonce(4,array('verified'=>1));
        $this->validateNonceTable();
        
        $sig2 = '8jCCHFF0CY-JsQP_qPQKTImNL_jzptXlW57nMIJsd1kTbSh8IF1ECjYzfqrWOAC4WsLQoRuhFT4iLyI2iKL4CA';
        $vukSig = 'MfPmNen3F_fUTrYiqP6T0Dy-Sx9jNsXIgFyrkhY-I0NLLfKzLu5nu7AoOZZglgXK1hymHvOs-4A2KTgiRf-XCg';
        $clientResp2 = array(
            'server'=>$this->base64UrlEncode($expectedResp1),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login~create\r\nsuk=$suk\r\nvuk=$vuk"),
            'ids'=>$sig2,
            'urs'=>$vukSig
            );
        
        //verify the server responds with ID match(0x01), IP match(0x04), SQRL enabled(0x08), and 
        //user logged in(0x10)
        $requestResponse2 = new SqrlRequestHandler(
                $this->config,
                new SqrlValidate($this->config,new $this->nonceValidatorName(),$this->storage),
                $this->storage,
                new \Trianglman\Sqrl\SqrlGenerate($this->config,$this->storage));
        $requestResponse2->parseRequest(
                array('nut'=>'interactionsTestNonce1'), //request is made back to original URL since no qry= was supplied
                $clientResp2, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        $this->assertEquals("ver=1\r\ntif=".(0x1D)."\r\nsfn=Example Server",$requestResponse2->getResponseMessage());
        $this->validateNonceTable();
        
        //verify new public key is saved
        $this->addUser(array(
            'id'=>4,
            'public_key'=>'ZWWeSJZAUvcim2IGizK755D0gkOkP3dluiAywyIhmyI=',
            'vuk'=>'BUT6BeRSuWpxmcH2yZrLFvGOfE2y11bmozBPm1V5hnM=',
            'suk'=>'12345w==',
            'disabled'=>0
            ));
        $keyQueryTable = $this->getConnection()->createQueryTable(
            'sqrl_pubkey', 'SELECT * FROM sqrl_pubkey'
        );
        $keyExpectedSet = new DbUnitArrayDataSet($this->userdata);
        $keyExpectedTable = $keyExpectedSet->getTable("sqrl_pubkey");
        $this->assertTablesEqual($keyExpectedTable, $keyQueryTable);
    }
    
    public function testNewUserAuthentciationAccountCreationNotAllowed()
    {
        $pub = 'ZWWeSJZAUvcim2IGizK755D0gkOkP3dluiAywyIhmyI';//secret = "another test key"
        
        $this->config->setAnonAllowed(false);
        
        //client will request a SQRL URL
        $sqrlUrl = $this->createInitialSqrlUrl(new SqrlGenerate($this->config,$this->storage), '192.168.0.5');
        
        //client will sign the URL, supply the IDK, and return the values
        $clientResp = array(
            'server'=>$this->base64UrlEncode($sqrlUrl),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>'MPffpsQ44_ioOpCEVVN9_3h9BtMch9o4OKKzbZH9uiLORZLom4SOhzJl4fRQeZEXGXr-xM1Rt5yukH905nl0Dw'
            );
        
        
        //server will verify the client response
        $requestResponse = new SqrlRequestHandler(
                $this->config,
                new SqrlValidate($this->config,new $this->nonceValidatorName(),$this->storage),
                $this->storage,
                new SqrlGenerate($this->config,$this->storage));
        $requestResponse->parseRequest(
                array('nut'=>'interactionsTestNonce1'), 
                $clientResp, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        //verify the basic server response includes IP match(0x04), 
        //command failed(0x40), and the friendly name
        $this->assertEquals("ver=1\r\ntif=".(0x44)."\r\nsfn=Example Server",$requestResponse->getResponseMessage());
        $this->changeNonce(4,array('verified'=>1));
        $this->validateNonceTable();
        
    }
    
    public function testUserDisableRequest()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and disable command, and return 
        //the values
        
        //verify the basic server response includes a the new nut, current 
        //ID match,  IP match, no SQRL enabled, and the friendly name
        
        //the user will sign the server response and send a login command
        
        //verify the server responds with ID match, IP match, and no SQRL 
        //enabled
    }
    
    public function testUserEnableUnlockCurrentKey()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and enable command, and return 
        //the values
        
        //verify the basic server response includes a the new nut, current 
        //ID match,  IP match, no SQRL enabled, the stored SUK, the link, and 
        //the friendly name
        
        //the user will sign the server response and send a login command with 
        //the VUK
        
        //verify the server responds with ID match, IP match, SQRL enabled, 
        //and user logged in
    }
    
    public function testStandardValidAuthenticationNewIDK()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and pIDK, and return 
        //the values
        
        //verify the basic server response includes a the new nut, no current 
        //ID match, previous ID match, IP match, SQRL enabled, the stored SUK, 
        //the link, and the friendly name
        
        //the user will sign the server response and send a login command with 
        //the VUK
        
        //verify the server responds with ID match, IP match, SQRL enabled, 
        //and user logged in
    }
    
    public function testUserEnableNewIDK()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and pIDK and the enable command, 
        //and return the values
        
        //verify the basic server response includes a the new nut, no current 
        //ID match, previous ID match, IP match, no SQRL enabled, the stored SUK, 
        //the link, and the friendly name
        
        //the user will sign the server response and send a login command with 
        //the VUK
        
        //verify the server responds with with ID match, IP match, SQRL enabled, 
        //and user logged in
    }
    
    public function testuserEnableNewIDKandLock()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and pIDK and the enable command, 
        //and return the values
        
        //verify the basic server response includes a the new nut, no current 
        //ID match, previous ID match, IP match, no SQRL enabled, the stored SUK, 
        //the link, and the friendly name
        
        //the user will sign the server response and send a login command with 
        //the VUK
        
        //verify the server responds with without ID match, IP match, SQRL enabled, 
        //and user logged in
    }
    
    protected function base64UrlEncode($string)
    {
        $base64 = base64_encode($string);
        $urlencode = str_replace(array('+','/'), array('-','_'), $base64);
        return trim($urlencode, '=');
    }
    
    protected function createInitialSqrlUrl($generator,$ip,$nonce='interactionsTestNonce1')
    {
        $generator->setRequestorIp($ip);
        $generator->setNonce($nonce);
        $sqrlUrl = $generator->getUrl();
        $this->assertEquals('sqrl://domain.com/login/sqrlauth.php?nut='.$nonce,$sqrlUrl);
        $this->addNonce(
            array(
                'id'=>4,
                'nonce'=>$nonce,
                'created'=>date('Y-m-d H:i:s'),
                'ip'=>ip2long($ip),
                'action'=>  \Trianglman\Sqrl\SqrlRequestHandlerInterface::INITIAL_REQUEST,
                'related_public_key'=>null,
                'verified'=>0
            )
        );
        $this->validateNonceTable();
        return $sqrlUrl;
    }
    
    protected function addNonce(array $nonce)
    {
        $this->nonceData['sqrl_nonce'][] = $nonce;
    }
    
    protected function addUser(array $user)
    {
        $this->userdata['sqrl_pubkey'][] = $user;
    }
    
    protected function changeNonce($id,array $updates)
    {
        foreach ($this->nonceData['sqrl_nonce'] as &$nonce) {
            if ($nonce['id']==$id) {
                foreach ($updates as $key=>$value) {
                    $$nonce[$key] = $value;
                }
            }
        }
    }
    
    protected function validateNonceTable()
    {
        $queryTable = $this->getConnection()->createQueryTable(
            'sqrl_nonce', 'SELECT * FROM sqrl_nonce'
        );
        $expectedSet = new DbUnitArrayDataSet($this->nonceData);
        $expectedTable = $expectedSet->getTable("sqrl_nonce");
        $this->assertTablesEqual($expectedTable, $queryTable);
    }
}
