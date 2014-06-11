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

use Trianglman\Sqrl\SqrlException;
use Trianglman\Sqrl\SqrlStore;
use Trianglman\Sqrl\SqrlValidate;
use Trianglman\Sqrl\Ed25519NonceValidator;

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
    
    public function testStandardValidAuthentication()
    {
        $pub = 'MmDImzNYkpmVk7_Bjw4_WEBWec4rSlOjQvJLfYfGdBs';
        $config = new \Trianglman\Sqrl\SqrlConfiguration();
        $config->load(__DIR__.'/Resources/functionaltest.json');
        $storage = new SqrlStore();
        $storage->setConfiguration($config);
        $generator = $this->prepGenerator($storage,$config);
        
        //client will request a SQRL URL
        $generator->setRequestorIp('192.168.0.5');
        $sqrlUrl = $this->createInitialSqrlUrl($generator, '192.168.0.5');
        
        //client will sign the URL, supply the IDK, and return the values
        //  server=base64url({SQRL URL})&
        //  client=base64url(ver=1
        //  idk={blob}
        //  cmd=login)&
        //  ids={blob}
        $sig = 'HbsndEmALLJpgdIOu1qRCGZ4Ix87oVsF1v6D6e5uIXMHVPT1Gk83xaQYGlMymkrXDSB-hI0rFmbh_jqTOZ-6Bw';
        $clientResp = array(
            'server'=>$this->base64UrlEncode($sqrlUrl),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>$sig
            );
        
        //server will verify the client response
        $validator1 = $this->prepValidator($storage,$config);
        $gen2 = $this->prepGenerator($storage,$config);
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
        $requestResponse = new \Trianglman\Sqrl\SqrlRequestHandler($validator1,$storage,$gen2);
        $requestResponse->setSfn('Example Server');
        $requestResponse->parseRequest(
                array('nut'=>'interactionsTestNonce1'), 
                $clientResp, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        $serverResp1 = $requestResponse->getResponseMessage();
        //verify the server response includes a new nut, current ID match (0x01), 
        //IP match (0x04), SQRL enabled (0x08), and the friendly name
        //Also verify the database was updated with new data
        $expectedResp1 = "ver=1\r\ntif=".(0x0D)."\r\nsfn=Example Server\r\nnut=interactionsTestNonce2";
        $this->assertEquals($expectedResp1,$serverResp1);
        $this->changeNonce(4,array('verified'=>1));
        $queryTable = $this->getConnection()->createQueryTable(
            'sqrl_nonce', 'SELECT * FROM sqrl_nonce'
        );
        $expectedSet = new DbUnitArrayDataSet($this->nonceData);
        $expectedTable = $expectedSet->getTable("sqrl_nonce");
        $this->assertTablesEqual($expectedTable, $queryTable);
        
        //the user will sign the server response and send a login command
        $sig2 = 'bdoqyr4Mx8Tc9RDhZ9-s4pytITTBAEa1XFVs-1BDCg3rbtw_MO4rWQAnr3ElnfgoapTRh73ShYEiVvnal5lsDg';
        $clientResp2 = array(
            'server'=>$this->base64UrlEncode($expectedResp1),
            'client'=>$this->base64UrlEncode("ver=1\r\nidk=$pub\r\ncmd=login"),
            'ids'=>$sig2
            );
        
        //verify the server responds with ID match(0x01), IP match(0x04), SQRL enabled(0x08), and 
        //user logged in(0x10)
        $validator2 = $this->prepValidator($storage,$config);
        $gen3 = $this->prepGenerator($storage,$config);
        $requestResponse2 = new \Trianglman\Sqrl\SqrlRequestHandler($validator2,$storage,$gen3);
        $requestResponse2->setSfn('Example Server');
        $requestResponse2->parseRequest(
                array('nut'=>'interactionsTestNonce1'), //request is made back to original URL since no qry= was supplied
                $clientResp2, 
                array('REMOTE_ADDR'=>'192.168.0.5','HTTPS'=>'1'));
        $serverResp2 = $requestResponse2->getResponseMessage();
        $expectedResp2 = "ver=1\r\ntif=".(0x1D)."\r\nsfn=Example Server";
        $this->assertEquals($expectedResp2,$serverResp2);
        $queryTable2 = $this->getConnection()->createQueryTable(
            'sqrl_nonce', 'SELECT * FROM sqrl_nonce'
        );
        $expectedSet2 = new DbUnitArrayDataSet($this->nonceData);
        $expectedTable2 = $expectedSet2->getTable("sqrl_nonce");
        $this->assertTablesEqual($expectedTable2, $queryTable2);
    }

    public function testNewUserAuthenticationAccountCreationAllowed()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, supply the IDK and return the values
        
        //verify the basic server response includes a the new nut, no current 
        //ID match,  IP match, SQRL enabled, account creation allowed, the link, 
        //and the friendly name
        
        //the user will sign the server response and send a login command and SUK/VUK
        
        //verify the server responds with without ID match, IP match, SQRL enabled, 
        //and user logged in
    }
    
    public function testNewUserAuthentciationAccountCreationNotAllowed()
    {
        $this->markTestIncomplete();
        //client will request a SQRL URL
        
        //client will sign the URL, with the IDK and return the values
        
        //verify the basic server response includes a the new nut, without current 
        //ID match,  IP match, SQRL enabled,the link, and the friendly name and 
        //command failed
        
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
    
    protected function prepValidator($storage,$config)
    {
        $validator = new \Trianglman\Sqrl\SqrlValidate();
        $validator->setConfiguration($config);
        $validator->setValidator(new Ed25519NonceValidator());
        $validator->setStorage($storage);
        return $validator;
    }
    
    protected function prepGenerator($storage,$config)
    {
        $generator = new \Trianglman\Sqrl\SqrlGenerate();
        $generator->setConfiguration($config);
        $generator->setStorage($storage);
        return $generator;
    }
    
    protected function createInitialSqrlUrl($generator,$ip,$nonce='interactionsTestNonce1')
    {
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
        $queryTable = $this->getConnection()->createQueryTable(
            'sqrl_nonce', 'SELECT * FROM sqrl_nonce'
        );
        $expectedSet = new DbUnitArrayDataSet($this->nonceData);
        $expectedTable = $expectedSet->getTable("sqrl_nonce");
        $this->assertTablesEqual($expectedTable, $queryTable);
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
}
