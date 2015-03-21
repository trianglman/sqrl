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

use Endroid\QrCode\QrCode;

/**
 * Generates a SQRL QR image, URL and nonce.
 *
 * @author johnj
 */
class SqrlGenerate implements SqrlGenerateInterface
{
    /**
     * @var SqrlStore
     */
    protected $store = null;

    protected $nonce = '';

    /**
     *
     * @var SqrlConfiguration
     */
    protected $configuration = null;
    
    public function __construct(SqrlConfiguration $config,  SqrlStoreInterface $storage)
    {
        $this->configuration = $config;
        $this->store = $storage;
    }
    
    /**
     * Returns the generated nonce
     *
     * @param int    $action [Optional] The type of action this nonce is being generated for
     * @param string $key [Optional] The public key associated with the nonce
     * @param string $previousNonce [Optional] The previous nonce in the transaction that should be associated to this nonce
     *
     * @return string The one time use string for the QR link
     */
    public function getNonce($action = 0, $key = '', $previousNonce='')
    {
        if (empty($this->nonce)) {
            if ($this->store instanceof SqrlStoreStatelessAbstract) {
                $this->nonce = $this->store->generateNut($action, $key, $previousNonce);
                return $this->nonce;
            }
            if ($action === 0) {
                $check = $this->store->getSessionNonce();
                if (!empty($check)) {
                    $this->nonce = $check;
                    return $this->nonce;
                }
            }
            $this->generateNonce($action, $key,$previousNonce);
        }

        return $this->nonce;
    }

    public function generateQry()
    {
        $currentPathParts = parse_url($this->configuration->getAuthenticationPath());
        $pathAppend = (empty($currentPathParts['query'])?'?':'&').'nut=';

        return $this->configuration->getAuthenticationPath().$pathAppend.$this->getNonce();
    }

    public function getUrl()
    {
        $url = ($this->configuration->getSecure() ? 's' : '').'qrl://'.$this->configuration->getDomain();
        if (strpos($this->configuration->getDomain(), '/') !== false) {
            $extension = strlen($this->configuration->getDomain())-strpos($this->configuration->getDomain(), '/');
            $url.= substr($this->generateQry(),$extension).'&d='.$extension;
        } else {
            $url.= $this->generateQry();
        }
        return $url;
    }

    public function render($outputFile)
    {
        $qrCode = new QrCode();
        $qrCode->setText($this->getUrl());
        $qrCode->setSize($this->configuration->getQrHeight());
        $qrCode->setPadding($this->configuration->getQrPadding());
        $qrCode->render($outputFile);
    }

    /**
     * Generates a random, one time use key to be used in the sqrl validation
     *
     * The implementation of this may get more complicated depending on the
     * requirements detailed in any reference implementation. Users wanting to
     * make this library more (or less) secure should override this function
     * to strengthen (or weaken) the randomness of the generation.
     *
     * @param int    $action [Optional] The type of action this nonce is being generated for
     * @param string $key [Optional] The public key associated with the nonce
     * @param string $previousNonce [Optional] The previous nonce in the transaction that should be associated to this nonce
     *
     * @return string
     */
    protected function generateNonce($action = 0, $key = '', $previousNonce='')
    {
        $this->nonce = hash_hmac('sha256', uniqid('', true), $this->configuration->getNonceSalt());
        $this->store->storeNonce($this->nonce, $action, $key,$previousNonce);
        return $this->nonce;
    }

}
