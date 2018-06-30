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
 * Generates a SQRL QR image, URL and nonce.
 *
 * @author johnj
 */
interface SqrlGenerateInterface
{
    /**
     * Generates the QR code image
     *
     * @param string $outputFile
     *
     * @return void
     */
    public function render(?string $outputFile);

    /**
     * Returns the generated nonce
     *
     * @param int    $action [Optional] The type of action this nonce is being generated for
     * @param string $key [Optional] The public key associated with the nonce
     * @param string $previousNonce [Optional] The previous nonce in the transaction that should be associated to this nonce
     *
     * @return string The one time use string for the QR link
     */
    public function getNonce(int $action = 0, string $key = '', string $previousNonce = ''): string;

    /**
     * Gets the validation URL including the nonce
     *
     * @return string
     */
    public function getUrl(): string;
    
    /**
     * Generates the qry parameter to send in server responses
     * 
     * @return string
     */
    public function generateQry(): string;
}
