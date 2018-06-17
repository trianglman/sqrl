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
namespace Trianglman\Sqrl\Traits;

use Trianglman\Sqrl\SqrlConfiguration;

trait SqrlUrlGenerator
{
    /**
     * Appends the nut= parameter appropriately to the query path
     *
     * @param string $authPath The path from the root of the domain (e.g. /sqrl/auth)
     * @param string $nut
     * @return string
     */
    protected function generateQry(string $authPath, string $nut): string
    {
        $currentPathParts = parse_url($authPath);
        $pathAppend = (empty($currentPathParts['query'])?'?':'&').'nut=';

        return $authPath.$pathAppend.$nut;
    }

    /**
     * Generates the URL for client responses
     *
     * @param SqrlConfiguration $config
     * @param string $nut
     * @return string
     */
    protected function generateUrl(SqrlConfiguration $config, string $nut): string
    {
        $url = ($config->getSecure() ? 's' : '').'qrl://'.$config->getDomain();
        if (strpos($config->getDomain(), '/') !== false) {
            $extension = strlen($config->getDomain())-strpos($config->getDomain(), '/');
            $url.= substr($this->generateQry($config->getAuthenticationPath(), $nut), $extension).'&x='.$extension;
        } else {
            $url.= $this->generateQry($config->getAuthenticationPath(), $nut);
        }
        return $url;
    }
}