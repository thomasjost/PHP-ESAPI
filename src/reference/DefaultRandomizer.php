<?php
/**
 * OWASP Enterprise Security API (ESAPI).
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Andrew van der Stock
 * @created 2009
 *
 * @since 1.6
 *
 * @package ESAPI_Reference
 */

class DefaultRandomizer implements Randomizer
{
    
    private $maxRand;

    public function __construct()
    {
        $this->maxRand = mt_getrandmax();
    }
    
    /**
     * {@inheritDoc}
     */
    public function getRandomString($numChars, $charset)
    {
        if ($numChars < 1 || strlen($charset) < 2) {
            throw new InvalidArgumentException();
        }

        $l = strlen($charset) - 1;

        $rs = '';
        for ($i = 0; $i < $numChars; $i++) {
            $rs .= $charset[mt_rand(0, $l)];
        }

        return $rs;
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomBoolean()
    {
        return ((mt_rand(0, 100) % 2) ? true : false);
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomInteger($min, $max)
    {
        return mt_rand($min, $max);
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomLong()
    {
        return mt_rand();
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomFilename($extension = '')
    {
        // Because PHP runs on case insensitive OS as well as case sensitive OS, only use lowercase

        $rs = $this->getRandomString(16, 'abcdefghijklmnopqrstuvxyz0123456789');
        $rs .= $extension;

        return  $rs;
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomReal($min, $max)
    {
        $rf = (float) (mt_rand() / $this->maxRand);        // Maximizes the random bit counts from the PHP PRNG

        $factor = $max - $min;

        return (float) ($rf * $factor + $min);
    }

    /**
     * {@inheritDoc}
     */
    public function getRandomGUID()
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 65535),
            mt_rand(0, 65535), // 32 bits for "time_low"
            mt_rand(0, 65535), // 16 bits for "time_mid"
            mt_rand(0, 4095), // 12 bits before the 0100 of (version) 4 for "time_hi_and_version"
            bindec(substr_replace(sprintf('%016b', mt_rand(0, 65535)), '01', 6, 2)),
            // 8 bits, the last two of which (positions 6 and 7) are 01, for "clk_seq_hi_res"
            // (hence, the 2nd hex digit after the 3rd hyphen can only be 1, 5, 9 or d)
            // 8 bits for "clk_seq_low"
            mt_rand(0, 65535),
            mt_rand(0, 65535),
            mt_rand(0, 65535) // 48 bits for "node"
        );
    }
}
