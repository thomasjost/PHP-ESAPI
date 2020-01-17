<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 * @since 1.6
 */
  namespace PHPESAPI\PHPESAPI\Test\Reference;

class RandomizerTest extends \PHPUnit\Framework\TestCase
{
    private $CHAR_ALPHANUMERICS = 'abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ01234567890';

    /**
     * Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.
     * @throws \PHPESAPI\PHPESAPI\Errors\EncryptionException
     */
    public function testGetRandomGUID()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $list = array();

        $result = true;
        for ($i = 0; $i < 100; $i++) {
            $guid = $instance->getRandomGUID();
            if (in_array($guid, $list)) {
                $result = false;
                $this->fail();
            }

            $list[] = $guid;
        }

        $this->assertTrue($result);
    }

    /**
     * Test of getRandomString method, of class org.owasp.esapi.Randomizer.
     */
    public function testGetRandomString()
    {
        $length = 20;
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();
        $charset = str_split($this->CHAR_ALPHANUMERICS);

        try {
            for ($i = 0; $i < 100; $i++) {
                $result = $instance->getRandomString($length, $this->CHAR_ALPHANUMERICS);    // TODO replace with DefaultEncoder...

                for ($j = 0; $j< strlen($result); $j++) {
                    if (!in_array($result[$j], $charset)) {            // TODO replace with DefaultEncoder...
                        $this->fail("Character [ " . $result[$j] . " ] not found in [ " . $result . " ]");
                    }
                }
                $this->assertEquals($length, strlen($result));
            }
        } catch (\InvalidArgumentException $e) {
            $this->fail("getRandomString() failed due to too short length ($length) or no character set [ " . $this->CHAR_ALPHANUMERICS . " ]");
        }
    }

    /**
     * Test of getRandomInteger method, of class org.owasp.\PHPESAPI\PHPESAPI\esapi.Randomizer.
     */
    public function testGetRandomInteger()
    {
        $min = -20;
        $max = 100;

        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $minResult = ($max - $min) / 2;
        $maxResult = ($max - $min) / 2;

        for ($i = 0; $i < 100; $i++) {
            $result = $instance->getRandomInteger($min, $max);
            if ($result < $minResult) {
                $minResult = $result;
            }
            if ($result > $maxResult) {
                $maxResult = $result;
            }
        }
        $this->assertTrue(($minResult >= $min && $maxResult <= $max), "minResult ($minResult) >= min ($min) && maxResult ($maxResult) <= max ($max)");
    }

    /**
     * Test of getRandomReal method, of class org.owasp.\PHPESAPI\PHPESAPI\esapi.Randomizer.
     */
    public function testGetRandomReal()
    {
        $min = -20.5234;
        $max = 100.12124;

        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $minResult = ($max - $min) / 2;
        $maxResult = ($max - $min) / 2;

        for ($i = 0; $i < 100; $i++) {
            $result = $instance->getRandomReal($min, $max);
            if ($result < $minResult) {
                $minResult = $result;
            }
            if ($result > $maxResult) {
                $maxResult = $result;
            }
        }
        $this->assertTrue(($minResult >= $min && $maxResult <= $max));
    }

    public function testGetRandomBoolean()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $result = $instance->getRandomBoolean();

        // PHP funkyness: I am using the equal operator with the type equivalence extra '='
        // If both true and false are not found, then we don't have a boolean
        $this->assertFalse($result !== true && $result !== false);
    }

    public function testGetRandomLong()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();
        $result = $instance->getRandomLong();

        $this->assertTrue($result >= 0);
        $this->assertTrue($result < mt_getrandmax());
    }

    public function testGetRandomFilenameCharSet()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();
        $charset = str_split('abcdefghijklmnopqrstuvxyz0123456789'); // TODO replace with DefaultEncoder...

        try {
            for ($i = 0; $i < 100; $i++) {
                $result = $instance->getRandomFilename();
                $len = strlen($result);        // Filenames should be 16 characters long

                for ($j = 0; $j < $len; $j++) {
                    if (!in_array($result[$j], $charset)) {
                        $this->fail("Character [ " . $result[$j] . " ] not found in [ " . $result . " ]");
                    }
                }
            }
        } catch (\InvalidArgumentException $e) {
            $this->fail("getRandomFilename() failed due to too short length (16) or no character set [ abcdefghijklmnopqrstuvxyz0123456789 ]");
        }

        // TODO: probably should try to prove something here. Equivalent to SimpleTest's pass method
        $this->assertTrue(true);
    }

    public function testGetRandomFilenameLengthNoExtension()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $result = $instance->getRandomFilename();
        $this->assertEquals(16, strlen($result));
    }

    public function testGetRandomFilenameLengthWithExtension()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getRandomizer();

        $result = $instance->getRandomFilename('.php');
        $this->assertEquals(20, strlen($result));
    }
}
