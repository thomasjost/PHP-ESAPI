<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * PHP version 5.2
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Arnaud Labenne <arnaud.labenne@dotsafe.fr>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Require ESAPI and SafeFile.
 */

/**
 * Unit Tests for the SafeFile extension to SplFileObject.
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Arnaud Labenne <arnaud.labenne@dotsafe.fr>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
 namespace PHPESAPI\PHPESAPI\Test\Reference;

class SafeFileTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Test constructor of class SafeFile.
     *
     * @return bool True on Pass.
     */
    public function testSafeFile()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml';

        $sf = null;
        try {
            $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
        } catch (\Exception $e) {
            $this->fail('SafeFile threw an exception during construction');
        }
        if ($sf && !$sf->isReadable()) {
            $this->fail("{$file} is not readable");
        }

        $this->assertTrue($sf && $sf->isReadable());
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithNullByteInFileName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml' . chr(0);

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Valid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithDevNull()
    {
        $file = null;
        if (substr(PHP_OS, 0, 3) == 'WIN') {
            $file = 'nul';
        } else {
            $file = '/dev/null';
        }

        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);

        if (!$sf->isReadable()) {
            $this->fail("{$file} is not readable - %s");
        }

        $this->assertTrue($sf->isReadable());
    }

    /**
     * Test class SafeFile with Invalid path.
     * On windows, this test will bypass the protection provided by SplFileObject
     * by using a valid device name (nul) with an invalid file extension and hence
     * tests SafeFile privat _doFileCheck method.
     * On *nix, the test input will be caught by SplFileObject.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithDevNullAndPercentEncoding()
    {
        $file = null;
        if (substr(PHP_OS, 0, 3) == 'WIN') {
            $file = 'nul.%07';
            $this->setExpectedException('ValidationException');
        } else {
            $file = '/dev/null.%07';
            $this->setExpectedException('EnterpriseSecurityException');
        }

        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithNullByteInDirName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . chr(0) . '/ESAPI.xml';

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithPercentEncodingInFileName01()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml%00';

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithPercentEncodingInFileName02()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml%3C';

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithPercentEncodingInFileName03()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml%3c';

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithPercentEncodingInFileName04()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . '/ESAPI.xml%Ac';

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileWithPercentEncodingInFile()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . "%00/ESAPI.xml";

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileIllegalCharacter()
    {
        $fileIllegals = array('/', ':', '*', '?', '<', '>', '|', '\\');
        $dirIllegals = array('*', '?', '<', '>', '|');

        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();

        foreach ($fileIllegals as $char) {
            $file = $config->getResourceDirectory() . "/ESAPI$char.xml";

            try {
                $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
                $this->fail();
            } catch (\Exception $e) {
                //Expected
            }
        }

        foreach ($dirIllegals as $char) {
            $file = $config->getResourceDirectory() . "$char/ESAPI.xml";

            try {
                $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
                $this->fail();
            } catch (\Exception $e) {
                //Expected
            }
        }

        $this->assertTrue(true);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileHighByteInFileName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . "/ESAPI" . chr(200) . ".xml";

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileHighByteInDirName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . chr(200) . "/ESAPI.xml";

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileLowByteInDirName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . chr(8) . "/ESAPI.xml";

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test constructor of class SafeFile with Invalid path.
     *
     * @return bool True on Pass.
     */
    public function testSafeFileLowByteInFileName()
    {
        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $file = $config->getResourceDirectory() . "/ESAPI" . chr(8) . ".xml";

        $this->setExpectedException('EnterpriseSecurityException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /**
     * Test null byte injection.
     *
     * @return bool True on Pass.
     */
    public function testURILocal()
    {
        $file = null;
        if (substr(PHP_OS, 0, 3) == 'WIN') {
            $file = 'file:///C://WINDOWS/system32/drivers/etc/hosts';
        } else {
            $file = 'file:///etc/hosts';
        }

        try {
            $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
        } catch (\Exception $e) {
            $this->fail(
                'This test could not run so did not really fail. Please choose a suitable test input.'
            );
        }

        $file .= chr(0) . '/test.php'; // SplFileObject doesn't catch this!

        $this->setExpectedException('ValidationException'); // but we will!
        $sf = new SafeFile($file);
    }

    /**
     * Test null byte injection.
     *
     * @return bool True on Pass.
     */
    public function testURIRemote()
    {
        $file = 'http://www.google.com/index.html';

        try {
            $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
        } catch (\Exception $e) {
            $this->fail(
                'This test could not run so did not really fail. Please choose a suitable test input.'
            );
        }

        $file .= chr(0);

        $this->setExpectedException('ValidationException');
        $sf = new \PHPESAPI\PHPESAPI\SafeFile($file);
    }

    /*
    function testDetectForbiddenCharacter()
    {
        $config = ESAPI::getSecurityConfiguration();

        for ($i = 0 ; $i < 256 ; $i++) {
            $file = $config->getResourceDirectory() . "/ESAPI.xml" . chr($i);

            try {
                @$f = new SplFileObject($file);
                if ($f->isReadable()) {

                    try {
                        $sf = new SafeFile($file);
                        $this->fail();

                    } catch (Exception $e) {
                        //Expected
                    }

                }
            } catch (Exception $e) {
                //Expected
            }
        }
    }
    */
}
