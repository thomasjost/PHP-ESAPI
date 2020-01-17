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
 * Notes - any changes to the testresources/ESAPI.xml file MUST be reflected in this file
 * or else most (if not all) of these tests will fail.
 *
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 * @since 1.6
 */
 namespace PHPESAPI\PHPESAPI\Test\Reference;

class StringUtilitiesTest extends \PHPUnit\Framework\TestCase
{
    public function testStripControlsEmpty()
    {
        $this->assertEquals('', \PHPESAPI\PHPESAPI\StringUtilities::stripControls(false));
        $this->assertEquals('', \PHPESAPI\PHPESAPI\StringUtilities::stripControls(null));
        $this->assertEquals('', \PHPESAPI\PHPESAPI\StringUtilities::stripControls(''));
    }

    public function testStripControlsPass()
    {
        $this->assertEquals('esapi', \PHPESAPI\PHPESAPI\StringUtilities::stripControls('esapi'));
    }

    public function testStripControlsLowChars()
    {
        $this->assertEquals('esapi rocks', \PHPESAPI\PHPESAPI\StringUtilities::stripControls("esapi" . chr(10) . "rocks"));
    }

    public function testStripControlsHighChars()
    {
        $this->assertEquals('  ', \PHPESAPI\PHPESAPI\StringUtilities::stripControls(chr(0xFE) . chr(0xED)));
    }

    public function testStripControlsBorderCases()
    {
        $this->assertEquals('  ', \PHPESAPI\PHPESAPI\StringUtilities::stripControls(chr(0x20) . chr(0x7f)));
    }

    public function testContainsPass()
    {
        $this->assertTrue(\PHPESAPI\PHPESAPI\StringUtilities::contains('esapi rocks', 'e'));
    }

    public function testContainsPassString()
    {
        $this->assertTrue(\PHPESAPI\PHPESAPI\StringUtilities::contains('esapi rocks', 'pi ro'));
    }

    public function testContainsFail()
    {
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('esapi rocks', 'z'));
    }

    public function testContainsFailString()
    {
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('esapi rocks', 'invalid'));
    }

    public function testContainsNull()
    {
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains(null, 'z'));
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('foo', null));
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains(null, null));
    }

    public function testContainsEmpty()
    {
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('', 'z'));
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('z', ''));
        $this->assertFalse(\PHPESAPI\PHPESAPI\StringUtilities::contains('', ''));
    }

    public function testUnionPass()
    {
        $arr1 = array('e', 's' , 'a', 'p', 'i');
        $arr2 = array('r', 'o' , 'c', 'k', 's');

        $expected = array('a','c','e','i','k','o','p','r','s');

        $this->assertEquals($expected, \PHPESAPI\PHPESAPI\StringUtilities::union($arr1, $arr2));
    }

    public function testUnionUnique()
    {
        $arr1 = array("esapi", "rocks");
        $arr2 = array("esapi");

        $expected = array("esapi", "rocks");

        $this->assertEquals($expected, \PHPESAPI\PHPESAPI\StringUtilities::union($arr1, $arr2));
    }

    public function testUnionEmpty()
    {
        $arr1 = array();
        $arr2 = array();

        $this->assertEquals(null, \PHPESAPI\PHPESAPI\StringUtilities::union($arr1, $arr2));
    }
}
