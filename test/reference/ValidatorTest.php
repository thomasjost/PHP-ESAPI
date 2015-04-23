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
 */

require_once __DIR__ . '/../testresources/TestHelpers.php';

class ValidatorTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test of Validator::isValidInput with an email.
     */
    public function testIsValidInput_Email()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidInput('test', 'jeff.williams@aspectsecurity.com', 'Email', 100, false));
        $this->assertTrue($instance->isValidInput('test', null, 'Email', 100, true));
        
        $this->assertFalse($instance->isValidInput('test', 'jeff.williams@@aspectsecurity.com', 'Email', 100, false));
        $this->assertFalse($instance->isValidInput('test', 'jeff.williams@aspectsecurity', 'Email', 100, false));
        $this->assertFalse($instance->isValidInput('test', null, 'Email', 100, false));
    }

    /**
     * Test of Validator::isValidInput with an IPv4 address.
     */
    public function testIsValidInput_IPv4Address()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidInput('test', '123.168.100.234', 'IPAddress', 100, false));
        $this->assertTrue($instance->isValidInput('test', '192.168.1.234', 'IPAddress', 100, false));
        
        $this->assertFalse($instance->isValidInput('test', '..168.1.234', 'IPAddress', 100, false));
        $this->assertFalse($instance->isValidInput('test', '10.x.1.234', 'IPAddress', 100, false));
    }

    /**
     * Test of Validator::isValidInput with a URL.
     */
    public function testIsValidInput_URL()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidInput('test', 'http://www.aspectsecurity.com', 'URL', 100, false));
        
        $this->assertFalse($instance->isValidInput('test', 'http:///www.aspectsecurity.com', 'URL', 100, false));
        $this->assertFalse($instance->isValidInput('test', 'http://www.aspect security.com', 'URL', 100, false));
    }

    /**
     * Test of Validator::isValidInput with a US Social Security number.
     */
    public function testIsValidInput_SSN()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidInput('test', '078-05-1120', 'SSN', 100, false));
        $this->assertTrue($instance->isValidInput('test', '078 05 1120', 'SSN', 100, false));
        $this->assertTrue($instance->isValidInput('test', '078051120', 'SSN', 100, false));
        
        $this->assertFalse($instance->isValidInput('test', '987-65-4320', 'SSN', 100, false));
        $this->assertFalse($instance->isValidInput('test', '000-00-0000', 'SSN', 100, false));
        $this->assertFalse($instance->isValidInput('test', '(555) 555-5555', 'SSN', 100, false));
        $this->assertFalse($instance->isValidInput('test', 'test', 'SSN', 100, false));
    }

    /**
     * Test of Validator::isValidDate.
     */
    public function testIsValidDate()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidDate('test', 'June 23, 1967', 'F j, Y', false));
        $this->assertFalse($instance->isValidDate('test', 'freakshow', 'F j, Y', false));
    }

    /**
     * Test of Validator::isValidSafeHTML.
     */
    public function testIsValidSafeHTML()
    {
        $this->markTestIncomplete();
        
        $instance = ESAPI::getValidator();

        $this->assertTrue($instance->isValidSafeHTML('test', '<b>Jeff</b>', 100, false));
        $this->assertTrue($instance->isValidSafeHTML('test', "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
        $this->assertFalse($instance->isValidSafeHTML('test', 'Test. <script>alert(document.cookie)</script>', 100, false));

        // TODO: waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // $this->assertFalse($instance->isValidSafeHTML('test', "\" onload=\"alert(document.cookie)\" "));
    }

    /**
     * Test of Validator::isValidCreditCard.
     */
    public function testIsValidCreditCard_valid()
    {
        $instance = ESAPI::getValidator();

        $this->assertTrue($instance->isValidCreditCard('test', '1234 9876 0000 0008', false));
        $this->assertTrue($instance->isValidCreditCard('test', '1234987600000008', false));
        $this->assertTrue($instance->isValidCreditCard('test', '1234-9876-0000-0008', false));
        $this->assertTrue($instance->isValidCreditCard('test', '', true));
        $this->assertTrue($instance->isValidCreditCard('test', null, true));
        
        $this->assertFalse($instance->isValidCreditCard('test', '12349876000000081', false));
        $this->assertFalse($instance->isValidCreditCard('test', '4417 1234 5678 9112', false));
        $this->assertFalse($instance->isValidCreditCard('test', 0, true));
        $this->assertFalse($instance->isValidCreditCard('test', array(), true));
    }

    /**
     * Test of Validator::isValidListItem.
     */
    public function testIsValidListItem()
    {
        $val = ESAPI::getValidator();
        
        $list = array('one','two');

        $this->assertTrue($val->isValidListItem('test', 'one', $list));
        $this->assertFalse($val->isValidListItem('test', 'three', $list));
    }

    /**
     * Test of Validator::isValidNumber.
     */
    public function testIsValidNumber()
    {
        $instance = ESAPI::getValidator();
        
        // testing negative range
        $this->assertFalse($instance->isValidNumber('test', '-4', 1, 10, false));
        $this->assertTrue($instance->isValidNumber('test', '-4', -10, 10, false));
        // testing null value
        $this->assertTrue($instance->isValidNumber('test', null, -10, 10, true));
        $this->assertFalse($instance->isValidNumber('test', null, -10, 10, false));
        // testing empty string
        $this->assertTrue($instance->isValidNumber('test', '', -10, 10, true));
        $this->assertFalse($instance->isValidNumber('test', '', -10, 10, false));
        // testing improper range
        $this->assertFalse($instance->isValidNumber('test', '5', 10, -10, false));
        // testing non-integers
        $this->assertTrue($instance->isValidNumber('test', '4.3214', -10, 10, true));
        $this->assertTrue($instance->isValidNumber('test', '-1.65', -10, 10, true));
        // other testing
        $this->assertTrue($instance->isValidNumber('test', '4', 1, 10, false));
        $this->assertTrue($instance->isValidNumber('test', '400', 1, 10000, false));
        $this->assertTrue($instance->isValidNumber('test', '400000000', 1, 400000000, false));
        $this->assertFalse($instance->isValidNumber('test', '4000000000000', 1, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'alsdkf', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '--10', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '14.1414234x', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '-Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', 'NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '-NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidNumber('test', '+NaN', 10, 10000, false));
        $this->assertTrue($instance->isValidNumber('test', '1e-6', -999999999, 999999999, false));
        $this->assertTrue($instance->isValidNumber('test', '-1e-6', -999999999, 999999999, false));
    }

    /**
     * Test of Validator::isValidInteger.
     */
    public function testIsValidInteger()
    {
        $instance = ESAPI::getValidator();
        
        // testing negative range
        $this->assertFalse($instance->isValidInteger('test', '-4', 1, 10, false));
        $this->assertTrue($instance->isValidInteger('test', '-4', -10, 10, false));
        // testing null value
        $this->assertTrue($instance->isValidInteger('test', null, -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', null, -10, 10, false));
        // testing empty string
        $this->assertTrue($instance->isValidInteger('test', '', -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', '', -10, 10, false));
        // testing improper range
        $this->assertFalse($instance->isValidInteger('test', '5', 10, -10, false));
        // testing non-integers
        $this->assertFalse($instance->isValidInteger('test', '4.3214', -10, 10, true));
        $this->assertFalse($instance->isValidInteger('test', '-1.65', -10, 10, true));
        // other testing
        $this->assertTrue($instance->isValidInteger('test', '4', 1, 10, false));
        $this->assertTrue($instance->isValidInteger('test', '400', 1, 10000, false));
        $this->assertTrue($instance->isValidInteger('test', '400000000', 1, 400000000, false));
        $this->assertFalse($instance->isValidInteger('test', '4000000000000', 1, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'alsdkf', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '--10', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '14.1414234x', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '-Infinity', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', 'NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '-NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '+NaN', 10, 10000, false));
        $this->assertFalse($instance->isValidInteger('test', '1e-6', -999999999, 999999999, false));
        $this->assertFalse($instance->isValidInteger('test', '-1e-6', -999999999, 999999999, false));
    }

    /**
     * Test of Validator::isValidPrintable.
     */
    public function testIsValidPrintable()
    {
        $instance = ESAPI::getValidator();
        
        $this->assertTrue($instance->isValidPrintable('test', 'abcDEF', 100, false));
        
        $input = '';
        for ($i = 32; $i <= 126; $i++) {
            $input .= chr($i);
        }
        $this->assertTrue($instance->isValidPrintable('test', $input, 100, false));
        $this->assertTrue($instance->isValidPrintable('test', '!@#R()*$;><()', 100, false));
        
        $bytes = chr(0x60) . chr(0xFF) . chr(0x10) . chr(0x25);
        $this->assertFalse($instance->isValidPrintable('test', $bytes, 100, false));
        
        $this->assertFalse($instance->isValidPrintable('test', '%08', 100, false));
    }

    /**
     * Test of Validator::isValidDirectoryPath.
     */
    public function testIsValidDirectoryPath()
    {
        $instance = ESAPI::getValidator();

        if (substr(PHP_OS, 0, 3) == 'WIN') {
            // Windows paths that should pass
            $this->assertTrue($instance->isValidDirectoryPath('test', 'C:\\', false));                            // Windows root directory
            $this->assertTrue($instance->isValidDirectoryPath('test', 'C:\\Windows', false));                     // Windows always exist directory

            // Windows paths that don't exist and thus should fail
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\ridiculous', false));
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\temp\\..\\etc', false));

            // Windows path that exists but is not a directory
            $this->assertFalse($instance->isValidDirectoryPath('test', 'C:\\Windows\\System32\\cmd.exe', false)); // Windows command shell

            // Windows path that exists but is not canonical
            $this->assertFalse($instance->isValidDirectoryPath('test', 'C:\\Windows\\System32\\..', false));

            // Unix specific paths should not pass
            $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp', false));                           // Unix Temporary directory
            $this->assertFalse($instance->isValidDirectoryPath('test', '/bin/sh', false));                        // Unix Standard shell
            $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/config', false));

            // Unix specific paths that should not exist or work
            $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/ridiculous', false));
            $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp/../etc', false));
        } else {
            // Unix specific paths should pass
            $this->assertTrue($instance->isValidDirectoryPath('test', '/', false));                               // Root directory
            $this->assertTrue($instance->isValidDirectoryPath('test', '/bin', false));                            // Always exist directory

            // Unix specific path that exists but is not a directory
            $this->assertFalse($instance->isValidDirectoryPath('test', '/bin/sh', false));                        // Standard shell

            // Unix specific path that exists but is not canonical
            $this->assertFalse($instance->isValidDirectoryPath('test', '/bin/../', false));
            
            // Unix specific paths that should not exist or work
            $this->assertFalse($instance->isValidDirectoryPath('test', '/etc/ridiculous', false));
            $this->assertFalse($instance->isValidDirectoryPath('test', '/tmp/../etc', false));

            // Windows paths should fail
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\ridiculous', false));
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\temp\\..\\etc', false));

            // Standard Windows locations should fail
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\', false));                           // Windows root directory
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\Windows\\temp', false));              // Windows temporary directory
            $this->assertFalse($instance->isValidDirectoryPath('test', 'c:\\Windows\\System32\\cmd.exe', false)); // Windows command shell
        }
    }
}
