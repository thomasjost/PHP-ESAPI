<?php
/**
 * OWASP Enterprise Security API (ESAPI)
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
 * @author Andrew van der Stock < van der aj ( at ) owasp. org >
 * @created 2009
 */

class UnixCodecTest extends PHPUnit_Framework_TestCase
{
    private $unixCodec;
    
    protected function setUp()
    {
        $this->unixCodec = new UnixCodec();
    }

    public function testEncode()
    {
        $immune = array();
        
        $this->assertEquals('\\"\\;\\ ls\\ \\/\\ \\>\\ \\/tmp\\/foo\\;\\ \\#\\ ', $this->unixCodec->encode($immune, '"; ls / > /tmp/foo; # '));
    }
    
    public function testEncodeCharacter()
    {
        $immune = array();
        
        $this->assertEquals("\\<", $this->unixCodec->encode($immune, "<"));
    }
    
    public function testDecode()
    {
        $this->assertEquals('"; ls / > /tmp/foo; # ', $this->unixCodec->decode('\\"\\;\\ ls\\ \\/\\ \\>\\ \\/tmp\\/foo\\;\\ \\#\\ '));
    }
        
    public function testDecodeCharacter()
    {
        $this->assertEquals("<", $this->unixCodec->decode("\\<"));
    }
}
