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

class OracleCodecTest extends PHPUnit_Framework_TestCase
{
    private $oracleCodec;
    
    protected function setUp()
    {
        $this->oracleCodec = new OracleCodec();
    }
        
    public function testEncode()
    {
        $immune = array();
        
        $this->assertEquals(' || \'\'x\'\' FROM DUAL;--', $this->oracleCodec->encode($immune, ' || \'x\' FROM DUAL;--'));
        $this->assertEquals('\'\'', $this->oracleCodec->encode($immune, '\''));
    }
    
    public function testEncodeCharacter()
    {
        $immune = array();
        
        $this->assertEquals("''", $this->oracleCodec->encode($immune, "'"));
    }
    
    public function testDecode()
    {
        $this->assertEquals(' || \'x\' FROM DUAL;--', $this->oracleCodec->decode(' || \'\'x\'\' FROM DUAL;--'));
        $this->assertEquals('\'', $this->oracleCodec->decode('\'\''));
    }
        
    public function testDecodeCharacter()
    {
        $this->assertEquals("'", $this->oracleCodec->decode("''"));
    }
}
