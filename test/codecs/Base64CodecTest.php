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

class Base64CodecTest extends PHPUnit_Framework_TestCase
{
    private $base64Codec;
    
    protected function setUp()
    {
        $this->base64Codec = new Base64Codec();
    }
        
    public function testEncode()
    {
        $this->assertEquals('Ij48c2NyaXB0PmFsZXJ0KC9YU1MvKTwvc2NyaXB0Pjxmb28gYXR0cj0i', $this->base64Codec->encode('"><script>alert(/XSS/)</script><foo attr="'));
    }
    
    public function testEncodeCharacter()
    {
        $this->assertEquals("PA==", $this->base64Codec->encode("<"));
    }
    
    public function testDecode()
    {
        $this->assertEquals('"><script>alert(/XSS/)</script><foo attr="', $this->base64Codec->decode('Ij48c2NyaXB0PmFsZXJ0KC9YU1MvKTwvc2NyaXB0Pjxmb28gYXR0cj0i'));
    }
        
    public function testDecodeCharacter()
    {
        $this->assertEquals("<", $this->base64Codec->decode("PA=="));
    }
}
