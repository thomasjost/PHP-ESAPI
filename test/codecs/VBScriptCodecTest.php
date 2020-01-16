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
namespace PHPESAPI\PHPESAPI\Test\Codecs;

class VBScriptCodecTest extends \PHPUnit\Framework\TestCase
{
    private $vbScriptCodec;

    protected function setUp()
    {
        $this->vbScriptCodec = new \PHPESAPI\PHPESAPI\Codecs\VBScriptCodec();
    }

    public function testEncode()
    {
        $immune = array(" ");

        $this->assertEquals(" \"!\"@\"$\"%\"(\")\"=\"+\"{\"}\"[\"]\"\"\"<script\">", $this->vbScriptCodec->encode($immune, " !@$%()=+{}[]\"<script>"));
    }

    public function testEncodeCharacter()
    {
        $immune = array(" ");

        $this->assertEquals("\"<", $this->vbScriptCodec->encode($immune, "<"));
    }

    public function testDecode()
    {
        $this->assertEquals(" !@$%()=+{}[]\"", $this->vbScriptCodec->decode(" \"!\"@\"$\"%\"(\")\"=\"+\"{\"}\"[\"]\"\""));
    }

    public function testDecodeCharacter()
    {
        $this->assertEquals("<", $this->vbScriptCodec->decode("\"<"));
    }
}
