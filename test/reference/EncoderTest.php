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

/**
 *
 */

/**
 * Tests of DefaultEncoder methods.
 *
 * @author jah (at jaboite.co.uk)
 * @since  1.6
 */
class EncoderTest extends PHPUnit_Framework_TestCase
{
    private $encoderInstance = null;

    public function setUp()
    {
        global $ESAPI;

        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI(__DIR__.'/../testresources/ESAPI.xml');
        }
        
        $codecArray = array();
        array_push($codecArray, new HTMLEntityCodec());
        array_push($codecArray, new PercentCodec());
        $this->encoderInstance = new DefaultEncoder($codecArray);
    }

    public function tearDown()
    {
        // NoOp
    }

    /*
     * Test for exception thrown when DefaultEncoder is constructed with an array
     * containing an object other than a Codec instance.
     */
    public function testDefaultEncoderException()
    {
        $codecList = array();
        array_push($codecList, new HTMLEntityCodec());
        array_push($codecList, new Exception()); // any class except a codec will suffice.

        $this->setExpectedException('InvalidArgumentException');
        $instance = new DefaultEncoder($codecList);
    }

    /*
     * Test of canonicalize method of class Encoder.
     *
     * @throws EncodingException
     */
    public function testCanonicalize_001()
    {
        // This block sets-up the encoder for subsequent canonicalize tests
        $codecArray = array();
        array_push($codecArray, new HTMLEntityCodec());
        array_push($codecArray, new PercentCodec());
        $this->encoderInstance = new DefaultEncoder($codecArray);

        $this->assertEquals(null, $this->encoderInstance->canonicalize(null));
    }
    public function testCanonicalize_002()
    {
        $this->assertEquals(null, $this->encoderInstance->canonicalize(null, true));
    }
    public function testCanonicalize_003()
    {
        $this->assertEquals(null, $this->encoderInstance->canonicalize(null, false));
    }

    public function testCanonicalize_004()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("%25", true));
    }
    public function testCanonicalize_005()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("%25", false));
    }

    public function testCanonicalize_006()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("%25"));
    }
    public function testCanonicalize_007()
    {
        $this->assertEquals("%F", $this->encoderInstance->canonicalize("%25F"));
    }
    public function testCanonicalize_008()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%3c"));
    }
    public function testCanonicalize_009()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%3C"));
    }
    public function testCanonicalize_010()
    {
        $this->assertEquals("%X1", $this->encoderInstance->canonicalize("%X1"));
    }

    public function testCanonicalize_011()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lt"));
    }
    public function testCanonicalize_012()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&LT"));
    }
    public function testCanonicalize_013()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lt;"));
    }
    public function testCanonicalize_014()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&LT;"));
    }

    public function testCanonicalize_015()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("&#37;"));
    }
    public function testCanonicalize_016()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("&#37"));
    }
    public function testCanonicalize_017()
    {
        $this->assertEquals("%b", $this->encoderInstance->canonicalize("&#37b"));
    }
    public function testCanonicalize_018()
    {
        $this->assertEquals("%b", $this->encoderInstance->canonicalize("&#37;b"));
    }
    public function testCanonicalize_019()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3c"));
    }
    public function testCanonicalize_020()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3c;"));
    }
    public function testCanonicalize_021()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3C"));
    }
    public function testCanonicalize_022()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3c"));
    }
    public function testCanonicalize_023()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3C"));
    }
    public function testCanonicalize_024()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3C;"));
    }

    // percent encoding
    public function testCanonicalize_025()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%3c"));
    }
    public function testCanonicalize_026()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%3C"));
    }

    // html entity encoding
    public function testCanonicalize_027()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#60"));
    }
    public function testCanonicalize_028()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#060"));
    }
    public function testCanonicalize_029()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#0060"));
    }
    public function testCanonicalize_030()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#00060"));
    }
    public function testCanonicalize_031()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#000060"));
    }
    public function testCanonicalize_032()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#0000060"));
    }
    public function testCanonicalize_033()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#60;"));
    }
    public function testCanonicalize_034()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#060;"));
    }
    public function testCanonicalize_035()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#0060;"));
    }
    public function testCanonicalize_036()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#00060;"));
    }
    public function testCanonicalize_037()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#000060;"));
    }
    public function testCanonicalize_038()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#0000060;"));
    }
    public function testCanonicalize_039()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3c"));
    }
    public function testCanonicalize_040()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x03c"));
    }
    public function testCanonicalize_041()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x003c"));
    }
    public function testCanonicalize_042()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x0003c"));
    }
    public function testCanonicalize_043()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x00003c"));
    }
    public function testCanonicalize_044()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x000003c"));
    }
    public function testCanonicalize_045()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3c;"));
    }
    public function testCanonicalize_046()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x03c;"));
    }
    public function testCanonicalize_047()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x003c;"));
    }
    public function testCanonicalize_048()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x0003c;"));
    }
    public function testCanonicalize_049()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x00003c;"));
    }
    public function testCanonicalize_050()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x000003c;"));
    }
    public function testCanonicalize_051()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3c"));
    }
    public function testCanonicalize_052()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X03c"));
    }
    public function testCanonicalize_053()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X003c"));
    }
    public function testCanonicalize_054()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X0003c"));
    }
    public function testCanonicalize_055()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X00003c"));
    }
    public function testCanonicalize_056()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X000003c"));
    }
    public function testCanonicalize_057()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3c;"));
    }
    public function testCanonicalize_058()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X03c;"));
    }
    public function testCanonicalize_059()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X003c;"));
    }
    public function testCanonicalize_060()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X0003c;"));
    }
    public function testCanonicalize_061()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X00003c;"));
    }
    public function testCanonicalize_062()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X000003c;"));
    }
    public function testCanonicalize_063()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3C"));
    }
    public function testCanonicalize_064()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x03C"));
    }
    public function testCanonicalize_065()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x003C"));
    }
    public function testCanonicalize_066()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x0003C"));
    }
    public function testCanonicalize_067()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x00003C"));
    }
    public function testCanonicalize_068()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x000003C"));
    }
    public function testCanonicalize_069()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x3C;"));
    }
    public function testCanonicalize_070()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x03C;"));
    }
    public function testCanonicalize_071()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x003C;"));
    }
    public function testCanonicalize_072()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x0003C;"));
    }
    public function testCanonicalize_073()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x00003C;"));
    }
    public function testCanonicalize_074()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x000003C;"));
    }
    public function testCanonicalize_075()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3C"));
    }
    public function testCanonicalize_076()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X03C"));
    }
    public function testCanonicalize_077()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X003C"));
    }
    public function testCanonicalize_078()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X0003C"));
    }
    public function testCanonicalize_079()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X00003C"));
    }
    public function testCanonicalize_080()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X000003C"));
    }
    public function testCanonicalize_081()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X3C;"));
    }
    public function testCanonicalize_082()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X03C;"));
    }
    public function testCanonicalize_083()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X003C;"));
    }
    public function testCanonicalize_084()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X0003C;"));
    }
    public function testCanonicalize_085()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X00003C;"));
    }
    public function testCanonicalize_086()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#X000003C;"));
    }

    public function testCanonicalize_087()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lt"));
    }
    public function testCanonicalize_088()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lT"));
    }
    public function testCanonicalize_089()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&Lt"));
    }
    public function testCanonicalize_090()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&LT"));
    }
    public function testCanonicalize_091()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lt;"));
    }
    public function testCanonicalize_092()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&lT;"));
    }
    public function testCanonicalize_093()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&Lt;"));
    }
    public function testCanonicalize_094()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&LT;"));
    }

    public function testCanonicalize_095()
    {
        $this->assertEquals("<script>alert(\"hello\");</script>",
            $this->encoderInstance->canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
    }
    public function testCanonicalize_096()
    {
        $this->assertEquals("<script>alert(\"hello\");</script>",
            $this->encoderInstance->canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", false));
    }

    // javascript escape syntax
    //public function testCanonicalize_097()
    //{
    //    $this->encoderInstance = null;
    //    $this->encoderInstance = new DefaultEncoder(array(new JavaScriptCodec()));
    //
    //    $this->assertEquals("\0", $this->encoderInstance->canonicalize("\\0"));
    //}
    //public function testCanonicalize_098()
    //{
    //    $this->assertEquals("".chr(0x08), $this->encoderInstance->canonicalize("\\b"));
    //}
    //public function testCanonicalize_099()
    //{
    //    $this->assertEquals("\t", $this->encoderInstance->canonicalize("\\t"));
    //}
    //public function testCanonicalize_100()
    //{
    //    $this->assertEquals("\n", $this->encoderInstance->canonicalize("\\n"));
    //}
    //public function testCanonicalize_101()
    //{
    //    $this->assertEquals("".chr(0x0b), $this->encoderInstance->canonicalize("\\v"));
    //}
    //public function testCanonicalize_102()
    //{
    //    $this->assertEquals("".chr(0x0c), $this->encoderInstance->canonicalize("\\f"));
    //}
    //public function testCanonicalize_103()
    //{
    //    $this->assertEquals("\r", $this->encoderInstance->canonicalize("\\r"));
    //}
    //public function testCanonicalize_104()
    //{
    //    $this->assertEquals("'", $this->encoderInstance->canonicalize("\\'"));
    //}
    //public function testCanonicalize_105()
    //{
    //    $this->assertEquals("\"", $this->encoderInstance->canonicalize("\\\""));
    //}
    //public function testCanonicalize_106()
    //{
    //    $this->assertEquals("\\", $this->encoderInstance->canonicalize("\\\\"));
    //}
    public function testCanonicalize_107()
    {
        $this->encoderInstance = null;
        $this->encoderInstance = new DefaultEncoder(array(new JavaScriptCodec()));
    
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\<"));
    }
    public function testCanonicalize_108()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\u003c"));
    }
    public function testCanonicalize_109()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\U003c"));
    }
    public function testCanonicalize_110()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\u003C"));
    }
    public function testCanonicalize_111()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\U003C"));
    }
    public function testCanonicalize_112()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\x3c"));
    }
    public function testCanonicalize_113()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\X3c"));
    }
    public function testCanonicalize_114()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\x3C"));
    }
    public function testCanonicalize_115()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\X3C"));
    }

    // css escape syntax
    public function testCanonicalize_116()
    {
        $this->encoderInstance = null;
        $this->encoderInstance = new DefaultEncoder(array(new CSSCodec()));

        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\3c"));
    }
    public function testCanonicalize_117()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\03c"));
    }
    public function testCanonicalize_118()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\003c"));
    }
    public function testCanonicalize_119()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\0003c"));
    }
    public function testCanonicalize_120()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\00003c"));
    }
    public function testCanonicalize_121()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\3C"));
    }
    public function testCanonicalize_122()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\03C"));
    }
    public function testCanonicalize_123()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\003C"));
    }
    public function testCanonicalize_124()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\0003C"));
    }
    public function testCanonicalize_125()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("\\00003C"));
    }

    // note these examples use the strict=false flag on canonicalize to allow
    // full decoding without throwing an IntrusionException. Generally, you
    // should use strict mode as allowing double-encoding is an abomination.

    // double encoding examples
    public function testDoubleEncodingCanonicalization_01()
    {
        $this->encoderInstance = ESAPI::getEncoder();

        $this->assertEquals("<", $this->encoderInstance->canonicalize("&#x26;lt&#59", false)); //double entity
    }
    public function testDoubleEncodingCanonicalization_02()
    {
        $this->assertEquals("\\", $this->encoderInstance->canonicalize("%255c", false)); //double percent
    }
    public function testDoubleEncodingCanonicalization_03()
    {
        $this->assertEquals("%", $this->encoderInstance->canonicalize("%2525", false)); //double percent
    }

    // double encoding with multiple schemes example
    public function testDoubleEncodingCanonicalization_04()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%26lt%3b", false)); //first entity, then percent
    }
    public function testDoubleEncodingCanonicalization_05()
    {
        $this->assertEquals("&", $this->encoderInstance->canonicalize("&#x25;26", false)); //first percent, then entity
    }

    // nested encoding examples
    public function testDoubleEncodingCanonicalization_06()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%253c", false)); //nested encode % with percent
    }
    public function testDoubleEncodingCanonicalization_07()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%%33%63", false)); //nested encode both nibbles with percent
    }
    public function testDoubleEncodingCanonicalization_08()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%%33c", false)); // nested encode first nibble with percent
    }
    public function testDoubleEncodingCanonicalization_09()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%3%63", false));  //nested encode second nibble with percent
    }
    public function testDoubleEncodingCanonicalization_10()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&&#108;t;", false)); //nested encode l with entity
    }
    public function testDoubleEncodingCanonicalization_11()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%2&#x35;3c", false)); //triple percent, percent, 5 with entity
    }

    // nested encoding with multiple schemes examples
    public function testDoubleEncodingCanonicalization_12()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("&%6ct;", false)); // nested encode l with percent
    }
    public function testDoubleEncodingCanonicalization_13()
    {
        $this->assertEquals("<", $this->encoderInstance->canonicalize("%&#x33;c", false)); //nested encode 3 with entity
    }

    // multiple encoding tests
    public function testDoubleEncodingCanonicalization_14()
    {
        $this->assertEquals("% & <script> <script>", $this->encoderInstance->canonicalize("%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false));
    }
    public function testDoubleEncodingCanonicalization_15()
    {
        $this->assertEquals("< < < < < < <", $this->encoderInstance->canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false));
    }

    // test strict mode with both mixed and multiple encoding
    public function testDoubleEncodingCanonicalization_16()
    {
        $this->setExpectedException('IntrusionException');
        $this->encoderInstance->canonicalize('%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B');
    }
    public function testDoubleEncodingCanonicalization_17()
    {
        $this->setExpectedException('IntrusionException');
        $this->encoderInstance->canonicalize('%253Cscript');
    }
    public function testDoubleEncodingCanonicalization_18()
    {
        $this->setExpectedException('IntrusionException');
        $this->encoderInstance->canonicalize('&#37;3Cscript');
    }

    /*
     * Test of encodeForHTML method of class Encoder.
     *
     * @throws Exception
     */
    public function testEncodeForHTML_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForHTML(null));
    }
    public function testEncodeForHTML_02()
    {
        $instance = ESAPI::getEncoder();
        // test invalid characters are replaced with spaces
        $this->assertEquals("a b c d e f&#x9;g", $instance->encodeForHTML("a".(chr(0))."b".(chr(4))."c".(chr(128))."d".(chr(150))."e".(chr(159))."f".(chr(9))."g"));
    }
    public function testEncodeForHTML_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("a b c d e f&#x9;g h i j&nbsp;k&iexcl;l&cent;m", $instance->encodeForHTML("a".(chr(0))."b".(chr(4))."c".(chr(128))."d".(chr(150))."e".(chr(159))."f".(chr(9))."g".(chr(127))."h".(chr(129))."i".(chr(159))."j".(chr(160))."k".(chr(161))."l".(chr(162))."m"));
    }
    public function testEncodeForHTML_04()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&lt;script&gt;", $instance->encodeForHTML("<script>"));
    }
    public function testEncodeForHTML_05()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", $instance->encodeForHTML("&lt;script&gt;"));
    }
    public function testEncodeForHTML_06()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTML("!@$%()=+{}[]"));
    }
    public function testEncodeForHTML_07()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTML($instance->canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", false)));
    }
    public function testEncodeForHTML_08()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(",.-_ ", $instance->encodeForHTML(",.-_ "));
    }
    public function testEncodeForHTML_09()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("dir&amp;", $instance->encodeForHTML("dir&"));
    }
    public function testEncodeForHTML_10()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("one&amp;two", $instance->encodeForHTML("one&two"));
    }
    public function testEncodeForHTML_11()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("".(chr(12345)).(chr(65533)).(chr(1244)), "".(chr(12345)).(chr(65533)).(chr(1244)));
    }

    /*
     * Test of encodeForHTMLAttribute method of class Encoder.
     */
    public function testEncodeForHTMLAttribute_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForHTMLAttribute(null));
    }
    public function testEncodeForHTMLAttribute_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&lt;script&gt;", $instance->encodeForHTMLAttribute("<script>"));
    }
    public function testEncodeForHTMLAttribute_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(",.-_", $instance->encodeForHTMLAttribute(",.-_"));
    }
    public function testEncodeForHTMLAttribute_04()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTMLAttribute(" !@$%()=+{}[]"));
    }

    /*
     * Test of encodeForCSS method of class Encoder.
     */
    public function testEncodeForCSS_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForCSS(null));
    }
    public function testEncodeForCSS_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\3c script\\3e ", $instance->encodeForCSS("<script>"));
    }
    public function testEncodeForCSS_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ", $instance->encodeForCSS("!@$%()=+{}[]"));
    }

    /*
     * Test of encodeForJavaScript method of class Encoder.
     * Note that JavaScriptCodec is closer to ESAPI 2 for Java and so these
     * tests are taken from that version.
     */
    public function testEncodeForJavascript_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForJavaScript(null));
    }
    public function testEncodeForJavascript_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\x3Cscript\\x3E", $instance->encodeForJavaScript("<script>"));
    }
    public function testEncodeForJavascript_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(",.\\x2D_\\x20", $instance->encodeForJavaScript(",.-_ "));
    }
    public function testEncodeForJavascript_04()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", $instance->encodeForJavaScript("!@$%()=+{}[]"));
    }
    public function testEncodeForJavascript_05()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\x00", $instance->encodeForJavaScript("\0"));
    }
    public function testEncodeForJavascript_06()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("\\x5C", $instance->encodeForJavaScript("\\"));
    }

    /*
     * Test of encodeForVBScript method of class Encoder.
     */
    public function testEncodeForVBScript_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForVBScript(null));
    }
    public function testEncodeForVBScript_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('""', $instance->encodeForVBScript('"'));
    }
    public function testEncodeForVBScript_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('"<script">', $instance->encodeForVBScript('<script>'));
    }
    public function testEncodeForVBScript_04()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(' "!"@"$"%"(")"="+"{"}"["]""', $instance->encodeForVBScript(' !@$%()=+{}[]"'));
    }

    /*
     * Test of encodeForXPath method of class Encoder.
     */
    public function testEncodeForXPath_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForXPath(null));
    }
    public function testEncodeForXPath_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x27;or 1&#x3d;1", $instance->encodeForXPath("'or 1=1"));
    }

    /*
     * Test of encodeForSQL method of class Encoder.
     */
    public function testEncodeForSQL_MySQL_ANSI_01()
    {
        $instance = ESAPI::getEncoder();
        $mysqlAnsiCodec = new MySQLCodec(MySQLCodec::MYSQL_ANSI);
        $this->assertEquals(null, $instance->encodeForSQL($mysqlAnsiCodec, null));
    }
    public function testEncodeForSQL_MySQL_ANSI_02()
    {
        $instance = ESAPI::getEncoder();
        $mysqlAnsiCodec = new MySQLCodec(MySQLCodec::MYSQL_ANSI);
        $this->assertEquals("Jeff'' or ''1''=''1", $instance->encodeForSQL($mysqlAnsiCodec, "Jeff' or '1'='1"));
    }
    public function testEncodeForSQL_MySQL_STD_01()
    {
        $instance = ESAPI::getEncoder();
        $mysqlStdCodec = new MySQLCodec(MySQLCodec::MYSQL_STD);
        $this->assertEquals(null, $instance->encodeForSQL($mysqlStdCodec, null));
    }
    public function testEncodeForSQL_MySQL_STD_02()
    {
        $instance = ESAPI::getEncoder();
        $mysqlStdCodec = new MySQLCodec(MySQLCodec::MYSQL_STD);
        $this->assertEquals("Jeff\\' or \\'1\\'\\=\\'1", $instance->encodeForSQL($mysqlStdCodec, "Jeff' or '1'='1"));
    }
    public function testEncodeForSQL_MySQL_STD_03()
    {
        $instance = ESAPI::getEncoder();
        $mysqlStdCodec = new MySQLCodec(MySQLCodec::MYSQL_STD);
        $this->assertEquals("\\b \\n \\r \\t \\Z \\_ \\\" \\' \\\\ \\0 \\%", $instance->encodeForSQL($mysqlStdCodec, "\x08 \x0a \x0d \x09 \x1a _ \" ' \\ \x00 \x25"));
    }
    public function testEncodeForSQL_Oracle01()
    {
        $instance = ESAPI::getEncoder();
        $oracleCodec = new OracleCodec();
        $this->assertEquals(null, $instance->encodeForSQL($oracleCodec, null));
    }
    public function testEncodeForSQL_Oracle02()
    {
        $instance = ESAPI::getEncoder();
        $oracleCodec = new OracleCodec();
        $this->assertEquals("Jeff'' or ''1''=''1", $instance->encodeForSQL($oracleCodec, "Jeff' or '1'='1"));
    }

    /*
     * Test of encodeForLDAP method of class Encoder.
     */
    public function testEncodeForLDAP_01()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForLDAP");
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForLDAP(null));
        */
    }
    public function testEncodeForLDAP_02()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForLDAP");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("No special characters to escape", "Hi This is a test #��", $instance->encodeForLDAP("Hi This is a test #��"));
        */
    }
    public function testEncodeForLDAP_03()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForLDAP");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("Zeros", "Hi \\00", $instance->encodeForLDAP("Hi \u0000"));
        */
    }
    public function testEncodeForLDAP_04()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForLDAP");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # � � �", $instance->encodeForLDAP("Hi (This) = is * a \\ test # � � �"));
        */
    }

    /*
     * Test of encodeForDN method of class Encoder.
     */
    public function testEncodeForDN_01()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForDN(null));
        */
    }
    public function testEncodeForDN_02()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("No special characters to escape", "Hello�", $instance->encodeForDN("Hello�"));
        */
    }
    public function testEncodeForDN_03()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("leading #", "\\# Hello�", $instance->encodeForDN("# Hello�"));
        */
    }
    public function testEncodeForDN_04()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("leading space", "\\ Hello�", $instance->encodeForDN(" Hello�"));
        */
    }
    public function testEncodeForDN_05()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("trailing space", "Hello�\\ ", $instance->encodeForDN("Hello� "));
        */
    }
    public function testEncodeForDN_06()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("less than greater than", "Hello\\<\\>", $instance->encodeForDN("Hello<>"));
        */
    }
    public function testEncodeForDN_07()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("only 3 spaces", "\\  \\ ", $instance->encodeForDN("   "));
        */
    }
    public function testEncodeForDN_08()
    {
        $this->markTestIncomplete('This test has not been implemented yet.'); /* DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();
        $this->assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", $instance->encodeForDN(" Hello\\ + , \"World\" ; "));
        */
    }

    /*
     * Test of encodeForXML method of class Encoder.
     */
    public function testEncodeForXML_null()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForXML(null));
    }
    public function testEncodeForXML_space()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(' ', $instance->encodeForXML(' '));
    }
    public function testEncodeForXML_scripttag()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('&lt;script&gt;', $instance->encodeForXML('<script>'));
    }
    public function testEncodeForXML_immune()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(',.-_', $instance->encodeForXML(',.-_'));
    }
    public function testEncodeForXML_symbols()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;', $instance->encodeForXML('!@$%()=+{}[]'));
    }
    public function testEncodeForXML_pound()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('&#xa3;', $instance->encodeForXML("\xA3"));
    }

    /*
     * Test of encodeForXMLAttribute method of class Encoder.
     */
    public function testEncodeForXMLAttribute_null()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForXMLAttribute(null));
    }
    public function testEncodeForXMLAttribute_space()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x20;", $instance->encodeForXMLAttribute(" "));
    }
    public function testEncodeForXMLAttribute_scripttag()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&lt;script&gt;", $instance->encodeForXMLAttribute("<script>"));
    }
    public function testEncodeForXMLAttribute_immune()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(",.-_", $instance->encodeForXMLAttribute(",.-_"));
    }
    public function testEncodeForXMLAttribute_symbols()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForXMLAttribute(" !@$%()=+{}[]"));
    }
    public function testEncodeForXMLAttribute_pound()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('&#xa3;', $instance->encodeForXMLAttribute("\xA3"));
    }

    /*
     * Test of encodeForURL method of class Encoder.
     */
    public function testEncodeForURL_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForURL(null));
    }
    public function testEncodeForURL_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("%3Cscript%3E", $instance->encodeForURL("<script>"));
    }
    public function testEncodeForURL_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("+", $instance->encodeForURL(" "));
    }

    /*
     * Test of decodeFromURL method, of class Encoder.
     */
    public function testDecodeFromURL_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->decodeFromURL(null));
    }
    public function testDecodeFromURL_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("<script>", $instance->decodeFromURL("%3Cscript%3E"));
    }
    public function testDecodeFromURL_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals("     ", $instance->decodeFromURL("+++++"));
    }

    /*
     * Test of encodeForBase64 method of class Encoder.
     */
    public function testEncodeForBase64_01()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForBase64(null, false));
    }
    public function testEncodeForBase64_02()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->encodeForBase64(null, true));
    }
    public function testEncodeForBase64_03()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(null, $instance->decodeFromBase64(null));
    }
    // Test wrapping at 76 chars
    public function testEncodeForBase64_04()
    {
        $instance = ESAPI::getEncoder();
        $unencoded = ESAPI::getRandomizer()->getRandomString(76, Encoder::CHAR_SPECIALS);
        $encoded = $instance->encodeForBase64($unencoded, false);
        $encodedWrapped = $instance->encodeForBase64($unencoded, true);
        $expected = mb_substr($encoded, 0, 76, 'ASCII') . "\r\n" . mb_substr($encoded, 76, mb_strlen($encoded, 'ASCII')-76, 'ASCII');
        $this->assertEquals($expected, $encodedWrapped);
    }
    public function testEncodeForBase64_05()
    {
        $instance = ESAPI::getEncoder();
        try {
            for ($i = 0; $i < 100; $i++) {
                $unencoded = ESAPI::getRandomizer()->getRandomString(20, Encoder::CHAR_SPECIALS);
                $encoded = $instance->encodeForBase64($unencoded, ESAPI::getRandomizer()->getRandomBoolean());
                $decoded = $instance->decodeFromBase64($encoded);
                $this->assertEquals($unencoded, $decoded);
            }
        } catch (Exception $unexpected) {
            $this->fail();
        }
    }

    /*
     * Test of decodeFromBase64 method, of class Encoder.
     */
    public function testDecodeFromBase64_01()
    {
        $instance = ESAPI::getEncoder();
        for ($i = 0; $i < 100; $i++) {
            try {
                $unencoded = ESAPI::getRandomizer()->getRandomString(20, Encoder::CHAR_SPECIALS);
                $encoded = $instance->encodeForBase64($unencoded, ESAPI::getRandomizer()->getRandomBoolean());
                $decoded = $instance->decodeFromBase64($encoded);
                $this->assertEquals($unencoded, $decoded);
            } catch (Exception $unexpected) {
                $this->fail();
            }
        }
        for ($i = 0; $i < 100; $i++) {
            try {
                // get a string of 20 char_specials.
                $unencoded = ESAPI::getRandomizer()->getRandomString(20, Encoder::CHAR_SPECIALS);
                // encode the string of char_specials and then prepend an alplanum
                $encoded = ESAPI::getRandomizer()->getRandomString(1, Encoder::CHAR_ALPHANUMERICS) . $instance->encodeForBase64($unencoded, ESAPI::getRandomizer()->getRandomBoolean());
                // decoding the encoded (and prepended to) string
                $decoded = $instance->decodeFromBase64($encoded);
                // the decoded result should not equal the original string of 20 char_specials.
                $this->assertNotEquals($unencoded, $decoded);
            } catch (Exception $unexpected) {
                $this->fail();  // Note: java expects an IO exception, but base64_decode() doesn't throw one
            }
        }
    }

    public function testDecodeSingleCharacter_NumeralZero()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('0'));
    }
    public function testDecodeSingleCharacter_NumeralOne()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('1'));
    }
    public function testDecodeSingleCharacter_AlphaLower()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('a'));
    }
    public function testDecodeSingleCharacter_AlphaUpper()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('A'));
    }
    public function testDecodeSingleCharacter_CharBackslash()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('\\'));
    }
    public function testDecodeSingleCharacter_CharPlus()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('+'));
    }
    public function testDecodeSingleCharacter_CharPad()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('='));
    }
    public function testDecodeSingleInvalidCharacter_CharHyphen()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals('', $instance->decodeFromBase64('-'));
    }

    /*
     * Test of WindowsCodec
     */
    public function testWindowsCodec_01()
    {
        $instance = ESAPI::getEncoder();
        $codec_win = new WindowsCodec();
        $this->assertEquals(null, $instance->encodeForOS($codec_win, null));
    }
    public function testWindowsCodec_02()
    {
        $codec_win = new WindowsCodec();
        $decoded = $codec_win->decodeCharacter(Codec::normalizeEncoding("n"));
        $this->assertEquals(null, $decoded['decodedCharacter']);
    }
    public function testWindowsCodec_03()
    {
        $codec_win = new WindowsCodec();
        $decoded = $codec_win->decodeCharacter(Codec::normalizeEncoding(""));
        $this->assertEquals(null, $decoded['decodedCharacter']);
    }
    public function testWindowsCodec_04()
    {
        $codec_win = new WindowsCodec();

        $immune = array("\0"); // not that it matters, but the java test would encode alphanums with such an immune param.

        $encoded = $codec_win->encodeCharacter($immune, "<");
        $decoded = $codec_win->decode($encoded);
        $this->assertEquals("<", $decoded);
    }
    public function testWindowsCodec_05()
    {
        $codec_win = new WindowsCodec();

        $orig = "c:\\jeff";

        $this->assertEquals($orig, $codec_win->decode($orig));
    }
    public function testWindowsCodec_06()
    {
        $codec_win = new WindowsCodec();

        $immune = array();
        $orig = "c:\\jeff";
        $encoded = $codec_win->encode($immune, $orig);

        $this->assertEquals($orig, $codec_win->decode($encoded));
    }
    public function testWindowsCodec_07()
    {
        $codec_win = new WindowsCodec();
        $instance = ESAPI::getEncoder();

        $this->assertEquals("c^:^\\jeff", $instance->encodeForOS($codec_win, "c:\\jeff"));
    }
    public function testWindowsCodec_08()
    {
        $codec_win = new WindowsCodec();

        $immune = array();

        $this->assertEquals("c^:^\\jeff", $codec_win->encode($immune, "c:\\jeff"));
    }
    public function testWindowsCodec_09()
    {
        $codec_win = new WindowsCodec();
        $instance = ESAPI::getEncoder();

        $this->assertEquals("dir^ ^&^ foo", $instance->encodeForOS($codec_win, "dir & foo"));
    }
    public function testWindowsCodec_10()
    {
        $codec_win = new WindowsCodec();

        $immune = array();

        $this->assertEquals("dir^ ^&^ foo", $codec_win->encode($immune, "dir & foo"));
    }

    /*
     * Test of UnixCodec
     */
    public function testUnixCodec_01()
    {
        $instance = ESAPI::getEncoder();
        $codec_unix = new UnixCodec();
        $this->assertEquals(null, $instance->encodeForOS($codec_unix, null));
    }
    public function testUnixCodec_02()
    {
        $codec_unix = new UnixCodec();
        $decoded = $codec_unix->decodeCharacter(Codec::normalizeEncoding("n"));
        $this->assertEquals(null, $decoded['decodedCharacter']);
    }
    public function testUnixCodec_03()
    {
        $codec_unix = new UnixCodec();
        $decoded = $codec_unix->decodeCharacter(Codec::normalizeEncoding(""));
        $this->assertEquals(null, $decoded['decodedCharacter']);
    }
    public function testUnixCodec_04()
    {
        $codec_unix = new UnixCodec();

        $immune = array("\0"); // not that it matters, but the java test would encode alphanums with such an immune param.

        $encoded = $codec_unix->encodeCharacter($immune, "<");
        $decoded = $codec_unix->decode($encoded);
        $this->assertEquals("<", $decoded);
    }
    public function testUnixCodec_05()
    {
        $codec_unix = new UnixCodec();

        $orig = "/etc/passwd";

        $this->assertEquals($orig, $codec_unix->decode($orig));
    }
    public function testUnixCodec_06()
    {
        $codec_unix = new UnixCodec();

        $immune = array();
        $orig = "/etc/passwd";
        $encoded = $codec_unix->encode($immune, $orig);

        $this->assertEquals($orig, $codec_unix->decode($encoded));
    }
    public function testUnixCodec_07()
    {
        $codec_unix = new UnixCodec();
        $instance = ESAPI::getEncoder();

        // TODO: Check that this is acceptable for Unix hosts
        $this->assertEquals("c\\:\\\\jeff", $instance->encodeForOS($codec_unix, "c:\\jeff"));
    }
    public function testUnixCodec_08()
    {
        $codec_unix = new UnixCodec();

        $immune = array();

        // TODO: Check that this is acceptable for Unix hosts
        $this->assertEquals("c\\:\\\\jeff", $codec_unix->encode($immune, "c:\\jeff"));
    }
    public function testUnixCodec_09()
    {
        $codec_unix = new UnixCodec();
        $instance = ESAPI::getEncoder();

        // TODO: Check that this is acceptable for Unix hosts
        $this->assertEquals("dir\\ \\&\\ foo", $instance->encodeForOS($codec_unix, "dir & foo"));
    }
    public function testUnixCodec_10()
    {
        $codec_unix = new UnixCodec();

        $immune = array();

        // TODO: Check that this is acceptable for Unix hosts
        $this->assertEquals("dir\\ \\&\\ foo", $codec_unix->encode($immune, "dir & foo"));
    }
    // Unix paths (that must be encoded safely)
    public function testUnixCodec_11()
    {
        $codec_unix = new UnixCodec();
        $instance = ESAPI::getEncoder();

        $immune = array();

        // TODO: Check that this is acceptable for Unix
        $this->assertEquals("\\/etc\\/hosts", $instance->encodeForOS($codec_unix, "/etc/hosts"));
    }
    public function testUnixCodec_12()
    {
        $codec_unix = new UnixCodec();
        $instance = ESAPI::getEncoder();

        $immune = array();

        // TODO: Check that this is acceptable for Unix
        $this->assertEquals("\\/etc\\/hosts\\;\\ ls\\ -l", $instance->encodeForOS($codec_unix, "/etc/hosts; ls -l"));
    }

    // these tests check that mixed character encoding is handled properly when
    // encoding.
    public function testCharsForBase64()
    {
        $instance = $this->encoderInstance;
        $expected = '/^[a-zA-Z0-9\/+]*={0,2}$/';
        for ($i = 0; $i<256; $i++) {
            $input = chr($i);
            $output = $instance->encodeForBase64($input);
            $this->assertRegExp($expected, $output, "Input was character with ordinal: {$i} - %s");
            $this->assertEquals($input, $instance->decodeFromBase64($output));
        }
    }
    public function testCharsPlusAlphaForBase64()
    {
        $instance = $this->encoderInstance;
        $expected = '/^[a-zA-Z0-9\/+]*={0,2}$/';
        for ($i = 0; $i < 256; $i++) {
            $input = 'a' . chr($i);
            $output = $instance->encodeForBase64($input);
            $this->assertRegExp($expected, $output, "Input was 'a' concat with character with ordinal: {$i} - %s");
            $this->assertEquals($input, $instance->decodeFromBase64($output));
        }
    }
    public function testCharsPlusUnicodeForBase64()
    {
        $instance = $this->encoderInstance;
        $expected = '/^[a-zA-Z0-9\/+]*={0,2}$/';
        for ($i = 0; $i < 256; $i++) {
            $input = 'ϑ' . chr($i);
            $output = $instance->encodeForBase64($input);
            $this->assertRegExp($expected, $output, "Input was char known as '&thetasym;' concat with character with ordinal: {$i} - %s");
            $this->assertEquals($input, $instance->decodeFromBase64($output));
        }
    }

    public function testCharsForCSS()
    {
        $instance = new CSSCodec();
        for ($i = 1; $i < 256; $i++) {
            if (($i >= 0x30 && $i <= 0x39)
                || ($i >= 0x41 && $i <= 0x5a)
                || ($i >= 0x61 && $i <= 0x7a)
            ) {
                $expected = chr($i);
            } else {
                $expected = '\\' . dechex($i) . ' ';
            }
            $this->assertEquals($expected, $instance->encode(array(), chr($i)));
            $input = $expected;
            if ($i <= 127) {
                $expected = mb_convert_encoding(chr($i), 'UTF-8', 'ASCII');
            } else {
                $expected = mb_convert_encoding(chr($i), 'UTF-8', 'ISO-8859-1');
            }
            
            $this->assertEquals($expected, $instance->decode($input));
        }
    }
    public function testCharsPlusAlphaForCSS()
    {
        $instance = new CSSCodec();
        for ($i = 1; $i < 256; $i++) {
            // expected to take account of non encoding of alphanums
            if (($i >= 0x30 && $i <= 0x39)
                || ($i >= 0x41 && $i <= 0x5a)
                || ($i >= 0x61 && $i <= 0x7a)
            ) {
                $expected = 'a' . chr($i);
            } else {
                $expected = 'a\\' . dechex($i) . ' ';
            }
            $this->assertEquals($expected, $instance->encode(array(), 'a' . chr($i)));
            $input = $expected;
            if ($i <= 127) {
                $expected = 'a' . mb_convert_encoding(chr($i), 'UTF-8', 'ASCII');
            } else {
                $expected = 'a' . mb_convert_encoding(chr($i), 'UTF-8', 'ISO-8859-1');
            }
            $this->assertEquals($expected, $instance->decode($input));
        }
    }
    public function testCharsPlusUnicodeForCSS()
    {
        $instance = new CSSCodec();
        for ($i = 1; $i < 256; $i++) {
            $input = 'ϑ' . chr($i);
            // expected to take account of non-encoding of alphanums
            if (($i >= 0x30 && $i <= 0x39)
                || ($i >= 0x41 && $i <= 0x5a)
                || ($i >= 0x61 && $i <= 0x7a)
            ) {
                $expected = '\\3d1 ' . chr($i);
            } else {
                $expected = '\\3d1 \\' . dechex($i) . ' ';
            }
            $this->assertEquals($expected, $instance->encode(array(), $input));
            $input = $expected;
            if ($i <= 127) {
                $expected = 'ϑ' . mb_convert_encoding(chr($i), 'UTF-8', 'ASCII');
            } else {
                $expected = 'ϑ' . mb_convert_encoding(chr($i), 'UTF-8', 'ISO-8859-1');
            }
            $this->assertEquals($expected, $instance->decode($input));
        }
    }
}
