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
 * Tests of DefaultEncoder methods.
 *
 * @author jah (at jaboite.co.uk)
 * @since  1.6
 */
class EncoderTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test for exception thrown when DefaultEncoder is constructed with an array
     * containing an object other than a Codec instance.
     */
    public function testDefaultEncoderException()
    {
        $codecList = array(
            new HTMLEntityCodec(),
            new Exception() // any class except a codec will suffice.
        );

        $this->setExpectedException('InvalidArgumentException');
        $instance = new DefaultEncoder($codecList);
    }

    /**
     * Test of canonicalize method of class Encoder.
     *
     * @throws EncodingException
     */
    public function testCanonicalize()
    {
        // This block sets-up the encoder for subsequent canonicalize tests
        $instance = new DefaultEncoder(array(
            new HTMLEntityCodec(),
            new PercentCodec()
        ));

        // Test null paths
        $this->assertEquals(null, $instance->canonicalize(null));
        $this->assertEquals(null, $instance->canonicalize(null, true));
        $this->assertEquals(null, $instance->canonicalize(null, false));

        // Test exception paths
        $this->assertEquals("%", $instance->canonicalize("%25", true));
        $this->assertEquals("%", $instance->canonicalize("%25", false));
        
        $this->assertEquals("%", $instance->canonicalize("%25"));
        $this->assertEquals("%F", $instance->canonicalize("%25F"));
        $this->assertEquals("<", $instance->canonicalize("%3c"));
        $this->assertEquals("<", $instance->canonicalize("%3C"));
        $this->assertEquals("%X1", $instance->canonicalize("%X1"));
        
        $this->assertEquals("<", $instance->canonicalize("&lt"));
        $this->assertEquals("<", $instance->canonicalize("&LT"));
        $this->assertEquals("<", $instance->canonicalize("&lt;"));
        $this->assertEquals("<", $instance->canonicalize("&LT;"));
        
        $this->assertEquals("%", $instance->canonicalize("&#37;"));
        $this->assertEquals("%", $instance->canonicalize("&#37"));
        $this->assertEquals("%b", $instance->canonicalize("&#37b"));
        $this->assertEquals("%b", $instance->canonicalize("&#37;b"));
        
        $this->assertEquals("<", $instance->canonicalize("&#x3c"));
        $this->assertEquals("<", $instance->canonicalize("&#x3c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x3C"));
        $this->assertEquals("<", $instance->canonicalize("&#X3c"));
        $this->assertEquals("<", $instance->canonicalize("&#X3C"));
        $this->assertEquals("<", $instance->canonicalize("&#X3C;"));
        
        // percent encoding
        $this->assertEquals("<", $instance->canonicalize("%3c"));
        $this->assertEquals("<", $instance->canonicalize("%3C"));
        
        // html entity encoding
        $this->assertEquals("<", $instance->canonicalize("&#60"));
        $this->assertEquals("<", $instance->canonicalize("&#060"));
        $this->assertEquals("<", $instance->canonicalize("&#0060"));
        $this->assertEquals("<", $instance->canonicalize("&#00060"));
        $this->assertEquals("<", $instance->canonicalize("&#000060"));
        $this->assertEquals("<", $instance->canonicalize("&#0000060"));
        $this->assertEquals("<", $instance->canonicalize("&#60;"));
        $this->assertEquals("<", $instance->canonicalize("&#060;"));
        $this->assertEquals("<", $instance->canonicalize("&#0060;"));
        $this->assertEquals("<", $instance->canonicalize("&#00060;"));
        $this->assertEquals("<", $instance->canonicalize("&#000060;"));
        $this->assertEquals("<", $instance->canonicalize("&#0000060;"));
        $this->assertEquals("<", $instance->canonicalize("&#x3c"));
        $this->assertEquals("<", $instance->canonicalize("&#x03c"));
        $this->assertEquals("<", $instance->canonicalize("&#x003c"));
        $this->assertEquals("<", $instance->canonicalize("&#x0003c"));
        $this->assertEquals("<", $instance->canonicalize("&#x00003c"));
        $this->assertEquals("<", $instance->canonicalize("&#x000003c"));
        $this->assertEquals("<", $instance->canonicalize("&#x3c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x03c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x0003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x00003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x000003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X3c"));
        $this->assertEquals("<", $instance->canonicalize("&#X03c"));
        $this->assertEquals("<", $instance->canonicalize("&#X003c"));
        $this->assertEquals("<", $instance->canonicalize("&#X0003c"));
        $this->assertEquals("<", $instance->canonicalize("&#X00003c"));
        $this->assertEquals("<", $instance->canonicalize("&#X000003c"));
        $this->assertEquals("<", $instance->canonicalize("&#X3c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X03c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X0003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X00003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#X000003c;"));
        $this->assertEquals("<", $instance->canonicalize("&#x3C"));
        $this->assertEquals("<", $instance->canonicalize("&#x03C"));
        $this->assertEquals("<", $instance->canonicalize("&#x003C"));
        $this->assertEquals("<", $instance->canonicalize("&#x0003C"));
        $this->assertEquals("<", $instance->canonicalize("&#x00003C"));
        $this->assertEquals("<", $instance->canonicalize("&#x000003C"));
        $this->assertEquals("<", $instance->canonicalize("&#x3C;"));
        $this->assertEquals("<", $instance->canonicalize("&#x03C;"));
        $this->assertEquals("<", $instance->canonicalize("&#x003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#x0003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#x00003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#x000003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X3C"));
        $this->assertEquals("<", $instance->canonicalize("&#X03C"));
        $this->assertEquals("<", $instance->canonicalize("&#X003C"));
        $this->assertEquals("<", $instance->canonicalize("&#X0003C"));
        $this->assertEquals("<", $instance->canonicalize("&#X00003C"));
        $this->assertEquals("<", $instance->canonicalize("&#X000003C"));
        $this->assertEquals("<", $instance->canonicalize("&#X3C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X03C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X0003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X00003C;"));
        $this->assertEquals("<", $instance->canonicalize("&#X000003C;"));
        $this->assertEquals("<", $instance->canonicalize("&lt"));
        $this->assertEquals("<", $instance->canonicalize("&lT"));
        $this->assertEquals("<", $instance->canonicalize("&Lt"));
        $this->assertEquals("<", $instance->canonicalize("&LT"));
        $this->assertEquals("<", $instance->canonicalize("&lt;"));
        $this->assertEquals("<", $instance->canonicalize("&lT;"));
        $this->assertEquals("<", $instance->canonicalize("&Lt;"));
        $this->assertEquals("<", $instance->canonicalize("&LT;"));
        
        $this->assertEquals("<script>alert(\"hello\");</script>",
            $instance->canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
        $this->assertEquals("<script>alert(\"hello\");</script>",
            $instance->canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", false));

        // javascript escape syntax
        $instance = new DefaultEncoder(array(new JavaScriptCodec()));
    
        $this->assertEquals("<", $instance->canonicalize("\\<"));
        $this->assertEquals("<", $instance->canonicalize("\\u003c"));
        $this->assertEquals("<", $instance->canonicalize("\\U003c"));
        $this->assertEquals("<", $instance->canonicalize("\\u003C"));
        $this->assertEquals("<", $instance->canonicalize("\\U003C"));
        $this->assertEquals("<", $instance->canonicalize("\\x3c"));
        $this->assertEquals("<", $instance->canonicalize("\\X3c"));
        $this->assertEquals("<", $instance->canonicalize("\\x3C"));
        $this->assertEquals("<", $instance->canonicalize("\\X3C"));
        
        // css escape syntax
        $instance = new DefaultEncoder(array(new CSSCodec()));

        $this->assertEquals("<", $instance->canonicalize("\\3c"));
        $this->assertEquals("<", $instance->canonicalize("\\03c"));
        $this->assertEquals("<", $instance->canonicalize("\\003c"));
        $this->assertEquals("<", $instance->canonicalize("\\0003c"));
        $this->assertEquals("<", $instance->canonicalize("\\00003c"));
        $this->assertEquals("<", $instance->canonicalize("\\3C"));
        $this->assertEquals("<", $instance->canonicalize("\\03C"));
        $this->assertEquals("<", $instance->canonicalize("\\003C"));
        $this->assertEquals("<", $instance->canonicalize("\\0003C"));
        $this->assertEquals("<", $instance->canonicalize("\\00003C"));
    }

    /**
     * Test of canonicalize method, of class org.owasp.esapi.Encoder.
     *
     * @throws EncodingException
     */
    public function testDoubleEncodingCanonicalization()
    {
        $instance = ESAPI::getEncoder();

        // note these examples use the strict=false flag on canonicalize to allow
        // full decoding without throwing an IntrusionException. Generally, you
        // should use strict mode as allowing double-encoding is an abomination.
        
        // double encoding examples
        $this->assertEquals("<", $instance->canonicalize("&#x26;lt&#59", false)); //double entity
        $this->assertEquals("\\", $instance->canonicalize("%255c", false)); //double percent
        $this->assertEquals("%", $instance->canonicalize("%2525", false)); //double percent
        
        // double encoding with multiple schemes example
        $this->assertEquals("<", $instance->canonicalize("%26lt%3b", false)); //first entity, then percent
        $this->assertEquals("&", $instance->canonicalize("&#x25;26", false)); //first percent, then entity

        // nested encoding examples
        $this->assertEquals("<", $instance->canonicalize("%253c", false)); //nested encode % with percent
        $this->assertEquals("<", $instance->canonicalize("%%33%63", false)); //nested encode both nibbles with percent
        $this->assertEquals("<", $instance->canonicalize("%%33c", false)); // nested encode first nibble with percent
        $this->assertEquals("<", $instance->canonicalize("%3%63", false));  //nested encode second nibble with percent
        $this->assertEquals("<", $instance->canonicalize("&&#108;t;", false)); //nested encode l with entity
        $this->assertEquals("<", $instance->canonicalize("%2&#x35;3c", false)); //triple percent, percent, 5 with entity

        // nested encoding with multiple schemes examples
        $this->assertEquals("<", $instance->canonicalize("&%6ct;", false)); // nested encode l with percent
        $this->assertEquals("<", $instance->canonicalize("%&#x33;c", false)); //nested encode 3 with entity

        // multiple encoding tests
        $this->assertEquals("% & <script> <script>", $instance->canonicalize("%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false));
        $this->assertEquals("< < < < < < <", $instance->canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false));

        // test strict mode with both mixed and multiple encoding
        $this->setExpectedException('IntrusionException');
        $instance->canonicalize('%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B');
        $this->setExpectedException('IntrusionException');
        $instance->canonicalize('%253Cscript');
        $this->setExpectedException('IntrusionException');
        $instance->canonicalize('&#37;3Cscript');
    }

    /**
     * Test of encodeForHTML method of class Encoder.
     *
     * @throws Exception
     */
    public function testEncodeForHTML()
    {
        $instance = ESAPI::getEncoder();
        
        $this->assertEquals(null, $instance->encodeForHTML(null));
        // test invalid characters are replaced with spaces
        $this->assertEquals("a b c d e f&#x9;g", $instance->encodeForHTML("a" . chr(0) . "b" . chr(4) . "c" . chr(128) . "d" . chr(150) . "e" . chr(159) . "f" . chr(9) . "g"));
        $this->assertEquals("a b c d e f&#x9;g h i j&nbsp;k&iexcl;l&cent;m", $instance->encodeForHTML("a" . chr(0) . "b" . chr(4) . "c" . chr(128) . "d" . chr(150) . "e" . chr(159) . "f" . chr(9) . "g" . chr(127) . "h" . chr(129) . "i" . chr(159) . "j" . chr(160) . "k" . chr(161) . "l" . chr(162) . "m"));
        
        $this->assertEquals("&lt;script&gt;", $instance->encodeForHTML("<script>"));
        $this->assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", $instance->encodeForHTML("&lt;script&gt;"));
        $this->assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTML("!@$%()=+{}[]"));
        $this->assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTML($instance->canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;", false)));
        $this->assertEquals(",.-_ ", $instance->encodeForHTML(",.-_ "));
        $this->assertEquals("dir&amp;", $instance->encodeForHTML("dir&"));
        $this->assertEquals("one&amp;two", $instance->encodeForHTML("one&two"));
        $this->assertEquals("" . chr(12345) . chr(65533) . chr(1244), "" . chr(12345) . chr(65533) . chr(1244));
    }

    /**
     * Test of encodeForHTMLAttribute method of class Encoder.
     */
    public function testEncodeForHTMLAttribute()
    {
        $instance = ESAPI::getEncoder();
        
        $this->assertEquals(null, $instance->encodeForHTMLAttribute(null));
        $this->assertEquals("&lt;script&gt;", $instance->encodeForHTMLAttribute("<script>"));
        $this->assertEquals(",.-_", $instance->encodeForHTMLAttribute(",.-_"));
        $this->assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForHTMLAttribute(" !@$%()=+{}[]"));
    }

    /**
     * Test of encodeForCSS method of class Encoder.
     */
    public function testEncodeForCSS()
    {
        $instance = ESAPI::getEncoder();
        
        $this->assertEquals(null, $instance->encodeForCSS(null));
        $this->assertEquals("\\3c script\\3e ", $instance->encodeForCSS("<script>"));
        $this->assertEquals("\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ", $instance->encodeForCSS("!@$%()=+{}[]"));
    }

    /**
     * Test of encodeForJavaScript method of class Encoder.
     * Note that JavaScriptCodec is closer to ESAPI 2 for Java and so these
     * tests are taken from that version.
     */
    public function testEncodeForJavascript()
    {
        $instance = ESAPI::getEncoder();
        
        $this->assertEquals(null, $instance->encodeForJavaScript(null));
        $this->assertEquals("\\x3Cscript\\x3E", $instance->encodeForJavaScript("<script>"));
        $this->assertEquals(",.\\x2D_\\x20", $instance->encodeForJavaScript(",.-_ "));
        $this->assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", $instance->encodeForJavaScript("!@$%()=+{}[]"));
        $this->assertEquals("\\x00", $instance->encodeForJavaScript("\0"));
        $this->assertEquals("\\x5C", $instance->encodeForJavaScript("\\"));
    }

    /**
     * Test of encodeForVBScript method of class Encoder.
     */
    public function testEncodeForVBScript()
    {
        $instance = ESAPI::getEncoder();
        
        $this->assertEquals(null, $instance->encodeForVBScript(null));
        $this->assertEquals('""', $instance->encodeForVBScript('"'));
        $this->assertEquals('"<script">', $instance->encodeForVBScript('<script>'));
        $this->assertEquals(' "!"@"$"%"(")"="+"{"}"["]""', $instance->encodeForVBScript(' !@$%()=+{}[]"'));
    }

    /**
     * Test of encodeForXPath method of class Encoder.
     */
    public function testEncodeForXPath()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForXPath(null));
        $this->assertEquals("&#x27;or 1&#x3d;1", $instance->encodeForXPath("'or 1=1"));
    }

    /**
     * Test of encodeForSQL method of class Encoder.
     */
    public function testEncodeForSQL()
    {
        $instance = ESAPI::getEncoder();

        $mysqlAnsiCodec = new MySQLCodec(MySQLCodec::MYSQL_ANSI);
        $this->assertEquals(null, $instance->encodeForSQL($mysqlAnsiCodec, null));
        $this->assertEquals("Jeff'' or ''1''=''1", $instance->encodeForSQL($mysqlAnsiCodec, "Jeff' or '1'='1"));
        
        $mysqlStdCodec = new MySQLCodec(MySQLCodec::MYSQL_STD);
        $this->assertEquals(null, $instance->encodeForSQL($mysqlStdCodec, null));
        $this->assertEquals("Jeff\\' or \\'1\\'\\=\\'1", $instance->encodeForSQL($mysqlStdCodec, "Jeff' or '1'='1"));
        $this->assertEquals("\\b \\n \\r \\t \\Z \\_ \\\" \\' \\\\ \\0 \\%", $instance->encodeForSQL($mysqlStdCodec, "\x08 \x0a \x0d \x09 \x1a _ \" ' \\ \x00 \x25"));

        $oracleCodec = new OracleCodec();
        $this->assertEquals(null, $instance->encodeForSQL($oracleCodec, null));
        $this->assertEquals("Jeff'' or ''1''=''1", $instance->encodeForSQL($oracleCodec, "Jeff' or '1'='1"));
    }

    /**
     * Test of encodeForLDAP method of class Encoder.
     */
    public function testEncodeForLDAP()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');

        /* TODO: DELETE ME ("encodeForLDAP");
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForLDAP(null));
        $this->assertEquals("No special characters to escape", "Hi This is a test #��", $instance->encodeForLDAP("Hi This is a test #��"));
        $this->assertEquals("Zeros", "Hi \\00", $instance->encodeForLDAP("Hi \u0000"));
        $this->assertEquals("LDAP Christams Tree", "Hi \\28This\\29 = is \\2a a \\5c test # � � �", $instance->encodeForLDAP("Hi (This) = is * a \\ test # � � �"));
        */
    }

    /**
     * Test of encodeForDN method of class Encoder.
     */
    public function testEncodeForDN()
    {
        $this->markTestIncomplete('This test has not been implemented yet.');

        /* TODO: DELETE ME ("encodeForDN");
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForDN(null));
        $this->assertEquals("No special characters to escape", "Hello�", $instance->encodeForDN("Hello�"));
        $this->assertEquals("leading #", "\\# Hello�", $instance->encodeForDN("# Hello�"));
        $this->assertEquals("leading space", "\\ Hello�", $instance->encodeForDN(" Hello�"));
        $this->assertEquals("trailing space", "Hello�\\ ", $instance->encodeForDN("Hello� "));
        $this->assertEquals("less than greater than", "Hello\\<\\>", $instance->encodeForDN("Hello<>"));
        $this->assertEquals("only 3 spaces", "\\  \\ ", $instance->encodeForDN("   "));
        $this->assertEquals("Christmas Tree DN", "\\ Hello\\\\ \\+ \\, \\\"World\\\" \\;\\ ", $instance->encodeForDN(" Hello\\ + , \"World\" ; "));
        */
    }

    /**
     * Test of encodeForXML method of class Encoder.
     */
    public function testEncodeForXML()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForXML(null));
        $this->assertEquals(' ', $instance->encodeForXML(' '));
        $this->assertEquals('&lt;script&gt;', $instance->encodeForXML('<script>'));
        $this->assertEquals(',.-_', $instance->encodeForXML(',.-_'));
        $this->assertEquals('&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;', $instance->encodeForXML('!@$%()=+{}[]'));
        $this->assertEquals('&#xa3;', $instance->encodeForXML("\xA3"));
    }

    /**
     * Test of encodeForXMLAttribute method of class Encoder.
     */
    public function testEncodeForXMLAttribute_null()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForXMLAttribute(null));
        $this->assertEquals("&#x20;", $instance->encodeForXMLAttribute(" "));
        $this->assertEquals("&lt;script&gt;", $instance->encodeForXMLAttribute("<script>"));
        $this->assertEquals(",.-_", $instance->encodeForXMLAttribute(",.-_"));
        $this->assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", $instance->encodeForXMLAttribute(" !@$%()=+{}[]"));
        $this->assertEquals('&#xa3;', $instance->encodeForXMLAttribute("\xA3"));
    }

    /**
     * Test of encodeForURL method of class Encoder.
     */
    public function testEncodeForURL()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForURL(null));
        $this->assertEquals("%3Cscript%3E", $instance->encodeForURL("<script>"));
        $this->assertEquals("+", $instance->encodeForURL(" "));
    }

    /**
     * Test of decodeFromURL method, of class Encoder.
     */
    public function testDecodeFromURL()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->decodeFromURL(null));
        $this->assertEquals("<script>", $instance->decodeFromURL("%3Cscript%3E"));
        $this->assertEquals("     ", $instance->decodeFromURL("+++++"));
    }

    /**
     * Test of encodeForBase64 method of class Encoder.
     */
    public function testEncodeForBase64()
    {
        $instance = ESAPI::getEncoder();

        $this->assertEquals(null, $instance->encodeForBase64(null, false));
        $this->assertEquals(null, $instance->encodeForBase64(null, true));
        $this->assertEquals(null, $instance->decodeFromBase64(null));

        // Test wrapping at 76 chars
        $unencoded = ESAPI::getRandomizer()->getRandomString(76, Encoder::CHAR_SPECIALS);
        $encoded = $instance->encodeForBase64($unencoded, false);
        $encodedWrapped = $instance->encodeForBase64($unencoded, true);
        $expected = mb_substr($encoded, 0, 76, 'ASCII') . "\r\n" . mb_substr($encoded, 76, mb_strlen($encoded, 'ASCII')-76, 'ASCII');
        $this->assertEquals($expected, $encodedWrapped);
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

    /**
     * Test of decodeFromBase64 method, of class Encoder.
     */
    public function testDecodeFromBase64()
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
        
        // Test decode single character
        $this->assertEquals('', $instance->decodeFromBase64('0'));
        $this->assertEquals('', $instance->decodeFromBase64('1'));
        $this->assertEquals('', $instance->decodeFromBase64('a'));
        $this->assertEquals('', $instance->decodeFromBase64('A'));
        $this->assertEquals('', $instance->decodeFromBase64('\\'));
        $this->assertEquals('', $instance->decodeFromBase64('+'));
        $this->assertEquals('', $instance->decodeFromBase64('='));
        $this->assertEquals('', $instance->decodeFromBase64('-'));
    }

    /**
     * Test of WindowsCodec
     */
    public function testWindowsCodec()
    {
        $instance = ESAPI::getEncoder();

        $codec_win = new WindowsCodec();
        $this->assertEquals(null, $instance->encodeForOS($codec_win, null));
        $decoded = $codec_win->decodeCharacter(Codec::normalizeEncoding("n"));
        $this->assertEquals(null, $decoded['decodedCharacter']);
        $decoded = $codec_win->decodeCharacter(Codec::normalizeEncoding(""));
        $this->assertEquals(null, $decoded['decodedCharacter']);

        $immune = array("\0"); // not that it matters, but the java test would encode alphanums with such an immune param.
        $encoded = $codec_win->encodeCharacter($immune, "<");
        $decoded = $codec_win->decode($encoded);
        $this->assertEquals("<", $decoded);

        $orig = "c:\\jeff";
        $this->assertEquals($orig, $codec_win->decode($orig));

        $immune = array();
        $orig = "c:\\jeff";
        $encoded = $codec_win->encode($immune, $orig);
        $this->assertEquals($orig, $codec_win->decode($encoded));
        $this->assertEquals("c^:^\\jeff", $instance->encodeForOS($codec_win, "c:\\jeff"));
        $this->assertEquals("c^:^\\jeff", $codec_win->encode($immune, "c:\\jeff"));
        $this->assertEquals("dir^ ^&^ foo", $instance->encodeForOS($codec_win, "dir & foo"));
        $this->assertEquals("dir^ ^&^ foo", $codec_win->encode($immune, "dir & foo"));
    }

    /**
     * Test of UnixCodec
     */
    public function testUnixCodec()
    {
        $instance = ESAPI::getEncoder();

        $codec_unix = new UnixCodec();
        $this->assertEquals(null, $instance->encodeForOS($codec_unix, null));
        $decoded = $codec_unix->decodeCharacter(Codec::normalizeEncoding("n"));
        $this->assertEquals(null, $decoded['decodedCharacter']);
        $decoded = $codec_unix->decodeCharacter(Codec::normalizeEncoding(""));
        $this->assertEquals(null, $decoded['decodedCharacter']);

        $immune = array("\0"); // not that it matters, but the java test would encode alphanums with such an immune param.
        $encoded = $codec_unix->encodeCharacter($immune, "<");
        $decoded = $codec_unix->decode($encoded);
        $this->assertEquals("<", $decoded);

        $orig = "/etc/passwd";
        $this->assertEquals($orig, $codec_unix->decode($orig));

        $immune = array();
        $orig = "/etc/passwd";
        $encoded = $codec_unix->encode($immune, $orig);
        $this->assertEquals($orig, $codec_unix->decode($encoded));

        // TODO: Check that this is acceptable for Unix hosts
        $this->assertEquals("c\\:\\\\jeff", $instance->encodeForOS($codec_unix, "c:\\jeff"));
        $this->assertEquals("c\\:\\\\jeff", $codec_unix->encode($immune, "c:\\jeff"));
        $this->assertEquals("dir\\ \\&\\ foo", $instance->encodeForOS($codec_unix, "dir & foo"));
        $this->assertEquals("dir\\ \\&\\ foo", $codec_unix->encode($immune, "dir & foo"));

        // Unix paths (that must be encoded safely)
        // TODO: Check that this is acceptable for Unix
        $this->assertEquals("\\/etc\\/hosts", $instance->encodeForOS($codec_unix, "/etc/hosts"));
        $this->assertEquals("\\/etc\\/hosts\\;\\ ls\\ -l", $instance->encodeForOS($codec_unix, "/etc/hosts; ls -l"));

        // these tests check that mixed character encoding is handled properly when encoding.
        $expected = '/^[a-zA-Z0-9\/+]*={0,2}$/';
        
        for ($i = 0; $i<256; $i++) {
            $input = chr($i);
            $output = $instance->encodeForBase64($input);
            $this->assertRegExp($expected, $output, "Input was character with ordinal: {$i} - %s");
            $this->assertEquals($input, $instance->decodeFromBase64($output));
        }

        for ($i = 0; $i < 256; $i++) {
            $input = 'a' . chr($i);
            $output = $instance->encodeForBase64($input);
            $this->assertRegExp($expected, $output, "Input was 'a' concat with character with ordinal: {$i} - %s");
            $this->assertEquals($input, $instance->decodeFromBase64($output));
        }

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
