<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Linden Darling <a href="http://www.jds.net.au">JDS Australia</a>
 * @since  2009
 * @since  1.6
 */

/**
 * Test case for HTMLEntityCodec.
 */
class HTMLEntityCodecTest extends PHPUnit_Framework_TestCase
{
    private $htmlEntityCodec;

    // these immune characters are the ones defined in DefaultEncoder.
    private $immune_html     = array(',', '.', '-', '_', ' ');
    private $immune_htmlattr = array(',', '.', '-', '_');

    protected function setUp()
    {
        $this->htmlEntityCodec = new HTMLEntityCodec();
    }

    /* ENCODING METHODS */

    // nice example of encoding for HTML.
    public function testEncodeForHTML()
    {
        $this->assertEquals(
            '&quot;&gt;&lt;script&gt;alert&#x28;&#x2f;XSS&#x2f;&#x29;&lt;&#x2f;script&gt;&lt;foo attr&#x3d;&quot;',
            $this->htmlEntityCodec->encode(
                $this->immune_html,
                '"><script>alert(/XSS/)</script><foo attr="'
            )
        );
    }

    // test that characters normally immune from encoding, can be encoded.
    public function testEncodeImmuneCharsForHTML()
    {
        $immune = array();
        $this->assertEquals(
            'testTEST0123&#x2c;&#x2e;&#x2d;&#x5f;&#x20;',
            $this->htmlEntityCodec->encode(
                $immune,
                'testTEST0123,.-_ '
            )
        );
    }

    // characters immune from encoding don't get encoded.
    public function testNoEncodeImmuneCharsForHTML()
    {
        $this->assertEquals(
            'testTEST0123,.-_ ',
            $this->htmlEntityCodec->encode(
                $this->immune_html,
                'testTEST0123,.-_ '
            )
        );
    }

    // null stays null
    public function testEncodeNullForHTML()
    {
        $this->assertEquals(
            null,
            $this->htmlEntityCodec->encode($this->immune_html, null)
        );
    }

    // chars that must not be encoded for html are replaced with spaces. These
    // two tests expect the same as ESAPI 2.0 for Java.
    public function testEncodeInvalidCharsReplacedBySpace_01()
    {
        $this->assertEquals(
            'a b c d e f&#x9;g',
            $this->htmlEntityCodec->encode(
                $this->immune_html,
                'a' . chr(0) . 'b' . chr(4) . 'c' . chr(128) . 'd' .
                chr(150) . 'e' . chr(159) . 'f' . chr(9) . 'g'
            )
        );
    }

    public function testEncodeInvalidCharsReplacedBySpace_02()
    {
        $this->assertEquals(
            'a b c d e f&#x9;g h i j&nbsp;k&iexcl;l&cent;m',
            $this->htmlEntityCodec->encode(
                $this->immune_html,
                'a' . chr(0)   . 'b' . chr(4)   . 'c' . chr(128) .
                'd' . chr(150) . 'e' . chr(159) . 'f' . chr(9)   .
                'g' . chr(127) . 'h' . chr(129) . 'i' . chr(159) .
                'j' . chr(160) . 'k' . chr(161) . 'l' . chr(162) .
                'm'
            )
        );
    }

    public function testEncodeScriptTag()
    {
        $this->assertEquals(
            '&lt;script&gt;',
            $this->htmlEntityCodec->encode($this->immune_html, '<script>')
        );
    }

    public function testEncodeEncodedScriptTag()
    {
        $this->assertEquals(
            '&amp;lt&#x3b;script&amp;gt&#x3b;',
            $this->htmlEntityCodec->encode($this->immune_html, '&lt;script&gt;')
        );
    }

    public function testEncodeSpecialsForHTML()
    {
        $this->assertEquals(
            '&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;',
            $this->htmlEntityCodec->encode($this->immune_html, '!@$%()=+{}[]')
        );
    }

    public function testEncodeCanonicalisedEncodedSpecials()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(
            '&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;',
            $this->htmlEntityCodec->encode(
                $this->immune_html,
                $instance->canonicalize(
                    '&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;'
                )
            )
        );
    }

    public function testEncodeAmpForHTMLEoS()
    {
        $this->assertEquals(
            'dir&amp;',
            $this->htmlEntityCodec->encode($this->immune_html, 'dir&')
        );
    }

    public function testEncodeAmpForHTMLMidS()
    {
        $this->assertEquals(
            'one&amp;two',
            $this->htmlEntityCodec->encode($this->immune_html, 'one&two')
        );
    }

    public function testSomeChars()
    {
        $this->assertEquals(
            '' . chr(12345) . chr(65533) . chr(1244),
            '' . chr(12345) . chr(65533) . chr(1244)
        );
    }

    public function testEncodeNullForHTMLAttribute()
    {
        $this->assertEquals(
            null,
            $this->htmlEntityCodec->encode($this->immune_htmlattr, null)
        );
    }

    public function testEncodeImmuneCharsForHTMLAttribute()
    {
        $immune = array();
        $this->assertEquals(
            'testTEST0123&#x2c;&#x2e;&#x2d;&#x5f;',
            $this->htmlEntityCodec->encode(
                $immune,
                'testTEST0123,.-_'
            )
        );
    }

    public function testNoEncodeImmuneCharsForHTMLAttribute()
    {
        $this->assertEquals(
            'testTEST0123,.-_',
            $this->htmlEntityCodec->encode(
                $this->immune_htmlattr,
                'testTEST0123,.-_'
            )
        );
    }

    public function testEncodeSpecialsForHTMLAttribute()
    {
        $this->assertEquals(
            '&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;',
            $this->htmlEntityCodec->encode($this->immune_htmlattr, ' !@$%()=+{}[]')
        );
    }

    /* DECODE METHODS */

    public function testDecodeFromHTML()
    {
        $this->assertEquals(
            '"><script>alert(/XSS/)</script><foo attr="',
            $this->htmlEntityCodec->decode(
                '&quot;&gt;&lt;script&gt;alert&#x28;&#x2f;XSS&#x2f;&#x29;&lt;&#x2f;script&gt;&lt;foo attr&#x3d;&quot;'
            )
        );
    }

    public function testDecodeNullFromHTML()
    {
        $this->assertEquals(null, $this->htmlEntityCodec->decode(null));
    }

    public function testDecodeDecimalNumericEntitiesFromHTML()
    {
        $this->assertEquals(
            'test!',
            $this->htmlEntityCodec->decode('&#116;&#101;&#115;&#116;!')
        );
    }

    public function testDecodeHexNumericEntitiesFromHTML()
    {
        $this->assertEquals(
            'test!',
            $this->htmlEntityCodec->decode('&#x74;&#x65;&#x73;&#x74;!')
        );
    }

    public function testDecodeInvalidNamedEntityFromHTML()
    {
        $this->assertEquals('&jeff;', $this->htmlEntityCodec->decode('&jeff;'));
    }

    // Mixed character encoding should not be returned from decode.
    // In this case, ASCII and Latin Supplement characters will exist in the
    // decoded string and should be presented as UTF-8
    public function testDecodeDoesNotProduceMixedCharacterEncoding()
    {
        $codec = new HTMLEntityCodec();
        // expecting a UTF-8 encoded string
        $expected = mb_convert_encoding("a b c d e f\x09g h i j\xa0k\xa1l\xa2m", 'UTF-8', 'ISO-8859-1');
        // check that the encoding conversion went well and the expected string is correct
        $expected_unpacked = array(
            1 => 0x61,  2 => 0x20,  3 => 0x62,  4 => 0x20,
            5 => 0x63,  6 => 0x20,  7 => 0x64,  8 => 0x20,
            9 => 0x65, 10 => 0x20, 11 => 0x66, 12 => 0x09,
           13 => 0x67, 14 => 0x20, 15 => 0x68, 16 => 0x20,
           17 => 0x69, 18 => 0x20, 19 => 0x6a, 20 => 0xc2,
           21 => 0xa0, 22 => 0x6b, 23 => 0xc2, 24 => 0xa1,
           25 => 0x6c, 26 => 0xc2, 27 => 0xa2, 28 => 0x6d,
        );
        $unpacked = unpack('C*', $expected);
        $this->assertSame(
            $expected_unpacked,
            $unpacked,
            'Ensuring expected value was correctly encoded to UTF-8 - %s'
        );
        // decode and hope we get $expected!
        $this->assertEquals(
            $expected,
            $codec->decode(
                'a b c d e f&#x9;g h i j&#xa0;k&#xa1;l&#xa2;m'
            )
        );
    }

    public function testDecodeScriptTag()
    {
        $this->assertEquals(
            '<script>',
            $this->htmlEntityCodec->decode('&lt;script&gt;')
        );
    }

    public function testDecodeOnceDoubleEncodedScriptTag()
    {
        $this->assertEquals(
            '&lt;script&gt;',
            $this->htmlEntityCodec->decode('&amp;lt&#x3b;script&amp;gt&#x3b;')
        );
    }

    public function testDecodeSpecials()
    {
        $this->assertEquals(
            '!@$%()=+{}[]',
            $this->htmlEntityCodec->decode(
                '&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;'
            )
        );
    }

    public function testDecodeSpecialsEqualsCanonicalisedEncodedSpecials()
    {
        $instance = ESAPI::getEncoder();
        $this->assertEquals(
            $instance->canonicalize(
                '&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;'
            ),
            $this->htmlEntityCodec->decode(
                '&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;'
            )
        );
    }

    public function testDecodeAmpFromHTMLEoS()
    {
        $this->assertEquals('dir&', $this->htmlEntityCodec->decode('dir&amp;'));
    }

    public function testDecodeAmpFromHTMLMidS()
    {
        $this->assertEquals(
            'one&two',
            $this->htmlEntityCodec->decode('one&amp;two')
        );
    }

    public function testDecodeCharacter()
    {
        $this->assertEquals('<', $this->htmlEntityCodec->decode('&lt;'));
    }
}
