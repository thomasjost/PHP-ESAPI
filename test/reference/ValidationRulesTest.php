<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * UnitTestCase for ValidationRule implementations.
 *
 * PHP version 5.2.9
 *
 * @category  OWASP
 * @package   ESAPI
 * @version   1.0
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @link      http://www.owasp.org/index.php/ESAPI
 */
 namespace PHPESAPI\PHPESAPI\Test\Reference;

class ValidationRulesTest extends \PHPUnit\Framework\TestCase
{
    /**
     * BaseValidationRule tests
     *
     * These tests use StringValidationRule (BaseVR is abstract) which
     * should be sufficient...
     */

    /**
     * test allowNull getter and setter
     */
    public function testStringVR_allowNull()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertFalse($svr->getAllowNull());

        $svr->setAllowNull(true);
        $this->assertTrue($svr->getAllowNull());

        $svr->setAllowNull('not a boolean!');  // will set it false
        $this->assertFalse($svr->getAllowNull());
    }

    /**
     * Constructor sets typeName, getter gets it and setter sets it.
     */
    public function testStringVR_typeName()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertEquals('A_String', $svr->getTypeName());

        $svr->setTypeName(null); // sets a default value - not interested what it is.
        $name = $svr->getTypeName();
        $this->assertTrue(is_string($name) && $name != 'A_String');

        $svr->setTypeName('A_String');
        $this->assertEquals('A_String', $svr->getTypeName());
    }

    /**
     * accepts only objects which provide canonicalize
     */
    public function testStringVR_Encoder()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertNull($svr->setEncoder(new \PHPESAPI\PHPESAPI\Reference\DefaultEncoder()));

        $this->setExpectedException('InvalidArgumentException');
        $svr->setEncoder(new \PHPESAPI\PHPESAPI\Codecs\Base64Codec);
    }

    /**
     * assertValid returns null for valid input
     */
    public function testStringVR_assertValid_valid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertNull($svr->assertValid('testStringVR_assertValid_valid', 'aabbcc'));
    }

    /**
     * assertValid throws ValidationException for invalid input
     */
    public function testStringVR_assertValid_invalid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->setExpectedException('ValidationException');
        $svr->assertValid('testStringVR_assertValid_invalid', 'dddddd');
    }

    /**
     * assertValid throws IntrusionException for obvious attack ;)
     */
    public function testStringVR_assertValid_attack()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->setExpectedException('IntrusionException');
        $svr->assertValid('testStringVR_assertValid_attack', 'dddddd%2500');
    }

    /**
     * getSafe returns canonicalised input for valid input
     */
    public function testStringVR_getSafe_valid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertEquals('aabbcc', $svr->getSafe('testStringVR_getSafe_valid', 'aabbcc'));

        $this->assertEquals('aabbcc', $svr->getSafe('testStringVR_getSafe_valid', '%61abbcc'));
    }

    /**
     * getSafe returns sanitized for invalid input
     */
    public function testStringVR_getSafe_invalid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertEquals('aabbcc00', $svr->getSafe('testStringVR_getSafe_invalid', 'aabbcc%00'));
    }

    /**
     * getSafe does not catch IntrusionExceptions
     */
    public function testStringVR_getSafe_attack()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->setExpectedException('IntrusionException');
        $svr->getSafe('testStringVR_getSafe_valid', 'aabbcc%2500');
    }

    /**
     * isValid returns boolean values only
     */
    public function testStringVR_isValid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertTrue($svr->isValid('testStringVR_isValid', 'aabbcc'));

        $this->assertFalse($svr->isValid('testStringVR_isValid', 'dddddd'));

        $this->assertFalse($svr->isValid('testStringVR_isValid', 'dddddd%2500'));
    }

    /**
     * whitelist returns a string containing only those chars from input that
     * are present in the whitelist
     */
    public function testStringVR_whitelist()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertEquals('aabbcc', $svr->whitelist('aabbcc%00', 'abc'));
    }

    /**
     * CreditCardValidationRule tests
     */

    /**
     * Test supplying constructor with an instance of a validator
     */
    public function testCCVR_constructValidator()
    {
        $config = ESAPI::getSecurityConfiguration();
        $pattern = $config->getValidationPattern('CreditCard');
        $ccr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('CreditCardValidator', null, $pattern);
        $ccr->setMaximumLength(16); // 19 in the default validator

        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn', null, $ccr);
        $this->assertTrue($ccvr->isValid('testCCVR_constructValidator', '0000000000000000'));
        $this->assertFalse($ccvr->isValid('testCCVR_constructValidator', '0000-0000-0000-0000'));
    }

    /**
     * getValid returns canonicalised input for valid input
     */
    public function testCCVR_getValid_valid()
    {
        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn');

        $this->assertEquals('0000-0000-0000-0000', $ccvr->getValid('testCCVR_getValid_valid', '0000-0000-0000-0000'));

        $this->assertEquals('0000 0000 0000 0000', $ccvr->getValid('testCCVR_getValid_valid', '0000%200000%200000%200000'));
    }

    /**
     * `&nbsp;` entity does not match a space in preg_match.
     */
    public function testCCVR_getValid_nbsp()
    {
        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn');

        $this->setExpectedException('ValidationException');
        $ccvr->assertValid('testCCVR_getValid_nbsp', '0000&nbsp;0000&nbsp;0000&nbsp;0018');
    }

    /**
     * getValid throws ValidationException for invalid
     */
    public function testCCVR_getValid_invalid()
    {
        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn');

        $this->setExpectedException('ValidationException');
        $ccvr->getValid('testCCVR_getValid_invalid', '0000 0000 0000%000018');
    }

    /**
     * getValid throws IntrusionException for obvious attack
     */
    public function testCCVR_getValid_attack()
    {
        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn');

        $this->setExpectedException('IntrusionException');
        $ccvr->getValid('testCCVR_getValid_attack', '0000%200000%25200000%200018');
    }

    /**
     * getValid does not treat '0' as empty. disallows empty values when
     * allowNull is false.
     */
    public function testCCVR_getValid_Empty()
    {
        $ccr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('CreditCardValidator', null, '^[0-9]*$');
        $ccr->setMaximumLength(1);

        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn', null, $ccr);

        $this->assertTrue($ccvr->isValid('testCCVR_getValid_Empty', '0'));

        $this->assertFalse($ccvr->isValid('testCCVR_getValid_Empty', ''));

        $this->assertFalse($ccvr->isValid('testCCVR_getValid_Empty', null));

        $ccvr->setAllowNull(true);

        $this->assertTrue($ccvr->isValid('testCCVR_getValid_Empty', ''));

        $this->assertTrue($ccvr->isValid('testCCVR_getValid_Empty', null));
    }

    /**
     * isValid returns boolean values only
     */
    public function testCCVR_isValid()
    {
        $ccvr = new \PHPESAPI\PHPESAPI\Reference\Validation\CreditCardValidationRule('CreditCardValidatorLuhn');

        $this->assertTrue($ccvr->isValid('testCCVR_isValid', '0000000000000026'));

        $this->assertTrue($ccvr->isValid('testCCVR_isValid', '0000000000000034'));

        $this->assertFalse($ccvr->isValid('testCCVR_isValid', '0'));

        $this->assertFalse($ccvr->isValid('testCCVR_isValid', 'not a credit card number'));

        $this->assertFalse($ccvr->isValid('testCCVR_isValid', '0000-0000-0000-0001'));
    }

    /**************************************************************************
     *
     *                       DateValidationRule tests
     *
     *
     **************************************************************************/

    /**
     * constructor sets a sane default date format string ('Y-m-d')
     */
    public function testDateVR_construct_format()
    {
        $dvr = new \PHPESAPI\PHPESAPI\Reference\Validation\DateValidationRule('DateValidator');

        $this->assertTrue($dvr->getValid('testDateVR_construct_format', '1970-01-31')->format('Y-m-d') == '1970-01-31');
    }

    /**************************************************************************
     *
     *                       HTMLValidationRule tests
     *
     *
     **************************************************************************/

    /**
     * Quick test to ensure HTMLPurifier 'works'
     */
    public function testHTMLVR_construct_purifier()
    {
        $hvr = new \PHPESAPI\PHPESAPI\Reference\Validation\HTMLValidationRule('HTMLValidator');

        $this->setExpectedException('ValidationException');
        $a = '<body><body><div>Hi!</div></body>';
        $hvr->getValid('testHTMLVR_construct_purifier', $a); // error=Unrecognized <body> tag removed
    }

    /**
     * IntegerValidationRuletests
     */

    /**
     * getValid returns canonicalised input for valid input
     */
    public function testIntegerVR_getValid_valid()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null);

        $this->assertTrue((int) 187 === $ivr->getValid('testIntegerVR_getValid_valid', '187'));

        $this->assertTrue((int) -187 === $ivr->getValid('testIntegerVR_getValid_valid', '-187'));

        $this->assertTrue((int) PHP_INT_MAX === $ivr->getValid('testIntegerVR_getValid_valid', (string) PHP_INT_MAX));
    }

    /**
     * getValid does not treat '0' as empty. disallows empty values when
     * allowNull is false.
     */
    public function testIntegerVR_getValid_Empty()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null);

        $this->assertTrue($ivr->isValid('testIntegerVR_getValid_Empty', '0'));

        $this->assertFalse($ivr->isValid('testIntegerVR_getValid_Empty', ''));

        $this->assertFalse($ivr->isValid('testIntegerVR_getValid_Empty', null));

        $ivr->setAllowNull(true);

        $this->assertTrue($ivr->isValid('testIntegerVR_getValid_Empty', ''));

        $this->assertTrue($ivr->isValid('testIntegerVR_getValid_Empty', null));
    }

    /**
     * getSafe returns canonicalised input for valid input
     */
    public function testIntegerVR_getSafe_valid()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 1-PHP_INT_MAX, PHP_INT_MAX);

        $this->assertTrue((int) -1 === $ivr->getSafe('testIntegerVR_getSafe_valid', '-1'));

        $this->assertTrue((int) 2 === $ivr->getSafe('testIntegerVR_getSafe_valid', '%32'));
    }

    /**
     * getSafe returns sanitized (zero) for invalid input
     */
    public function testIntegerVR_getSafe_invalid()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 0, PHP_INT_MAX);

        $this->assertTrue((int) 0 === $ivr->getSafe('testIntegerVR_getSafe_invalid', '00%00'));
    }

    /**
     * getSafe does not catch IntrusionExceptions
     */
    public function testIntegerVR_getSafe_attack()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 0, PHP_INT_MAX);

        $this->setExpectedException('IntrusionException');
        $ivr->getSafe('testIntegerVR_getSafe_valid', '00%2500');
    }

    /**
     * isValid returns boolean values only
     */
    public function testIntegerVR_isValid()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 1-PHP_INT_MAX, PHP_INT_MAX);

        $this->assertTrue($ivr->isValid('testIntegerVR_isValid', '12345678'));

        $this->assertTrue($ivr->isValid('testIntegerVR_isValid', '+1'));

        $this->assertTrue($ivr->isValid('testIntegerVR_isValid', '-10000000'));

        $this->assertFalse($ivr->isValid('testIntegerVR_isValid', '0.00.00'));

        $this->assertFalse($ivr->isValid('testIntegerVR_isValid', '1e6'));

        $i = PHP_INT_MAX+1;
        $this->assertFalse($ivr->isValid('testIntegerVR_isValid', "{$i}"));
    }

    /**
     * test sanity check min < max with PHP_INT_MAX
     */
    public function testIntegerVR_MinMax()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, PHP_INT_MAX, 1-PHP_INT_MAX);

        $this->setExpectedException('RuntimeException');
        $ivr->getValid('testIntegerVR_MinMax', '0');
    }

    /**
     * test sanitize returns zero (always, for now)
     */
    public function testIntegerVR_sanitize()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 0, PHP_INT_MAX);

        $this->assertTrue((int) 0 === $ivr->sanitize('testIntegerVR_sanitize', 'abc%00'));
    }

    /**
     * test sanitize with empty input
     */
    public function testIntegerVR_sanitize_empty()
    {
        $ivr = new \PHPESAPI\PHPESAPI\Reference\Validation\IntegerValidationRule('An_Integer', null, 0, PHP_INT_MAX);

        $this->assertTrue((int) 0 === $ivr->sanitize('testIntegerVR_sanitize_empty', null));

        $this->assertTrue((int) 0 === $ivr->sanitize('testIntegerVR_sanitize_empty', ''));
    }

    /**
     * NumberValidationRule tests
     */

    /**
     * getValid returns canonicalised input for valid input
     */
    public function testNumberVR_getValid_valid()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 0, PHP_INT_MAX);

        $this->assertTrue((double) 187 === $nvr->getValid('testNumberVR_getValid_valid', '187'));

        $this->assertTrue(187.211 === $nvr->getValid('testNumberVR_getValid_valid', '187.211'));

        $this->assertTrue((double) PHP_INT_MAX === $nvr->getValid('testNumberVR_getValid_valid', (string) PHP_INT_MAX));
    }

    /**
     * getValid does not treat '0' as empty. disallows empty values when
     * allowNull is false.
     */
    public function testNumberVR_getValid_Empty()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null);

        $this->assertTrue($nvr->isValid('testNumberVR_getValid_Empty', '0'));

        $this->assertFalse($nvr->isValid('testNumberVR_getValid_Empty', ''));

        $this->assertFalse($nvr->isValid('testNumberVR_getValid_Empty', null));

        $nvr->setAllowNull(true);

        $this->assertTrue($nvr->isValid('testNumberVR_getValid_Empty', ''));

        $this->assertTrue($nvr->isValid('testNumberVR_getValid_Empty', null));
    }

    /**
     * getSafe returns canonicalised input for valid input
     */
    public function testNumberVR_getSafe_valid()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 1-PHP_INT_MAX, PHP_INT_MAX);

        $this->assertTrue((double) -1 === $nvr->getSafe('testNumberVR_getSafe_valid', '-1'));

        $this->assertTrue((double) 2 === $nvr->getSafe('testNumberVR_getSafe_valid', '%32'));
    }

    /**
     * getSafe returns sanitized (zero) for invalid input
     */
    public function testNumberVR_getSafe_invalid()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 0, PHP_INT_MAX);

        $this->assertTrue((double) 0 === $nvr->getSafe('testNumberVR_getSafe_invalid', '00%00'));
    }

    /**
     * getSafe does not catch IntrusionExceptions
     */
    public function testNumberVR_getSafe_attack()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 0, PHP_INT_MAX);

        $this->setExpectedException('IntrusionException');
        $nvr->getSafe('testNumberVR_getSafe_valid', '00%2500');
    }

    /**
     * isValid returns boolean values only
     */
    public function testNumberVR_isValid()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 1-PHP_INT_MAX, PHP_INT_MAX);

        $this->assertTrue($nvr->isValid('testNumberVR_isValid', '0.00'));

        $this->assertTrue($nvr->isValid('testNumberVR_isValid', '-1'));

        $this->assertTrue($nvr->isValid('testNumberVR_isValid', '-1e9'));

        $this->assertTrue($nvr->isValid('testNumberVR_isValid', '-1.3e9'));

        $this->assertFalse($nvr->isValid('testNumberVR_isValid', '0.00.00'));

        $i = PHP_INT_MAX+1;
        $this->assertFalse($nvr->isValid('testNumberVR_isValid', "{$i}"));
    }

    /**
     * isValid returns boolean values only
     */
    public function testNumberVR_isValid_INF()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null);

        $this->assertTrue($nvr->isValid('testNumberVR_isValid_INF', '0.00'));

        $this->assertFalse($nvr->isValid('testNumberVR_isValid_INF', '0.00.00'));

        $this->assertFalse($nvr->isValid('testNumberVR_isValid_INF', (string) log(0)));
    }

    /**
     * test sanity check min < max with INF
     */
    public function testNumberVR_MinMax()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, INF, 0);

        $this->setExpectedException('RuntimeException');
        $nvr->getValid('testNumberVR_MinMax', '0');
    }

    /**
     * test sanitize returns zero (always, for now)
     */
    public function testNumberVR_sanitize()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 0, PHP_INT_MAX);

        $this->assertTrue((double) 0 === $nvr->sanitize('testNumberVR_sanitize', 'abc%00'));
    }

    /**
     * test sanitize with empty input
     */
    public function testNumberVR_sanitize_empty()
    {
        $nvr = new \PHPESAPI\PHPESAPI\Reference\Validation\NumberValidationRule('A_Number', null, 0, PHP_INT_MAX);

        $this->assertTrue((double) 0 === $nvr->sanitize('testNumberVR_sanitize_empty', null));

        $this->assertTrue((double) 0 === $nvr->sanitize('testNumberVR_sanitize_empty', ''));
    }

    /**
     * StringValidationRule tests
     */

    /**
     * test addWhitelistPattern
     */
    public function testStringVR_addWhitelistPattern()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, null);

        $svr->addWhitelistPattern('^[abc]+$');
        $this->assertTrue($svr->isValid('testStringVR_addWhitelistPattern', 'aabbcc'));
        $this->assertFalse($svr->isValid('testStringVR_addWhitelistPattern', 'dddddd'));

        $svr->addWhitelistPattern('^[ab]+$');  // input must pass both patterns!
        $this->assertTrue($svr->isValid('testStringVR_addWhitelistPattern', 'aabb'));
        $this->assertFalse($svr->isValid('testStringVR_addWhitelistPattern', 'aabbcc'));
    }

    /**
     * test addBlacklistPattern
     */
    public function testStringVR_addBlacklistPattern()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, null);

        $svr->addBlacklistPattern('^[abc]+$');
        $this->assertTrue($svr->isValid('testStringVR_addBlacklistPattern', 'dddddd'));
        $this->assertFalse($svr->isValid('testStringVR_addBlacklistPattern', 'aabbcc'));

        $svr->addBlacklistPattern('^[abcd]+$');  // input must pass both patterns!
        $this->assertTrue($svr->isValid('testStringVR_addBlacklistPattern', 'eeeeee'));
        $this->assertFalse($svr->isValid('testStringVR_addBlacklistPattern', 'dddddd'));
    }

    /**
     * test setMinimumLength
     */
    public function testStringVR_setMinimumLength()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $svr->setMinimumLength(6);

        $this->assertTrue($svr->isValid('testStringVR_setMinimumLength', 'aabbcc'));

        $this->assertFalse($svr->isValid('testStringVR_setMinimumLength', 'aabbc'));
    }

    /**
     * test setMaximumLength
     */
    public function testStringVR_setMaximumLength()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $svr->setMaximumLength('6');

        $this->assertTrue($svr->isValid('testStringVR_setMaximumLength', 'aabbcc'));

        $this->assertFalse($svr->isValid('testStringVR_setMaximumLength', 'aabbccc'));
    }

    /**
     * getValid returns canonicalised input for valid input
     */
    public function testStringVR_getValid_valid()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^[abc]+$');

        $this->assertEquals('aabbcc', $svr->getValid('testStringVR_getValid_valid', 'aabbcc'));

        $this->assertEquals('aabbcc', $svr->getValid('testStringVR_getValid_valid', '%61abbcc'));
    }

    /**
     * getValid does not treat '0' as empty. disallows empty values when
     * allowNull is false.
     */
    public function testStringVR_getValid_Empty()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, '^.*$');

        $this->assertTrue($svr->isValid('testStringVR_getValid_Empty', '0'));

        $this->assertFalse($svr->isValid('testStringVR_getValid_Empty', ''));

        $this->assertFalse($svr->isValid('testStringVR_getValid_Empty', null));

        $svr->setAllowNull(true);

        $this->assertTrue($svr->isValid('testStringVR_getValid_Empty', ''));

        $this->assertTrue($svr->isValid('testStringVR_getValid_Empty', null));
    }

    /**
     * test sanitize
     */
    public function testStringVR_sanitize()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, null);

        $this->assertEquals('abc00', $svr->sanitize('testStringVR_sanitize', 'abc%00'));
    }

    /**
     * test sanitize with empty input
     */
    public function testStringVR_sanitize_empty()
    {
        $svr = new \PHPESAPI\PHPESAPI\Reference\Validation\StringValidationRule('A_String', null, null);

        $this->assertEquals('', $svr->sanitize('testStringVR_sanitize_empty', null));

        $this->assertEquals('', $svr->sanitize('testStringVR_sanitize_empty', ''));
    }
}
