<?php
/**
 * OWASP Enterprise Security API (ESAPI).
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * PHP version 5.2
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @author    Jeff Williams <jeff.williams@aspectsecurity.com>
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Johannes B. Ullrich <jullrich@sans.edu>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Reference Implementation of the Validator interface.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @author    Jeff Williams <jeff.williams@aspectsecurity.com>
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Johannes B. Ullrich <jullrich@sans.edu>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
namespace PHPESAPI\PHPESAPI\Reference;

class DefaultValidator implements \PHPESAPI\PHPESAPI\Validator
{
    private $_rules;
    private $_auditor;
    private $_encoder;
    private $_fileValidator;

    const MAX_PARAMETER_NAME_LENGTH = 100;
    const MAX_PARAMETER_VALUE_LENGTH = 65535;

    /**
     * Validator constructor.
     *
     * @return does not return a value.
     */
    public function __construct()
    {
        $this->_auditor = \PHPESAPI\PHPESAPI\ESAPI::getAuditor('DefaultValidator');
        $this->_encoder = \PHPESAPI\PHPESAPI\ESAPI::getEncoder();
        $this->_fileValidator = new DefaultEncoder(array(
            new \PHPESAPI\PHPESAPI\Codecs\HTMLEntityCodec(),
            new \PHPESAPI\PHPESAPI\Codecs\PercentCodec()
        ));
    }

    /**
     * @inheritdoc
     */
    public function isValidInput($context, $input, $type, $maxLength, $allowNull)
    {
        try {
            $this->_assertValidInput($context, $input, $type, $maxLength, $allowNull);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param string $type      Please see corresponding isValidXX description.
     * @param int    $maxLength Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidInput($context, $input, $type, $maxLength, $allowNull)
    {
        $validationRule = new Validation\StringValidationRule($type, $this->_encoder);

        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $pattern = $config->getValidationPattern($type);
        if ($pattern !== false) {
            $validationRule->addWhitelistPattern($pattern);
        } else {
            $validationRule->addWhitelistPattern($type);
        }

        $validationRule->setMaximumLength($maxLength);
        $validationRule->setAllowNull($allowNull);

        $validationRule->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidDate($context, $input, $format, $allowNull)
    {
        try {
            $this->_assertValidDate($context, $input, $format, $allowNull);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $format    Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidDate($context, $input, $format, $allowNull)
    {
        $dvr = new Validation\DateValidationRule(
            'DateValidator',
            $this->_encoder,
            $format
        );
        $dvr->setAllowNull($allowNull);

        $dvr->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidHTML($context, $input, $maxLength, $allowNull)
    {
        try {
            $this->_assertValidHTML(
                $context,
                $input,
                $maxLength,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $maxLength Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidHTML($context, $input, $maxLength, $allowNull)
    {
        $hvr = new Validation\HTMLValidationRule(
            'HTML_Validator',
            $this->_encoder
        );
        $hvr->setMaximumLength($maxLength);
        $hvr->setAllowNull($allowNull);

        $hvr->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidCreditCard($context, $input, $allowNull)
    {
        try {
            $this->_assertValidCreditCard($context, $input, $allowNull);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidCreditCard($context, $input, $allowNull)
    {
        $ccvr = new Validation\CreditCardValidationRule(
            'CreditCard',
            $this->_encoder
        );
        $ccvr->setAllowNull($allowNull);

        $ccvr->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidDirectoryPath($context, $input, $allowNull)
    {
        try {
            $this->_assertValidDirectoryPath($context, $input, $allowNull);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidDirectoryPath($context, $input, $allowNull)
    {
        if (empty($input)) {
            if ($allowNull) {
                return;
            }

            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Input directory path required",
                "Input directory path required: context={$context}, input={$input}",
                $context
            );
        }

        $dir = new \SplFileInfo($input);

        if (!$dir->isReadable()) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Invalid directory name",
                "Invalid directory, does not exist: context={$context}, input={$input}"
            );
        }

        if (!$dir->isDir()) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Invalid directory name",
                "Invalid directory, not a directory: context={$context}, input={$input}"
            );
        }

        $canonicalPath = $dir->getRealPath();
        $canonical = $this->_fileValidator->canonicalize($canonicalPath);

        if ($input !== $canonical) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Invalid directory name",
                "Invalid directory name does not match the canonical path: context={$context}, " .
                    "input={$input}, canonical={$canonical}"
            );
        }
    }

    /**
     * @inheritdoc
     */
    public function isValidNumber($context, $input, $minValue, $maxValue, $allowNull)
    {
        try {
            $this->_assertValidNumber(
                $context,
                $input,
                $minValue,
                $maxValue,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $minValue  Please see corresponding isValidXX description.
     * @param int    $maxValue  Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidNumber($context, $input, $minValue, $maxValue, $allowNull)
    {
        $nvr = new Validation\NumberValidationRule(
            'NumberValidator',
            $this->_encoder,
            $minValue,
            $maxValue
        );
        $nvr->setAllowNull($allowNull);

        $nvr->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidInteger($context, $input, $minValue, $maxValue, $allowNull)
    {
        try {
            $this->_assertValidInteger(
                $context,
                $input,
                $minValue,
                $maxValue,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $minValue  Please see corresponding isValidXX description.
     * @param int    $maxValue  Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidInteger($context, $input, $minValue, $maxValue, $allowNull)
    {
        $nvr = new Validation\IntegerValidationRule(
            'IntegerValidator',
            $this->_encoder,
            $minValue,
            $maxValue
        );
        $nvr->setAllowNull($allowNull);

        $nvr->assertValid($context, $input);

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidDouble($context, $input, $minValue, $maxValue, $allowNull)
    {
        try {
            $this->_assertValidDouble(
                $context,
                $input,
                $minValue,
                $maxValue,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $minValue  Please see corresponding isValidXX description.
     * @param int    $maxValue  Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidDouble($context, $input, $minValue, $maxValue, $allowNull)
    {
        $this->_assertValidNumber(
            $context,
            $input,
            $minValue,
            $maxValue,
            $allowNull
        );

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidFileContent(
        $context,
        $input,
        $maxBytes,
        $allowNull
    ) {
        try {
            $this->_assertValidFileContent(
                $context,
                $input,
                $maxBytes,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $maxBytes  Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidFileContent(
        $context,
        $input,
        $maxBytes,
        $allowNull
    ) {
        if (! is_string($context)) {
            $context = 'Validate File Content';
        }
        if (! is_string($input) && $input !== null) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Input required",
                "Input was not a string or NULL: context={$context}",
                $context
            );
        }

        if (! is_numeric($maxBytes) || $maxBytes < 0) {
            $this->_auditor->warning(
                \ESAPILogger::SECURITY,
                false,
                'assertValidFileContent expected $maxBytes as positive integer.' .
                ' Falling back to AllowedFileUploadSize.'
            );
            $maxBytes = null;
        }

        if ($input === null || $input == '') {
            if ($this->allowNull) {
                return null;
            }
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Input required",
                "Input required: context={$context}",
                $context
            );
        }

        $config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        $esapiMaxBytes = $config->getAllowedFileUploadSize();

        $charEnc = mb_detect_encoding($input);
        $inputLen = mb_strlen($input, $charEnc);

        if ($inputLen > $esapiMaxBytes) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Invalid file content. Size must not exceed " .
                "{$esapiMaxBytes} bytes.",
                "Invalid file content. Input ({$inputLen} bytes) exceeds " .
                "AllowedFileUploadSize ({$esapiMaxBytes} bytes.)",
                $context
            );
        }

        if ($maxBytes !== null && $inputLen > $maxBytes) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Invalid file content. Size must not exceed " .
                "{$maxBytes} bytes.",
                "Invalid file content. Input ({$inputLen} bytes) exceeds " .
                "maximum of ({$esapiMaxBytes} bytes.)",
                $context
            );
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidListItem($context, $input, $list)
    {
        try {
            $this->_assertValidListItem($context, $input, $list);
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context Please see corresponding isValidXX description.
     * @param string $input   Please see corresponding isValidXX description.
     * @param array  $list    Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidListItem($context, $input, $list)
    {
        // Some sanity checks first
        if (! is_string($context)) {
            $context = 'ValidListItem';
        }
        if (! is_string($input) && $input !== null) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                "{$context}: Input required",
                "Input was not a string or NULL: context={$context}",
                $context
            );
        }
        if (! is_array($list)) {
            throw new \RuntimeException(
                'Validation misconfiguration - assertValidListItem expected' .
                ' an array $list!'
            );
        }

        // strict canonicalization
        $canonical = null;
        try {
            $canonical = $this->_encoder->canonicalize($input, true);
        } catch (\PHPESAPI\PHPESAPI\Errors\EncodingException $e) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                $context . ': Invalid input. Encoding problem detected.',
                'An EncodingException was thrown during canonicalization of ' .
                'the input.',
                $context
            );
        }

        if (in_array($canonical, $list, true) != true) {
            throw new \PHPESAPI\PHPESAPI\Errors\ValidationException(
                $context . ': Invalid input. Input was not a valid member of ' .
                'the list.',
                'canonicalized input was not a member of the supplied list.',
                $context
            );
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidPrintable($context, $input, $maxLength, $allowNull)
    {
        try {
            $this->_assertValidPrintable(
                $context,
                $input,
                $maxLength,
                $allowNull
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Implements corresponding isValidXX logic.
     *
     * @param string $context   Please see corresponding isValidXX description.
     * @param string $input     Please see corresponding isValidXX description.
     * @param int    $maxLength Please see corresponding isValidXX description.
     * @param bool   $allowNULL Please see corresponding isValidXX description.
     *
     * @throws ValidationException thrown if input is invalid.
     * @throws IntrusionException thrown if intrusion is detected.
     *
     * @return does not return a value.
     */
    private function _assertValidPrintable(
        $context,
        $input,
        $maxLength,
        $allowNull
    ) {
        $this->_assertValidInput(
            $context,
            $input,
            'PrintableASCII',
            $maxLength,
            $allowNull
        );

        return null;
    }

    /**
     * @inheritdoc
     */
    public function isValidRedirectLocation($context, $input, $allowNull)
    {
        return $this->isValidInput(
            $context,
            $input,
            "Redirect",
            512,
            $allowNull
        );
    }
}
