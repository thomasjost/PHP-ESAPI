<?php
/**
 * OWASP Enterprise Security API (ESAPI).
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * PHP version 5.2
 *
 * @category  OWASP
 *
 * @package   ESAPI_Codecs
 *
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Reference implementation of the CSS codec.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Codecs
 *
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

 namespace PHPESAPI\PHPESAPI\Codecs;

class PercentCodec extends Codec
{
    /**
     * {@inheritdoc}
     */
    public function encodeCharacter($immune, $c)
    {
        //detect encoding, special-handling for chr(172) and chr(128) to chr(159)
        //which fail to be detected by mb_detect_encoding()
        $initialEncoding = $this->detectEncoding($c);

        // Normalize encoding to UTF-32
        $_4ByteUnencodedOutput = $this->normalizeEncoding($c);

        // Start with nothing; format it to match the encoding of the string passed
        //as an argument.
        $encodedOutput = mb_convert_encoding("", $initialEncoding);

        // Grab the 4 byte character.
        $_4ByteCharacter = $this->forceToSingleCharacter($_4ByteUnencodedOutput);

        // Get the ordinal value of the character.
        list(, $ordinalValue) = unpack("N", $_4ByteCharacter);

        // check for immune characters
        if ($this->containsCharacter($_4ByteCharacter, $immune)) {
            // character is immune, therefore return character...
            return $encodedOutput . chr($ordinalValue);
        }

        // check for alphanumeric characters
        $hex = $this->getHexForNonAlphanumeric($_4ByteCharacter);
        if ($hex === null) {
            //character is alphanumric, therefore return the character...
            return $encodedOutput . chr($ordinalValue);
        }

        if ($ordinalValue < 16) {
            // ordinalValue is less than 16, therefore prepend hex with a 0...
            $hex = "0" . strtoupper($hex);
        }

        return "%" . strtoupper($hex);
    }

    /**
     * {@inheritdoc}
     */
    public function decodeCharacter($input)
    {
        if (mb_substr($input, 0, 1, UTF32) === null) {
            // 1st character is null, so return null
            // eat the 1st character off the string and return null
            //todo: this is not neccessary
            $input = mb_substr($input, 1, mb_strlen($input, UTF32), UTF32);

            return $this->respondWithDetails();
        }

        // if this is not an encoded character, return null
        if (mb_substr($input, 0, 1, UTF32) != $this->normalizeEncoding('%')) {
            // 1st character is not part of encoding pattern, so return null
            return $this->respondWithDetails();
        }

        // 1st character is part of encoding pattern...

        // check for exactly two hex digits following
        $potentialHexString = $this->normalizeEncoding('');
        $limit              = min(2, mb_strlen($input, UTF32) - 1);
        for ($i = 0; $i < $limit; $i++) {
            $c = mb_substr($input, 1 + $i, 1, UTF32);
            if ($c != '') {
                $ph = $this->_parseHex($c);
                if ($ph !== null) {
                    $potentialHexString .= $c;
                }
            }
        }
        if (mb_strlen($potentialHexString, UTF32) == 2) {
            $charFromHex = $this->normalizeEncoding(
                $this->_parseHex($potentialHexString)
            );
            return $this->respondWithDetails(
                $charFromHex,
                mb_substr($input, 0, 3, UTF32)
            );
        }

        $this->respondWithDetails();
    }

    /**
     * Parse a hex encoded entity.
     *
     * @param string $input Hex encoded input (such as 437ae;)
     *
     * @return string Returns an array containing two objects:
     *                'decodedCharacter' => NULL if input is NULL, the character
     *                of input after decoding 'encodedString' => the string that
     *                was decoded or found to be malformed
     */
    private function _parseHex($input)
    {
        //todo: encoding should be UTF-32, so why detect it?
        $hexString   = mb_convert_encoding("", mb_detect_encoding($input));
        $inputLength = mb_strlen($input, UTF32);
        for ($i = 0; $i < $inputLength; $i++) {
            // Get the ordinal value of the character.
            list(, $ordinalValue) = unpack("N", mb_substr($input, $i, 1, UTF32));

            // if character is a hex digit, add it and keep on going
            if (preg_match("/^[0-9a-fA-F]/", chr($ordinalValue))) {
                // hex digit found, add it and continue...
                $hexString .= mb_substr($input, $i, 1, UTF32);
            } elseif (mb_substr($input, $i, 1, UTF32) == $this->normalizeEncoding(';')) {
                break;
            } else {
                // otherwise just quit
                break;
            }
        }
        try {
            // trying to convert hexString to integer...
            if ($hexString == mb_convert_encoding("", mb_detect_encoding($input))) {
                return null;
            }
            $parsedInteger = (int) hexdec($hexString);
            if ($parsedInteger <= 0xFF) {
                $parsedCharacter = chr($parsedInteger);
            } else {
                $parsedCharacter = mb_convert_encoding('&#' . $parsedInteger . ';', UTF8, 'HTML-ENTITIES');
            }

            return $parsedCharacter;
        } catch (\Exception $e) {
            //TODO: throw an exception for malformed entity?
            return null;
        }
    }
}
