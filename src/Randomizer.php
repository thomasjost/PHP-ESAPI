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
 * @package   ESAPI
 *
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Use this ESAPI security control to get random numbers and strings.
 *
 * The idea behind this interface is to define a set of functions for
 * creating better random numbers and strings.
 *
 * @category  OWASP
 *
 * @package   ESAPI
 *
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
interface Randomizer
{

    /**
     * Gets a random string of a desired length and character set.  The use of
     * java.security.SecureRandom is recommended because it provides a
     * cryptographically strong pseudo-random number generator. If SecureRandom
     * is not used, the pseudo-random number gernerator used should comply with the
     * statistical random number generator tests specified in
     * <a href="http://csrc.nist.gov/cryptval/140-2.htm">
     * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section
     * 4.9.1.
     *
     * @param int    $length       the length of the string
     * @param string $characterSet The set of characters to include in the created
     *                             random string
     *
     * @return string the random string of the desired length and character set
     */
    public function getRandomString($length, $characterSet);

    /**
     * Returns a random boolean.  The use of java.security.SecureRandom
     * is recommended because it provides a cryptographically strong
     * pseudo-random number generator. If SecureRandom is not used, the
     * pseudo-random number gernerator used should comply with the
     * statistical random number generator tests specified in
     * <a href="http://csrc.nist.gov/cryptval/140-2.htm">
     * FIPS 140-2, Security Requirements for Cryptographic Modules</a>,
     * section 4.9.1.
     *
     * @return bool TRUE or FALSE, randomly
     */
    public function getRandomBoolean();

    /**
     * Gets the random integer. The use of java.security.SecureRandom
     * is recommended because it provides a cryptographically strong
     * pseudo-random number generator. If SecureRandom is not used, the
     *  pseudo-random number gernerator used should comply with the
     * statistical random number generator tests specified in
     * <a href="http://csrc.nist.gov/cryptval/140-2.htm">
     * FIPS 140-2, Security Requirements for Cryptographic Modules</a>,
     * section 4.9.1.
     *
     * @param int $min The minimum integer that will be returned
     * @param int $max The maximum integer that will be returned
     *
     * @return int the random integer
     */
    public function getRandomInteger($min, $max);

    /**
     * Gets the random long. The use of java.security.SecureRandom
     * is recommended because it provides a cryptographically strong
     * pseudo-random number generator. If SecureRandom is not used, the
     * pseudo-random number gernerator used should comply with the
     * statistical random number generator tests specified in
     * <a href="http://csrc.nist.gov/cryptval/140-2.htm">
     * FIPS 140-2, Security Requirements for Cryptographic Modules</a>,
     * section 4.9.1.
     *
     * @return int the random long
     */
    public function getRandomLong();

    /**
     * Returns an unguessable random filename with the specified extension.
     * This method could call getRandomString(length, charset) from this
     * Class with the desired length and alphanumerics as the charset
     * then merely append "." + extension.
     *
     * @param string $extension Extension to add to the random filename
     *
     * @return string a random unguessable filename ending with the specified
     *                extension
     */
    public function getRandomFilename($extension = '');

    /**
     * Gets the random real.  The use of java.security.SecureRandom
     * is recommended because it provides a cryptographically strong pseudo-random
     * number generator. If SecureRandom is not used, the pseudo-random number
     * generator used should comply with the statistical random number generator
     * tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
     * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section
     * 4.9.1.
     *
     * @param float $min The minimum real number that will be returned
     * @param float $max The maximum real number that will be returned
     *
     * @return float the random real
     */
    public function getRandomReal($min, $max);

    /**
     * Generates a random GUID.  This method could use a hash of random Strings,
     * the current time, and any other random data available.  The format is a
     * well-defined sequence of 32 hex digits grouped into chunks of 8-4-4-4-12.
     *
     * @throws EncryptionException if hashing or encryption fails
     *
     * @return string the GUID
     */
    public function getRandomGUID();
}
