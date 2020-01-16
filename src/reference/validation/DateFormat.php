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
 * @package   ESAPI_Reference_Validation
 *
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
 * Helper class.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference_Validation
 *
 * @author    Johannes B. Ullrich <jullrich@sans.edu>
 * @author    jah <jah@jahboite.co.uk>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
namespace PHPESAPI\PHPESAPI\Reference\Validation;

class DateFormat
{
    private $_format = [];

    const DATE_SMALL = 'SMALL';
    const DATE_MEDIUM = 'MEDIUM';
    const DATE_LONG = 'LONG';
    const DATE_FULL = 'FULL';

    /**
     * Constructor.
     *
     * @param string $format Date format
     * @param string $type   date type
     *
     * @return does not return a value.
     */
    public function __construct($format = null, $type = self::DATE_MEDIUM)
    {
        $this->setformat($format, $type);
    }

    /**
     * Helper function.
     *
     * @param string $format Date format
     * @param string $type   date type
     *
     * @return does not return a value.
     */
    public function setformat($format, $type = self::DATE_MEDIUM)
    {
        switch ($type) {
            case self::DATE_SMALL:
                if (is_array($format) && key_exists(self::DATE_SMALL, $format)) {
                    $this->_format[self::DATE_SMALL] = $format[self::DATE_SMALL];
                } else {
                    $this->_format[self::DATE_SMALL] = $format;
                }
                break;

            case self::DATE_LONG:
                if (is_array($format) && key_exists(self::DATE_LONG, $format)) {
                    $this->_format[self::DATE_LONG] = $format[self::DATE_LONG];
                } else {
                    $this->_format[self::DATE_LONG] = $format;
                }
                break;

            case self::DATE_FULL:
                if (is_array($format) && key_exists(self::DATE_FULL, $format)) {
                    $this->_format[self::DATE_FULL] = $format[self::DATE_FULL];
                } else {
                    $this->_format[self::DATE_FULL] = $format;
                }
                break;

            case self::DATE_MEDIUM:
            default:
                if (is_array($format) && key_exists(self::DATE_MEDIUM, $format)) {
                    $this->_format[self::DATE_MEDIUM] = $format[self::DATE_MEDIUM];
                } else {
                    $this->_format[self::DATE_MEDIUM] = $format;
                }
                break;
        }
    }
}
