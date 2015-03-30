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
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Reference implementation of an Intrusion Event.
 *
 * Represents the count of and times at which a user generated an event that
 * corresponds to a defined IntrusionDetector threshold.  The intrusion detector
 * stores instances of events and invokes their increment method which
 * determines whether the corresponding threshold has been reached.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @author    Jeff Williams <jeff.williams@aspectsecurity.com>
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class Event
{
    private $_key;
    private $_times = array();

    /**
     * @var int The number of times this event occurred for a given user.
     */
    public $count = 0;

    /**
     * Constructor stores the supplied key as the event name.
     *
     * @param string $key A name by which the event is known e.g.
     *                   'IntegrityException'.
     *
     */
    public function __construct($key)
    {
        $this->_key = $key;
    }

    /**
     * The increment method increments the number of times this event occurred
     * for this user.
     *
     * Each time increment is called it will decide whether or not to throw an
     * IntrusionException based on the supplied count and interval parameters.
     * If $count is exceeded within $interval seconds then the exception will be
     * thrown.  This implementation maintains a kind of sliding window of
     * timestamps so that it can track event occurrences over time.
     *
     * @param int $count    The event count that will trigger Intrusion Detection
     *                      within the supplied interval.
     * @param int $interval The number of seconds within which the supplied quota of
     *                      event occurrences will trigger Intrusion Detection.
     *
     */
    public function increment($count, $interval)
    {
        $now = null;
        if (function_exists('microtime')) {
            $now = microtime(true);
            $interval = (float) $interval;
        } else {
            $now = time();
        }

        $this->count++;
        array_push($this->_times, $now);

        // if the threshold has been exceeded
        while (sizeof($this->_times) > $count) {
            array_shift($this->_times);
        }

        if (sizeof($this->_times) == $count) {
            $past = reset($this->_times);
            if ($past === false) {
                // this should not happen because events are validated in
                // SecurityConfiguration...
                $past = $now;
            }
            $present = $now;
            if ($present - $past < $interval) {
                throw new IntrusionException(
                    "Threshold exceeded",
                    "Exceeded threshold for " . $this->_key
                );
            }
        }
    }
}
