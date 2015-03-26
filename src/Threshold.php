<?php
/**
 * OWASP Enterprise Security API (ESAPI)
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
 * @package   ESAPI
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Models a simple threshold as a count and an interval, along with a set of
 * actions to take if the threshold is exceeded.
 * 
 * These thresholds are used to define when the accumulation of a particular
 * event has met a set number within the specified time period. Once a threshold
 * value has been met, various actions can be taken at that point.
 *
 * PHP version 5.2
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    Jeff Williams <jeff.williams@aspectsecurity.com>
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class Threshold
{

    /** The name of this threshold. */
    public $name = null;

    /** The count at which this threshold is triggered. */
    public $count = 0;

    /** 
     * The time frame within which 'count' number of actions has to be detected in 
     * order to trigger this threshold.
     */
    public $interval = 0;

    /** 
     * The list of actions to take if the threshold is met. It is expected that 
     * this is a list of Strings, but your implementation could have this be a 
     * list of any type of 'actions' you wish to define. 
     */
    public $actions = null;

    /**
     * Constructs a threshold that is composed of its name, its threshold count, 
     * the time window for the threshold, and the actions to take if the threshold 
     * is triggered.
     * 
     * @param string $name     The name of this threshold.
     * @param int    $count    The count at which this threshold is triggered.
     * @param int    $interval The time frame within which 'count' number of actions
     *                         has to be detected in order to trigger this threshold.
     * @param array  $actions  The list of actions to take if the threshold is met.
     * 
     * @return Does not return a value.
     */
    public function __construct($name, $count, $interval, $actions)
    {
        $this->name = $name;
        $this->count = $count;
        $this->interval = $interval;
        $this->actions = $actions;
    }

}
