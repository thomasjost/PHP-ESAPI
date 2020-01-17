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
 * @package   ESAPI_Reference
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */
namespace PHPESAPI\PHPESAPI\Test\Reference;

/**
 * Require Test Helpers and SecurityConfiguration
 */
require_once dirname(__DIR__) . '/testresources/TestHelpers.php';

/**
 * Test for the DefaultIntrusionDetector implementation of the IntrusionDetector
 * interface.  Please note that this test case expects a custom version of ESAPI.xml
 * which contains IntrusionDetector events designed for these tests.
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class IntrusionDetectorTest extends \PHPUnit\Framework\TestCase
{
    private $_logFileLoc;
    private $_logDateFormat;
    private $_restoreSecCon;

    /**
     * Constructor swaps the SecurityConfiguration currently in use with one which
     * contains custom IDS events designed specifically for this UnitTestCase.
     */
    protected function setUp()
    {
        $this->_restoreSecCon = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
        \PHPESAPI\PHPESAPI\ESAPI::setSecurityConfiguration(null);
        // Use a custom properties file.
        $sc = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration(
            __DIR__ . '/../testresources/ESAPI_IDS_Tests.xml'
        );

        $this->_logFileLoc = getLogFileLoc();
        $this->_logDateFormat = $sc->getLogFileDateFormat();
    }

    /**
     * Destructor restores the original SecurityConfiguration.
     */
    public function __destruct()
    {
        \PHPESAPI\PHPESAPI\ESAPI::setSecurityConfiguration($this->_restoreSecCon);
    }

    /**
     * Test to ensure that EnterpriseSecurityExceptions are automatically added
     * to the IntrusionDetector and that the IntrusionDetector logs the
     * exceptions logMessage.
     *
     * @return bool True on Pass.
     */
    public function testExceptionAutoAdd()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $logMsg = 'testExceptionAutoAdd_';
        $logMsg .= getRandomAlphaNumString(32);
        new \PHPESAPI\PHPESAPI\Errors\EnterpriseSecurityException('user message - testExceptionAutoAdd', $logMsg);

        $m = 'Test attempts to detect exception log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $logMsg),
            $m
        );
    }

    /**
     * Test of addException method of class DefaultIntrusionDetector.
     *
     * @return bool True on Pass.
     */
    public function testAddException()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $logMsg = 'testAddException_';
        $logMsg .= getRandomAlphaNumString(32);
        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addException(new \Exception($logMsg));

        $m = 'Test attempts to detect exception log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $logMsg),
            $m
        );
    }

    /**
     * Test of addEvent method of DefaultIntrusionDetector.  This test checks
     * that a threshold exceeded message is logged and thus tests the addEvent,
     * addSecurityEvent and Event.increment methods and that takeSecurityAction
     * performs the 'log' action.
     *
     * @return bool True on Pass.
     */
    public function testAddEvent()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'AddEventTest';
        $threshold = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new \DateTime;

        // add event
        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $find, $date, 5, $this->_logDateFormat),
            $m
        );
    }

    /**
     * This test shows that IntrusionExceptions can be tracked by
     * IntrusionDetector.
     *
     * @return bool True on Pass.
     */
    public function testAddIntrusionExceptionIsTracked()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'IntrusionException';
        $threshold = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new \DateTime;

        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addException(
            new \PHPESAPI\PHPESAPI\Errors\IntrusionException(
                'Naughty User.',
                'testAddIntrusionExceptionIsTracked'
            )
        );

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $find, $date, 5, $this->_logDateFormat),
            $m
        );
    }

    /**
     * Test Rapid events
     *
     * @return bool True on Pass.
     */
    public function testRapidIDSEvents()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'RapidEventTest';
        $threshold = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new \DateTime;

        // Generate Exceptions
        $ids = \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector();
        for ($i = 1; $i <= $threshold->count; $i++) {
            $ids->addEvent(
                $eventName,
                'This is a Test Event for IntrusionDetectorTest.'
            );
        }

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $find, $date, 5, $this->_logDateFormat),
            $m
        );
    }

    /**
     * Once IntrusionDetector has been triggered, it can be triggered again with
     * another occurrence of the same event
     *
     * @return bool True on Pass.
     */
    public function testTripTwice()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'RapidEventTest';
        $threshold = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new \DateTime;

        // Note that the previous test testRapidValidationErrors has triggered
        // IDS for this event so we only need one more event to trigger again.
        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $find, $date, 5, $this->_logDateFormat),
            $m
        );
    }

    /**
     * This test will trigger IDS at a point which demonstrates the calculation
     * of event intervals.  Using a threshold that triggers after 5 events
     * within 5 seconds, four events will occur at 1 second intervals, then a
     * pause of 3 seconds and then 3 more events in quick succession.  IDS
     * should not trigger until the 7th event.
     *
     *                                   *
     *         e   e   e   e           eee
     *         |-+-|-+-|-+-|-+-|-+-|-+-|-+-|-+-|
     *         0   1   2   3   4   5   6   7   8
     *                 |___________________|
     *                   5 second interval
     *
     * @return bool True on Pass.
     */
    public function testSlidingInterval()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'SlidingIntervalTestEvent';
        $threshold = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new \DateTime;

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';

        // Generate 4 events at 1 sec intervals
        for ($i = 0; $i < 4; $i++) {
            \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addEvent(
                $eventName,
                'This is a Test Event for IntrusionDetectorTest.'
            );
            usleep(1000000);
        }
        // Sleep for a further 2 secs (for a total of 3 secs between this and
        // the next event.
        usleep(2000000);

        // The following two events should not trigger...
        ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );
        $this->assertFalse(
            fileContainsExpected($this->_logFileLoc, $find, $date, 10, $this->_logDateFormat),
            $m
        );
        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );
        $this->assertFalse(
            fileContainsExpected($this->_logFileLoc, $find, $date, 10, $this->_logDateFormat),
            $m
        );

        // OK this event SHOULD trigger!
        \PHPESAPI\PHPESAPI\ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $find, $date, 10, $this->_logDateFormat),
            $m
        );
    }
}
