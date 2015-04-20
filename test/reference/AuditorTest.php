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
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @since  2009
 * @since  1.6
 */

require_once __DIR__ . '/../testresources/TestHelpers.php';

/**
 * This test case covers logging functioanlity.
 *
 * It verifies that the various types of log entry are logged to file as well as
 * testing DefaultLogger methods.
 *
 * @author Laura D. Bell
 * @author jah (at jahboite.co.uk)
 * @since 1.6
 */
class AuditorTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var Auditor
     */
    private $testLogger;
    private $alphanum;
    private $rnd;
    private $logFileLoc;
    /**
     * Set the first time we attempt to read the logfile.  Used to differentiate
     * between failure to read the logfile and failure to match a pattern in the
     * logfile.
     *
     * @var boolean
     */
    private $logfileIsReadable = false;
    
    protected function setUp()
    {
        $this->logFileLoc = getLogFileLoc();
        $this->testLogger = ESAPI::getAuditor(__CLASS__);
        $this->testLogger->setLevel(Auditor::ALL);
    }

    public function testSetLevelOffCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelOffCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelOffCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelOffCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelOffCheckError()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelOffCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::OFF);
        $this->assertFalse($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelTraceCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelTraceCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelTraceCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelTraceCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelTraceCheckError()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelTraceCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::TRACE);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelDebugCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelDebugCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertTrue($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelDebugCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertTrue($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelDebugCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertTrue($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelDebugCheckError()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertTrue($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelDebugCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::DEBUG);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelInfoCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelInfoCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertFalse($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelInfoCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertTrue($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelInfoCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertTrue($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelInfoCheckError()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertTrue($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelInfoCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::INFO);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelWarningCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelWarningCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertFalse($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelWarningCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertFalse($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelWarningCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertTrue($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelWarningCheckError()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertTrue($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelWarningCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::WARNING);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelErrorCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelErrorCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertFalse($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelErrorCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertFalse($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelErrorCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertFalse($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelErrorCheckError()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertTrue($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelErrorCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::ERROR);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelFatalCheckTrace()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertFalse($this->testLogger->isTraceEnabled());
    }

    public function testSetLevelFatalCheckDebug()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertFalse($this->testLogger->isDebugEnabled());
    }

    public function testSetLevelFatalCheckInfo()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertFalse($this->testLogger->isInfoEnabled());
    }

    public function testSetLevelFatalCheckWarning()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertFalse($this->testLogger->isWarningEnabled());
    }

    public function testSetLevelFatalCheckError()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertFalse($this->testLogger->isErrorEnabled());
    }

    public function testSetLevelFatalCheckFatal()
    {
        $this->testLogger->setLevel(Auditor::FATAL);
        $this->assertTrue($this->testLogger->isFatalEnabled());
    }

    public function testSetLevelMultipleLogsExpectedTrue()
    {
        //Now test to see if a change to the logging level in one log affects other logs
        $newLogger = ESAPI::getAuditor('test_num2');
        $this->testLogger->setLevel(Auditor::OFF);
        $newLogger->setLevel(Auditor::INFO);
        $log_1_result = $this->testLogger->isInfoEnabled();
        $log_2_result = $newLogger->isInfoEnabled();

        $this->assertTrue(!$log_1_result && $log_2_result);
    }

    /*
     * This test is bogus.  It is the same as testSetLevelMultipleLogsExpectedTrue
     * but with the opposite expectation.
     */
#    function testSetLevelMultipleLogsExpectedFalse() {
#        //Now test to see if a change to the logging level in one log affects other logs
#        $newLogger = ESAPI::getAuditor('test_num2');
#        $this->testLogger->setLevel(Auditor::OFF);
#        $newLogger->setLevel(Auditor::INFO);
#        $log_1_result = $this->testLogger->isInfoEnabled();
#        $log_2_result = $newLogger->isInfoEnabled();

#        $this->assertTrue($log_1_result &&!$log_2_result);
#    }

    public function testLoggingToFile()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Test message. {$r}";
        $this->testLogger->fatal(Auditor::SECURITY, true, $logMsg);
        $logFileIsReadable = $this->verifyLogEntry("{$logMsg}", $testMsg);
        $this->assertTrue($logFileIsReadable, $testMsg);

        return $logFileIsReadable;
    }

    public function testFatalSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'SECURITY', true, $logMsg);
        $this->testLogger->fatal(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'SECURITY', false, $logMsg);
        $this->testLogger->fatal(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'SECURITY', true, $logMsg);
        $this->testLogger->fatal(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $throwable = new Exception('This is a message from a generic exception.');
        $expected = $this->getExpected('FATAL', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->fatal(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'SECURITY', true, $logMsg);
        $this->testLogger->warning(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'SECURITY', false, $logMsg);
        $this->testLogger->warning(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'SECURITY', true, $logMsg);
        $this->testLogger->warning(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $throwable = new ValidationException(
            'This is a user message from a ValidationException.',
            'This is a log message from a ValidationException.'
        );
        $expected = $this->getExpected('WARNING', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->warning(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'SECURITY', true, $logMsg);
        $this->testLogger->error(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'SECURITY', false, $logMsg);
        $this->testLogger->error(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'SECURITY', true, $logMsg);
        $this->testLogger->error(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $throwable = new Exception('This is a message from a generic exception.');
        $expected = $this->getExpected('ERROR', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->error(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'SECURITY', true, $logMsg);
        $this->testLogger->info(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'SECURITY', false, $logMsg);
        $this->testLogger->info(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'SECURITY', true, $logMsg);
        $this->testLogger->info(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $throwable = new Exception('This is a message from a generic exception.');
        $expected = $this->getExpected('INFO', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->info(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'SECURITY', true, $logMsg);
        $this->testLogger->debug(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'SECURITY', false, $logMsg);
        $this->testLogger->debug(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'SECURITY', true, $logMsg);
        $this->testLogger->debug(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $throwable = new Exception('This is a message from a generic exception.');
        $expected = $this->getExpected('DEBUG', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->debug(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceSecuritySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'SECURITY', true, $logMsg);
        $this->testLogger->trace(Auditor::SECURITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceSecurityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'SECURITY', false, $logMsg);
        $this->testLogger->trace(Auditor::SECURITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceNullException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'SECURITY', true, $logMsg);
        $this->testLogger->trace(Auditor::SECURITY, true, $logMsg, null);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceWithException()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $throwable = new Exception('This is a message from a generic exception.');
        $expected = $this->getExpected('TRACE', 'SECURITY', false, $logMsg, get_class($throwable));
        $this->testLogger->trace(Auditor::SECURITY, false, $logMsg, $throwable);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'USABILITY', true, $logMsg);
        $this->testLogger->fatal(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'USABILITY', false, $logMsg);
        $this->testLogger->fatal(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'USABILITY', true, $logMsg);
        $this->testLogger->warning(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'USABILITY', false, $logMsg);
        $this->testLogger->warning(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'USABILITY', true, $logMsg);
        $this->testLogger->error(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'USABILITY', false, $logMsg);
        $this->testLogger->error(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'USABILITY', true, $logMsg);
        $this->testLogger->info(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'USABILITY', false, $logMsg);
        $this->testLogger->info(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'USABILITY', true, $logMsg);
        $this->testLogger->debug(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'USABILITY', false, $logMsg);
        $this->testLogger->debug(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceUsabilitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'USABILITY', true, $logMsg);
        $this->testLogger->trace(Auditor::USABILITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceUsabilityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'USABILITY', false, $logMsg);
        $this->testLogger->trace(Auditor::USABILITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalPerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->fatal(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalPerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->fatal(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningPerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->warning(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningPerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->warning(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorPerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->error(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorPerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->error(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoPerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->info(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoPerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->info(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugPerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->debug(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugPerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->debug(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTracePerformanceSuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'PERFORMANCE', true, $logMsg);
        $this->testLogger->trace(Auditor::PERFORMANCE, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTracePerformanceFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'PERFORMANCE', false, $logMsg);
        $this->testLogger->trace(Auditor::PERFORMANCE, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->fatal(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testFatalFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Fatal level test message. {$r}";
        $expected = $this->getExpected('FATAL', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->fatal(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->warning(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testWarningFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Warning level test message. {$r}";
        $expected = $this->getExpected('WARNING', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->warning(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->error(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testErrorFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Error level test message. {$r}";
        $expected = $this->getExpected('ERROR', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->error(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->info(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testInfoFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Info level test message. {$r}";
        $expected = $this->getExpected('INFO', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->info(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->debug(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testDebugFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Debug level test message. {$r}";
        $expected = $this->getExpected('DEBUG', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->debug(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceFunctionalitySuccess()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'FUNCTIONALITY', true, $logMsg);
        $this->testLogger->trace(Auditor::FUNCTIONALITY, true, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    public function testTraceFunctionalityFailure()
    {
        $testMsg = null;
        $r = getRandomAlphaNumString(32);
        $logMsg = "Trace level test message. {$r}";
        $expected = $this->getExpected('TRACE', 'FUNCTIONALITY', false, $logMsg);
        $this->testLogger->trace(Auditor::FUNCTIONALITY, false, $logMsg);
        $this->assertTrue($this->verifyLogEntry($expected, $testMsg), $testMsg);
    }

    /**
     * @depends testLoggingToFile
     */
    public function testCRLFRemoval($logFileIsReadable)
    {
        $failMessage = null;
        if ($logFileIsReadable === false) {
            $failMessage = 'CRLF encoding could not be tested because we' .
                 ' could not read the logfile.';
        }
        $testMsg = null;
        $r = getRandomAlphaNumString(16);
        $expected = $this->getExpected('FATAL', 'SECURITY', true, "{$r}_{$r}");
        $this->testLogger->fatal(Auditor::SECURITY, true, "{$r}\n{$r}");
        $result = $this->verifyLogEntry($expected, $testMsg);
        
        $this->assertTrue($result, $failMessage);
    }

    /**
     * @depends testLoggingToFile
     */
    public function testHTMLEncoding($logFileIsReadable)
    {
        $failMessage = null;
        if (ESAPI::getSecurityConfiguration()->getLogEncodingRequired() ===
            false
        ) {
            $failMessage =
                'HTML encoding cannot be tested until the LogEncodingRequired' .
                ' property is set to true. This test has not actually failed.';
        } elseif ($logFileIsReadable === false) {
            $failMessage = 'HTML encoding could not be tested because we' .
                 ' could not read the logfile.';
        }
        $testMsg = null;
        $r = getRandomAlphaNumString(16);
        $expected = $this->getExpected('FATAL', 'SECURITY', true, "{$r}&amp;{$r}");
        $this->testLogger->fatal(Auditor::SECURITY, true, "{$r}&{$r}");
        $result = $this->verifyLogEntry($expected, $testMsg);
        
        $this->assertTrue($result, $failMessage);
    }

    /**
     * Helper function to read the logfile and match the supplied pattern.
     * It is expected that the supplied pattern contains a unique string to
     * avoid false positives.
     * Sets $msg with a descriptive message.
     *
     * @param  $expected the string pattern for a preg_match().
     * @param  &$msg reference to a string message which will be set here.
     *
     * @return boolean true if the pattern is matched in the logfile, otherwise
     *         false.
     */
    private function verifyLogEntry($expected, &$msg)
    {
        if ($this->logFileLoc === false) {
            $msg = 'Cannot find the logfile!';

            return false; // another fail because we couldn't find the logfile.
        }

        // read the logfile
        $result = fileContainsExpected($this->logFileLoc, $expected);

        if ($result === null) {
            $this->logFileLoc = false;
            $msg = "Failed to read the log file from {$this->logFileLoc}. All" .
                ' further LoggerTest tests will fail!';

            return false;
        } elseif ($result === true) {
            $msg = 'Log file contains the expected entry. Logging to file' .
                    ' with the supplied parameters is verified.';

            return true;
        } else {
            $msg = 'Log file does not contain the expected entry. Cannot verify' .
                ' that logging to file is working for the supplied parameters.';

            return false;
        }
    }

    /**
     * Helper method uses the supplied parameters to construct a pattern for
     * preg_match and which attempts to model log entries.  It is important to
     * note that if changes are made to the format of log entries {@see
     * DefaultLogger::log()} then this method will need to be modified
     * accordingly.
     *
     * @param  $level string uppercase log level.
     * @param  $type string uppercase log entry type.
     * @param  $success boolean true for a success log event, false otherwise.
     * @param  $msg string log message as passed to the DefaultLogger method.
     * @param  $exceptionClassName string optional class name of an exception
     *         passed to DefaultLogger methods.
     *
     * @return string pattern (incl. terminators) for preg_match().
     */
    private function getExpected($level, $type, $success, $msg, $exceptionClassName = null)
    {
        $date = '[0-9-]{10,10} [0-9:]{8,8} [+-][0-9:]{5,5}';
        $success = $success ? '-SUCCESS' : '-FAILURE';
        $appName
            = ESAPI::getSecurityConfiguration()->getLogApplicationName() === true
            ? ' ' . ESAPI::getSecurityConfiguration()->getApplicationName()
            : '';
        $name = __CLASS__;
        $serverName
            = '((?:(?:[0-9a-zA-Z][0-9a-zA-Z\-]{0,61}[0-9a-zA-Z])\.)*[a-zA-Z]{2,4}|[0-9a-zA-Z][0-9a-zA-Z\-]{0,61}[0-9a-zA-Z]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))';
        $localSocket = "{$serverName}:[0-9]{1,5}";
        $username = '[^@]+@';
        $remoteAddr = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|UnknownRemoteHost)';
        $sessionID = '([0-9]{1,7}|SessionUnknown)';
        if ($exceptionClassName !== null) {
            $msg .= " exception '{$exceptionClassName}'";
        }

        return "{$date} {$level}{$appName} {$name} {$type}{$success} {$localSocket} {$username}{$remoteAddr}\[ID:{$sessionID}\] {$msg}";
    }
}
