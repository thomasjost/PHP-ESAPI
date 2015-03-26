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
 * Use this ESAPI security control to manage ESAPI security control
 * functions.
 * 
 * The idea behind this interface is to centralize ESAPI security control
 * management.
 * 
 * @category  OWASP
 * @package   ESAPI
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
interface SecurityConfiguration
{

    /**
     * Gets the application name, used for logging
     * 
     * @return string the name of the current application
     */
    public function getApplicationName();

    /**
     * Gets the master password. This password can be used to encrypt/decrypt other
     * files or types of data that need to be protected by your application.
     * 
     * @return string the current master password
     */
    public function getMasterKey();

    /**
     * Gets the master salt that is used to salt stored password hashes and any 
     * other location where a salt is needed.
     * 
     * @return string the current master salt
     */
    public function getMasterSalt();

    /**
     * Gets the allowed file extensions for files that are uploaded to this 
     * application.
     * 
     * @return array a list of the current allowed file extensions
     */
    public function getAllowedFileExtensions();

    /**
     * Gets the maximum allowed file upload size.
     * 
     * @return int the current allowed file upload size
     */
    public function getAllowedFileUploadSize();

    /**
     * Gets the name of the password parameter used during user authentication.
     * 
     * @return string the name of the password parameter
     */
    public function getPasswordParameterName();

    /**
     * Gets the name of the username parameter used during user authentication.
     * 
     * @return string the name of the username parameter
     */
    public function getUsernameParameterName();

    /**
     * Gets the encryption algorithm used by ESAPI to protect data.
     * 
     * @return string the current encryption algorithm
     */
    public function getEncryptionAlgorithm();

    /**
     * Gets the hashing algorithm used by ESAPI to hash data.
     * 
     * @return string the current hashing algorithm
     */
    public function getHashAlgorithm();

    /**
     * Gets the character encoding scheme supported by this application. This is 
     * used to set the character encoding scheme on requests and responses when 
     * setCharacterEncoding() is called on SafeRequests and SafeResponses. This 
     * scheme is also used for encoding/decoding URLs and any other place where 
     * the current encoding scheme needs to be known.
     * <br><br>
     * Note: This does not get the configured response content type. That is 
     * accessed by calling getResponseContentType().
     * 
     * @return string the current character encoding scheme
     */
    public function getCharacterEncoding();

    /**
     * Gets the digital signature algorithm used by ESAPI to generate and verify 
     * signatures.
     * 
     * @return string the current digital signature algorithm
     */
    public function getDigitalSignatureAlgorithm();

    /**
     * Gets the random number generation algorithm used to generate random numbers 
     * where needed.
     * 
     * @return string the current random number generation algorithm
     */
    public function getRandomAlgorithm();

    /**
     * Gets the number of login attempts allowed before the user's account is 
     * locked. If this many failures are detected within the alloted time period, 
     * the user's account will be locked.
     * 
     * @return int the number of failed login attempts that cause an account to be 
     *             locked
     */
    public function getAllowedLoginAttempts();

    /**
     * getAllowedIncludes returns an array of include files that are allowed to be 
     * included by PHP. This is a ESAPI extension for PHP
     * 
     * @return array an array of allowed includes
     */
    public function getAllowedIncludes();
    
    /**
     * getAllowedResources returns an array of resources (files) that are permitted.
     * This is a new addition for the ESAPI for PHP project, but may be relevant 
     * for other ports, too.
     * 
     * @return array an array of allowed resources
     */
    public function getAllowedResources();
    
    /**
     * Gets the maximum number of old password hashes that should be retained. 
     * These hashes can be used to ensure that the user doesn't reuse the specified 
     * number of previous passwords when they change their password.
     * 
     * @return int the number of old hashed passwords to retain
     */
    public function getMaxOldPasswordHashes();

    /**
     * Gets the intrusion detection quota for the specified event.
     * 
     * @param string $eventName the name of the event whose quota is desired
     * 
     * @return int the Quota that has been configured for the specified type of 
     *             event
     */
    public function getQuota($eventName);

    /**
     * Allows for complete disabling of all intrusion detection mechanisms.
     * 
     * @return bool true if intrusion detection should be disabled.
     */
    public function getDisableIntrusionDetection();

    /**
     * Gets the name of the ESAPI resource directory as a String.
     * 
     * @return string The ESAPI resource directory.
     */
    public function getResourceDirectory();

    /**
     * Sets the ESAPI resource directory.
     * 
     * @param string $dir The location of the resource directory.
     * 
     * @return Does not return a value.
     */
    public function setResourceDirectory($dir);

    /**
     * Gets the content type for responses used when setSafeContentType() is called.
     * <br><br>
     * Note: This does not get the configured character encoding scheme. That is 
     * accessed by calling getCharacterEncoding().
     * 
     * @return string The current content-type set for responses.
     */
    public function getResponseContentType();

    /**
     * Gets the length of the time to live window for remember me tokens (in 
     * milliseconds).
     * 
     * @return int The time to live length for generated remember me tokens.
     */
    public function getRememberTokenDuration();

    /**
     * Gets the idle timeout length for sessions (in milliseconds). This is the 
     * amount of time that a session can live before it expires due to lack of 
     * activity. Applications or frameworks could provide a reauthenticate
     * function that enables a session to continue after reauthentication.
     * 
     * @return int The session idle timeout length.
     */
    public function getSessionIdleTimeoutLength();

    /**
     * Gets the absolute timeout length for sessions (in milliseconds). This is 
     * the amount of time that a session can live before it expires regardless 
     * of the amount of user activity. Applications or frameworks could provide a 
     * reauthenticate function that enables a session to continue after 
     * reauthentication.
     * 
     * @return int The session absolute timeout length.
     */
    public function getSessionAbsoluteTimeoutLength();

    /**
     * Returns whether HTML entity encoding should be applied to log entries.
     * 
     * @return bool True if log entries are to be HTML Entity encoded. False 
     *              otherwise.
     */
    public function getLogEncodingRequired();

    /**
     * Get the log level specified in the ESAPI configuration properties file. 
     * Return a default value if it is not specified in the properties file.
     * 
     * @return int the logging level defined in the properties file. If none is 
     *             specified, the default of Logger.WARNING is returned.
     */
    public function getLogLevel();

    /**
     * Get the name of the log file specified in the ESAPI configuration properties 
     * file. Return a default value if it is not specified.
     * 
     * @return string the log file name defined in the properties file.
     */
    public function getLogFileName();

    /**
     * Get the maximum size of a single log file from the ESAPI configuration 
     * properties file. Return a default value if it is not specified. Once the 
     * log hits this file size, it will roll over into a new log.
     * 
     * @return int the maximum size of a single log file (in bytes).
     */
    public function getMaxLogFileSize();
    
    /**
     * Get the specified validation pattern from the ESAPI configuration properties 
     * file.
     * 
     * @param string $type validation pattern name
     *
     * @return string the regular expression.
     */
    public function getValidationPattern($type);
    
    /**
     * getWorkingDirectory returns the default directory where processes will be 
     * executed by the Executor.
     * 
     * @return string working directory name
     */
    public function getWorkingDirectory();

    /**
     * getAllowedExecutables returns an array of executables that are allowed to 
     * be run by the Executor.
     * 
     * @return array an array of executable names
     */
    public function getAllowedExecutables();

}
