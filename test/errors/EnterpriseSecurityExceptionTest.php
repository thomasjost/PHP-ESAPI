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
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */

namespace PHPESAPI\PHPESAPI\Test\Errors;

// TODO: Add in PHP Unit expected exception tests

class EnterpriseSecurityExceptionTest extends \PHPUnit\Framework\TestCase
{
    public function testEnterpriseSecurityDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EnterpriseSecurityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testEnterpriseSecurityException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EnterpriseSecurityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAccessControlDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AccessControlException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAccessControlException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AccessControlException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAuthenticationDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAuthenticationException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAvailabilityDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AvailabilityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAvailabilityException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AvailabilityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testCertificateDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\CertificateException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testCertificateException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\CertificateException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testEncodingDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EncodingException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testEncodingException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EncodingException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testEncryptionDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EncryptionException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testEncryptionException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\EncryptionException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testExecutorDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ExecutorException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testExecutorException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ExecutorException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testValidationDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testValidationException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testValidationExceptionContext()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationException();
        $e->setContext("test");
        $this->assertEquals("test", $e->getContext());
    }

    public function testIntegrityDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\IntegrityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testIntegrityException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\IntegrityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAuthenticationHostDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationHostException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAuthenticationHostException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationHostException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    public function testAuthenticationAccountsDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationAccountsException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAuthenticationAccountsException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationAccountsException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAuthenticationCredentialsDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationCredentialsException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAuthenticationCredentialsException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationCredentialsException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    public function testAuthenticationLoginDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationLoginException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testAuthenticationLoginException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\AuthenticationLoginException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testValidationAvailabilityDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationAvailabilityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testValidationAvailabilityException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationAvailabilityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testValidationUploadDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationUploadException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    public function testValidationUploadException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\ValidationUploadException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testIntrusionDefaultException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\IntrusionException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testIntrusionException()
    {
        $e = new \PHPESAPI\PHPESAPI\Errors\IntrusionException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
}
