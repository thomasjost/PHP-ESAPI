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

// TODO: Add in PHP Unit expected exception tests

class EnterpriseSecurityExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testEnterpriseSecurityDefaultException()
    {
        $e = new EnterpriseSecurityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }

    public function testEnterpriseSecurityException()
    {
        $e = new EnterpriseSecurityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testAccessControlDefaultException()
    {
        $e = new AccessControlException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAccessControlException()
    {
        $e = new AccessControlException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAuthenticationDefaultException()
    {
        $e = new AuthenticationException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAuthenticationException()
    {
        $e = new AuthenticationException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testAvailabilityDefaultException()
    {
        $e = new AvailabilityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAvailabilityException()
    {
        $e = new AvailabilityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testCertificateDefaultException()
    {
        $e = new CertificateException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testCertificateException()
    {
        $e = new CertificateException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testEncodingDefaultException()
    {
        $e = new EncodingException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
        
    public function testEncodingException()
    {
        $e = new EncodingException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testEncryptionDefaultException()
    {
        $e = new EncryptionException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testEncryptionException()
    {
        $e = new EncryptionException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testExecutorDefaultException()
    {
        $e = new ExecutorException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testExecutorException()
    {
        $e = new ExecutorException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testValidationDefaultException()
    {
        $e = new ValidationException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testValidationException()
    {
        $e = new ValidationException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testValidationExceptionContext()
    {
        $e = new ValidationException();
        $e->setContext("test");
        $this->assertEquals("test", $e->getContext());
    }
    
    public function testIntegrityDefaultException()
    {
        $e = new IntegrityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testIntegrityException()
    {
        $e = new IntegrityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testAuthenticationHostDefaultException()
    {
        $e = new AuthenticationHostException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAuthenticationHostException()
    {
        $e = new AuthenticationHostException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    public function testAuthenticationAccountsDefaultException()
    {
        $e = new AuthenticationAccountsException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAuthenticationAccountsException()
    {
        $e = new AuthenticationAccountsException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testAuthenticationCredentialsDefaultException()
    {
        $e = new AuthenticationCredentialsException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAuthenticationCredentialsException()
    {
        $e = new AuthenticationCredentialsException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    public function testAuthenticationLoginDefaultException()
    {
        $e = new AuthenticationLoginException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testAuthenticationLoginException()
    {
        $e = new AuthenticationLoginException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
    
    public function testValidationAvailabilityDefaultException()
    {
        $e = new ValidationAvailabilityException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testValidationAvailabilityException()
    {
        $e = new ValidationAvailabilityException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testValidationUploadDefaultException()
    {
        $e = new ValidationUploadException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    public function testValidationUploadException()
    {
        $e = new ValidationUploadException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }

    public function testIntrusionDefaultException()
    {
        $e = new IntrusionException();
        $this->assertEquals($e->getUserMessage(), null);
        $this->assertEquals($e->getLogMessage(), '');
    }
    
    public function testIntrusionException()
    {
        $e = new IntrusionException("This is a message for users.", "This is a message for the log.");
        $this->assertEquals($e->getUserMessage(), "This is a message for users.");
        $this->assertEquals($e->getLogMessage(), "This is a message for the log.");
    }
}
