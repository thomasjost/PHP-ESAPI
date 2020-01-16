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
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Require ESAPI and SafeRequest.
 */

/**
 * UnitTestCase for SafeRequest implementation.
 * Note that the getParameter* methods are not tested here because they act upon
 * data from the $_GET and $_POST globals which are not populated when this test
 * script is run from the command-line.
 *
 * PHP version 5.2
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
namespace PHPESAPI\PHPESAPI\Test\Filters;

class SafeRequestTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test of SafeRequest::getAuthType() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetAuthTypeInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getAuthType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getAuthType() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetAuthTypeInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'AUTH_TYPE' => 'B-asic'
                )
            )
        );
        $result = $req->getAuthType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getAuthType() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetAuthTypeInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'AUTH_TYPE' => 'bAsic'
                )
            )
        );
        $result = $req->getAuthType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('bAsic', $result);
    }

    /**
     * Test of SafeRequest::getContentLength() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentLengthInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getContentLength();
        $this->assertInternalType('int', $result);
        $this->assertEquals(0, $result);
    }

    /**
     * Test of SafeRequest::getContentLength() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentLengthInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'CONTENT_LENGTH' => '-1'
                )
            )
        );
        $result = $req->getContentLength();
        $this->assertInternalType('int', $result);
        $this->assertEquals(0, $result);
    }

    /**
     * Test of SafeRequest::getContentLength() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentLengthInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'CONTENT_LENGTH' => '1024'
                )
            )
        );
        $result = $req->getContentLength();
        $this->assertInternalType('int', $result);
        $this->assertEquals(1024, $result);
    }

    /**
     * Test of SafeRequest::getContentType() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentTypeInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getContentType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getContentType() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentTypeInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'CONTENT_TYPE' => 'application/ürl-form-encoded'
                )
            )
        );
        $result = $req->getContentType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getContentType() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetContentTypeInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'CONTENT_TYPE' => 'application/url-form-encoded'
                )
            )
        );
        $result = $req->getContentType();
        $this->assertInternalType('string', $result);
        $this->assertEquals('application/url-form-encoded', $result);
    }

    /**
     * Test of SafeRequest::getPathInfo() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathInfoInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getPathInfo();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getPathInfo() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathInfoInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PATH_INFO' => '/foo%00'
                )
            )
        );
        $result = $req->getPathInfo();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of SafeRequest::getPathInfo() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathInfoInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PATH_INFO' => '/foo'
                )
            )
        );
        $result = $req->getPathInfo();
        $this->assertInternalType('string', $result);
        $this->assertEquals('/foo', $result);
    }

    /**
     * Test of SafeRequest::getPathTranslated() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathTranslatedInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getPathTranslated();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getPathTranslated() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathTranslatedInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PATH_TRANSLATED' => '/foo%00'
                )
            )
        );
        $result = $req->getPathTranslated();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getPathTranslated() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetPathTranslatedInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PATH_TRANSLATED' => '/foo'
                )
            )
        );
        $result = $req->getPathTranslated();
        $this->assertInternalType('string', $result);
        $this->assertEquals('/foo', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getQueryString() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetQueryStringInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getQueryString();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getQueryString() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetQueryStringInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'QUERY_STRING' => 'foo#bar'
                )
            )
        );
        $result = $req->getQueryString();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getQueryString() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetQueryStringInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'QUERY_STRING' => 'foo=bar'
                )
            )
        );
        $result = $req->getQueryString();
        $this->assertInternalType('string', $result);
        $this->assertEquals('foo=bar', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteAddr() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteAddrInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getRemoteAddr();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteAddr() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteAddrInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_ADDR' => '123.456.7.89'
                )
            )
        );
        $result = $req->getRemoteAddr();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteAddr() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteAddrInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_ADDR' => '123.45.67.89'
                )
            )
        );
        $result = $req->getRemoteAddr();
        $this->assertInternalType('string', $result);
        $this->assertEquals('123.45.67.89', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteHost() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteHostInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteHost() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteHostInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => 'example%com'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => '123.45.67.89'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => '-example.com'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteHost() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteHostInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => 'example.com'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('example.com', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => '0example0.com'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('0example0.com', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_HOST' => 'foo-bar.0example0.com'
                )
            )
        );
        $result = $req->getRemoteHost();
        $this->assertInternalType('string', $result);
        $this->assertEquals('foo-bar.0example0.com', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteHost() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteUserInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getRemoteUser();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteUser() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteUserInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_USER' => 'user:1'
                )
            )
        );
        $result = $req->getRemoteUser();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRemoteUser() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRemoteUserInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REMOTE_USER' => 'user_1'
                )
            )
        );
        $result = $req->getRemoteUser();
        $this->assertInternalType('string', $result);
        $this->assertEquals('user_1', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getMethod() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetMethodInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getMethod();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getMethod() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetMethodInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REQUEST_METHOD' => 'GETS'
                )
            )
        );
        $result = $req->getMethod();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getMethod() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetMethodInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'REQUEST_METHOD' => 'GET'
                )
            )
        );
        $result = $req->getMethod();
        $this->assertInternalType('string', $result);
        $this->assertEquals('GET', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRequestURI() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRequestURIInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getRequestURI();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRequestURI() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRequestURIInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SCRIPT_NAME' => '/foo/<script>.php'
                )
            )
        );
        $result = $req->getRequestURI();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getRequestURI() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetRequestURIInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SCRIPT_NAME' => '/foo/bar.php'
                )
            )
        );
        $result = $req->getRequestURI();
        $this->assertInternalType('string', $result);
        $this->assertEquals('/foo/bar.php', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerName() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerNameInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerName() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerNameInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_NAME' => '0123456789012345678901234567890123456789012345678901234567890123.com'
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_NAME' => '123.456.7.89'
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_NAME' => 'example%com'
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerName() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerNameInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_NAME' => '123.45.67.89'
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('123.45.67.89', $result);

        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_NAME' => 'example.com'
                )
            )
        );
        $result = $req->getServerName();
        $this->assertInternalType('string', $result);
        $this->assertEquals('example.com', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerPort() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerPortInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getServerPort();
        $this->assertInternalType('int', $result);
        $this->assertEquals(0, $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerPort() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerPortInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_PORT' => '65536'
                )
            )
        );
        $result = $req->getServerPort();
        $this->assertInternalType('int', $result);
        $this->assertEquals(0, $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerPort() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerPortInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'SERVER_PORT' => '80'
                )
            )
        );
        $result = $req->getServerPort();
        $this->assertInternalType('int', $result);
        $this->assertEquals(80, $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getHeader() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetHeaderInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'headers' => array(
                )
            )
        );
        $result = $req->getHeader('HTTP_ACCEPT');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getHeader() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetHeaderInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'headers' => array(
                    'HTTP_ACCEPT' => '%00text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                )
            )
        );
        $result = $req->getHeader('HTTP_ACCEPT');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getHeader() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetHeaderInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'headers' => array(
                    'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                )
            )
        );
        $result = $req->getHeader('HTTP_ACCEPT');
        $this->assertInternalType('string', $result);
        $this->assertEquals(
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            $result
        );
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getCookie() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetCookieInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'cookies' => array(
                )
            )
        );
        $result = $req->getCookie('foo');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getCookie() with invalid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetCookieInputInvalid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'cookies' => array(
                    'foo' => '\r\n\r\nGET /foo HTTP/1.1\r\nHost:example.com\r\n\r\n<html><script>alert(1)</html></script>'
                )
            )
        );
        $result = $req->getCookie('foo');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getCookie() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetCookieInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'cookies' => array(
                    'foo' => 'bar'
                )
            )
        );
        $result = $req->getCookie('foo');
        $this->assertInternalType('string', $result);
        $this->assertEquals('bar', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerGlobal() with null input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerGlobalInputNull()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                )
            )
        );
        $result = $req->getServerGlobal('foo');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerGlobal() with double encoding.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerGlobalInputDoubleEncoded()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PHP_SELF' => '/foo%252fbar'
                )
            )
        );
        $result = $req->getServerGlobal('PHP_SELF');
        $this->assertInternalType('null', $result);
    }

    /**
     * Test of \PHPESAPI\PHPESAPI\Filters\SafeRequest::getServerGlobal() with valid input.
     *
     * @return bool true True on Pass.
     */
    public function testGetServerGlobalInputValid()
    {
        $req = new \PHPESAPI\PHPESAPI\Filters\SafeRequest(
            array(
                'env' => array(
                    'PHP_SELF' => '/foo%2fbar'
                )
            )
        );
        $result = $req->getServerGlobal('PHP_SELF');
        $this->assertInternalType('string', $result);
        $this->assertEquals('/foo/bar', $result);
    }
}
