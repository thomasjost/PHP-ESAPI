<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href='http://www.owasp.org/index.php/ESAPI'>http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 */
namespace PHPESAPI\PHPESAPI\Test\Reference;

class AccessControllerTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp()
    {
        /* global $ESAPI;

        if (!isset($ESAPI)) {
            $ESAPI = new ESAPI(__DIR__.'/../testresources/ESAPI.xml');
        }

        $this->testLogger = ESAPI::getAuditor(__CLASS__);
        $this->testLogger->setLevel(Auditor::ALL);*/
    }

    public function tearDown()
    {
        //$this->testLogger = null; // TODO - working?
    }

    /**
     * Test of isAuthorizedForURL method, of class AccessController.
     *
     * @throws Exception
     */
    public function testIsAuthorizedForURL()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getAccessController();
        $auth = \PHPESAPI\PHPESAPI\ESAPI::getAuthenticator();

        $auth->setCurrentUser($auth->getUser('testuser1'));

        assertFalse($instance->isAuthorizedForURL('/nobody'));
        assertFalse($instance->isAuthorizedForURL('/test/admin'));
        assertTrue($instance->isAuthorizedForURL('/test/user'));
        assertTrue($instance->isAuthorizedForURL('/test/all'));
        assertFalse($instance->isAuthorizedForURL('/test/none'));
        assertTrue($instance->isAuthorizedForURL('/test/none/$test->gif'));
        assertFalse($instance->isAuthorizedForURL('/test/none/$test->exe'));
        assertTrue($instance->isAuthorizedForURL('/test/none/$test->png'));
        assertFalse($instance->isAuthorizedForURL('/test/moderator'));
        assertTrue($instance->isAuthorizedForURL('/test/profile'));
        assertFalse($instance->isAuthorizedForURL('/upload'));

        $auth->setCurrentUser($auth->getUser('testuser2'));

        assertFalse($instance->isAuthorizedForURL('/nobody'));
        assertTrue($instance->isAuthorizedForURL('/test/admin'));
        assertFalse($instance->isAuthorizedForURL('/test/user'));
        assertTrue($instance->isAuthorizedForURL('/test/all'));
        assertFalse($instance->isAuthorizedForURL('/test/none'));
        assertTrue($instance->isAuthorizedForURL('/test/none/$test->png'));
        assertFalse($instance->isAuthorizedForURL('/test/moderator'));
        assertTrue($instance->isAuthorizedForURL('/test/profile'));
        assertFalse($instance->isAuthorizedForURL('/upload'));

        $auth->setCurrentUser($auth->getUser('testuser3'));

        assertFalse($instance->isAuthorizedForURL('/nobody'));
        assertTrue($instance->isAuthorizedForURL('/test/admin'));
        assertTrue($instance->isAuthorizedForURL('/test/user'));
        assertTrue($instance->isAuthorizedForURL('/test/all'));
        assertFalse($instance->isAuthorizedForURL('/test/none'));
        assertTrue($instance->isAuthorizedForURL('/test/none/$test->png'));
        assertFalse($instance->isAuthorizedForURL('/test/moderator'));
        assertTrue($instance->isAuthorizedForURL('/test/profile'));
        assertFalse($instance->isAuthorizedForURL('/upload'));

        try {
            $instance->assertAuthorizedForURL('/test/admin');
            $instance->assertAuthorizedForURL('/nobody');
            fail();
        } catch (\PHPESAPI\PHPESAPI\Errors\AccessControlException $ex) {
            // expected
        }
    }

    /**
     * Test of isAuthorizedForFunction method, of class AccessController.
     */
    public function testIsAuthorizedForFunction()
    {
        $instance = ESAPI::getAccessController();
        $auth = ESAPI::getAuthenticator();

        $auth->setCurrentUser($auth->getUser('testuser1'));

        assertTrue($instance->isAuthorizedForFunction('/FunctionA'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionAdeny'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionB'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionBdeny'));
        assertTrue($instance->isAuthorizedForFunction('/FunctionC'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionCdeny'));

        $auth->setCurrentUser($auth->getUser('testuser2'));

        assertFalse($instance->isAuthorizedForFunction('/FunctionA'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionAdeny'));
        assertTrue($instance->isAuthorizedForFunction('/FunctionB'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionBdeny'));
        assertTrue($instance->isAuthorizedForFunction('/FunctionD'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionDdeny'));

        $auth->setCurrentUser($auth->getUser('testuser3'));

        assertTrue($instance->isAuthorizedForFunction('/FunctionA'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionAdeny'));
        assertTrue($instance->isAuthorizedForFunction('/FunctionB'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionBdeny'));
        assertTrue($instance->isAuthorizedForFunction('/FunctionC'));
        assertFalse($instance->isAuthorizedForFunction('/FunctionCdeny'));

        try {
            $instance->assertAuthorizedForFunction('/FunctionA');
            $instance->assertAuthorizedForFunction('/FunctionDdeny');
            fail();
        } catch (\PHPESAPI\PHPESAPI\Errors\AccessControlException $ex) {
            // expected
        }
    }

    /**
     * Test of isAuthorizedForData method, of class AccessController.
     */
    public function testIsAuthorizedForData()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getAccessController();
        $auth = \PHPESAPI\PHPESAPI\ESAPI::getAuthenticator();

        /*
         Class adminR = null;
        Class adminRW = null;
        Class userW = null;
        Class userRW = null;
        Class anyR = null;
        Class userAdminR = null;
        Class userAdminRW = null;
        Class undefined = null;
        try{
        adminR = $Class->forName('$java->u$til->ArrayList');
        adminRW = $Class->forName('$java->l$ang->Math');
        userW = $Class->forName('$java->u$til->Date');
        userRW = $Class->forName('$java->l$ang->String');
        anyR = $Class->forName('$java->i$o->BufferedReader');
        userAdminR = $Class->forName('$java->u$til->Random');
        userAdminRW = $Class->forName('$java->a$wt->e$vent->MouseWheelEvent');
        undefined = $Class->forName('$java->i$o->FileWriter');
        }catch(ClassNotFoundException cnf){
        $System->o$ut->println('CLASS NOT FOUND.');
        $cnf->printStackTrace();
        }

        //test User
        $auth->setCurrentUser($auth->getUser('testuser1'));
        assertTrue($instance->isAuthorizedForData('read', userRW));
        assertFalse($instance->isAuthorizedForData('read', undefined));
        assertFalse($instance->isAuthorizedForData('write', undefined));
        assertFalse($instance->isAuthorizedForData('read', userW));
        assertFalse($instance->isAuthorizedForData('read', adminRW));
        assertTrue($instance->isAuthorizedForData('write', userRW));
        assertTrue($instance->isAuthorizedForData('write', userW));
        assertFalse($instance->isAuthorizedForData('write', anyR));
        assertTrue($instance->isAuthorizedForData('read', anyR));
        assertTrue($instance->isAuthorizedForData('read', userAdminR));
        assertTrue($instance->isAuthorizedForData('write', userAdminRW));
        //test Admin
        $auth->setCurrentUser($auth->getUser('testuser2'));
        assertTrue($instance->isAuthorizedForData('read', adminRW));
        assertFalse($instance->isAuthorizedForData('read', undefined));
        assertFalse($instance->isAuthorizedForData('write', undefined));
        assertFalse($instance->isAuthorizedForData('read', userRW));
        assertTrue($instance->isAuthorizedForData('write', adminRW));
        assertFalse($instance->isAuthorizedForData('write', anyR));
        assertTrue($instance->isAuthorizedForData('read', anyR));
        assertTrue($instance->isAuthorizedForData('read', userAdminR));
        assertTrue($instance->isAuthorizedForData('write', userAdminRW));
        //test User/Admin
        $auth->setCurrentUser($auth->getUser('testuser3'));
        assertTrue($instance->isAuthorizedForData('read', userRW));
        assertFalse($instance->isAuthorizedForData('read', undefined));
        assertFalse($instance->isAuthorizedForData('write', undefined));
        assertFalse($instance->isAuthorizedForData('read', userW));
        assertTrue($instance->isAuthorizedForData('read', adminR));
        assertTrue($instance->isAuthorizedForData('write', userRW));
        assertTrue($instance->isAuthorizedForData('write', userW));
        assertFalse($instance->isAuthorizedForData('write', anyR));
        assertTrue($instance->isAuthorizedForData('read', anyR));
        assertTrue($instance->isAuthorizedForData('read', userAdminR));
        assertTrue($instance->isAuthorizedForData('write', userAdminRW));
        try {
        $instance->assertAuthorizedForData('read', userRW);
        $instance->assertAuthorizedForData('write', adminR);
        fail();
        } catch (AccessControlException $ex) {
        // expected
        }
        */
    }
    /**
     * Test of isAuthorizedForFile method, of class AccessController.
     */
    public function testIsAuthorizedForFile()
    {
        $instance = \PHPESAPI\PHPESAPI\ESAPI::getAccessController();
        $auth = \PHPESAPI\PHPESAPI\ESAPI::getAuthenticator();

        $auth->setCurrentUser($auth->getUser('testuser1'));

        assertTrue($instance->isAuthorizedForFile('/Dir/File1'));
        assertFalse($instance->isAuthorizedForFile('/Dir/File2'));
        assertTrue($instance->isAuthorizedForFile('/Dir/File3'));
        assertFalse($instance->isAuthorizedForFile('/Dir/ridiculous'));

        $auth->setCurrentUser($auth->getUser('testuser2'));

        assertFalse($instance->isAuthorizedForFile('/Dir/File1'));
        assertTrue($instance->isAuthorizedForFile('/Dir/File2'));
        assertTrue($instance->isAuthorizedForFile('/Dir/File4'));
        assertFalse($instance->isAuthorizedForFile('/Dir/ridiculous'));

        $auth->setCurrentUser($auth->getUser('testuser3'));

        assertTrue($instance->isAuthorizedForFile('/Dir/File1'));
        assertTrue($instance->isAuthorizedForFile('/Dir/File2'));
        assertFalse($instance->isAuthorizedForFile('/Dir/File5'));
        assertFalse($instance->isAuthorizedForFile('/Dir/ridiculous'));

        try {
            $instance->assertAuthorizedForFile('/Dir/File1');
            $instance->assertAuthorizedForFile('/Dir/File6');
            fail();
        } catch (\PHPESAPI\PHPESAPI\Errors\AccessControlException $ex) {
            // expected
        }
    }

    /**
     * Test of isAuthorizedForService method, of class AccessController.
     */
    public function testIsAuthorizedForService()
    {
        $instance = ESAPI::getAccessController();
        $auth = ESAPI::getAuthenticator();

        $auth->setCurrentUser($auth->getUser('testuser1'));

        assertTrue($instance->isAuthorizedForService('/services/ServiceA'));
        assertFalse($instance->isAuthorizedForService('/services/ServiceB'));
        assertTrue($instance->isAuthorizedForService('/services/ServiceC'));
        assertFalse($instance->isAuthorizedForService('/test/ridiculous'));

        $auth->setCurrentUser($auth->getUser('testuser2'));

        assertFalse($instance->isAuthorizedForService('/services/ServiceA'));
        assertTrue($instance->isAuthorizedForService('/services/ServiceB'));
        assertFalse($instance->isAuthorizedForService('/services/ServiceF'));
        assertFalse($instance->isAuthorizedForService('/test/ridiculous'));

        $auth->setCurrentUser($auth->getUser('testuser3'));

        assertTrue($instance->isAuthorizedForService('/services/ServiceA'));
        assertTrue($instance->isAuthorizedForService('/services/ServiceB'));
        assertFalse($instance->isAuthorizedForService('/services/ServiceE'));
        assertFalse($instance->isAuthorizedForService('/test/ridiculous'));

        try {
            $instance->assertAuthorizedForService('/services/ServiceD');
            $instance->assertAuthorizedForService('/test/ridiculous');
            fail();
        } catch (\PHPESAPI\PHPESAPI\Errors\AccessControlException $ex) {
            // expected
        }
    }
}
