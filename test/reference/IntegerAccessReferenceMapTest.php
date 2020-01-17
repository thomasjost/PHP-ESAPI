<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2009 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 * @since 1.6
 */
namespace PHPESAPI\PHPESAPI\Test\Reference;

class IntegerReferenceMapTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test of iterator method, of class org.owasp.esapi.AccessReferenceMap.
     */
    public function testIterator()
    {
        $users = array("andrew", "bipin", "laura", "jah", "linden", "mike", "arnaud");

        $arm = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap();
        $arm->update($users);

        $i = $arm->iterator();
        $j = 0;
        while ($i->valid()) {
            $userName = $arm->getDirectReference($i->current());
            $u = $users[$j];
            $this->assertEquals($u, $userName);
            $i->next();
            $j++;
        }
    }

    /**
     *
     * @throws \PHPESAPI\PHPESAPI\Errors\AccessControlException
     */
    public function testRemoveDirectReference()
    {
        $directReference = "234";

        $directArray = array();
        $directArray[] = "123";
        $directArray[] = $directReference;
        $directArray[] = "345";

        $instance = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap($directArray);

        $indirect = $instance->getIndirectReference($directReference);
        $this->assertNotNull($indirect);
        $deleted = $instance->removeDirectReference($directReference);
        $this->assertEquals($indirect, $deleted);
        $deleted = $instance->removeDirectReference("ridiculous");
        $this->assertNull($deleted);
    }

    /**
     * Test of getIndirectReference method, of class
     * org.owasp.esapi.AccessReferenceMap.
     */
    public function testGetIndirectReference()
    {
        $directReference = "234";

        $directArray = array();
        $directArray[] = "123";
        $directArray[] = $directReference;
        $directArray[] = "345";

        $instance = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap($directArray);

        $expResult = $directReference;
        $result = $instance->getIndirectReference($directReference);
        $this->assertNotSame($expResult, $result);
    }

    /**
     * Test of getDirectReference method, of class
     * org.owasp.esapi.AccessReferenceMap.
     *
     * @throws AccessControlException
     */
    public function testGetDirectReference()
    {
        $directReference = "234";

        $directArray = array();
        $directArray[] = "123";
        $directArray[] = $directReference;
        $directArray[] = "345";

        $instance = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap($directArray);

        $ind = $instance->getIndirectReference($directReference);
        $dir = $instance->getDirectReference($ind);

        // echo "<p>ind = [$ind], dir = [$dir], directreference = [$directReference]";

        $this->assertEquals($directReference, $dir);
        try {
            $instance->getDirectReference("invalid");
            $this->fail();
        } catch (\PHPESAPI\PHPESAPI\Errors\AccessControlException $e) {
            // success
        }
    }

    /**
     *
     * @throws \PHPESAPI\PHPESAPI\Errors\AccessControlException
     */
    public function testAddDirectReference()
    {
        $directReference = "234";

        $directArray = array();
        $directArray[] = "123";
        $directArray[] = $directReference;
        $directArray[] = "345";

        $instance = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap($directArray);

        $newDirect = $instance->addDirectReference("newDirect");
        $this->assertNotNull($newDirect);
        $ind = $instance->addDirectReference($directReference);
        $dir = $instance->getDirectReference($ind);
        $this->assertEquals($directReference, $dir);
        $newInd = $instance->addDirectReference($directReference);
        $this->assertEquals($ind, $newInd);
    }

    public function testUpdatePass()
    {
        $users = array('alpha', 'juliet', 'victor');

        $arm = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap();
        $arm->update($users);

        $indirect = $arm->getIndirectReference('victor');
        $this->assertNotNull($indirect);
    }

    public function testUpdateFail()
    {
        $users = array('alpha', 'juliet', 'victor');

        $arm = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap();
        $arm->update($users);

        $indirect = $arm->getIndirectReference('ridiculous');
        $this->assertNull($indirect);
    }

    public function testUpdateRemoveItem()
    {
        $users = array('alpha', 'juliet', 'victor');

        $arm = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap();
        $arm->update($users);

        unset($users[1]);
        $arm->update($users);

        $indirect = $arm->getIndirectReference('juliet');
        $this->assertNull($indirect);
    }

    public function testUpdateStableReference()
    {
        $users = array('alpha', 'juliet', 'victor');

        $arm = new \PHPESAPI\PHPESAPI\Reference\IntegerAccessReferenceMap();
        $arm->update($users);
        $indirect = $arm->getIndirectReference('juliet');

        $users[] = 'omega';

        $arm->update($users);

        $indirect2 = $arm->getIndirectReference('juliet');
        $this->assertEquals($indirect, $indirect2);
    }
}
