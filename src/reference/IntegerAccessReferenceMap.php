<?php
/**
 * OWASP Enterprise Security API (ESAPI).
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2011 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Andrew van der Stock
 * @created 2009
 *
 * @since 1.6
 *
 * @package ESAPI_Reference
 */

/**
 * Reference Implementation of the IntegerAccessReferenceMap interface.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class IntegerAccessReferenceMap implements AccessReferenceMap
{

    private $dtoi;
    private $itod;
    private $count = 1;

    public function __construct($directReferences = null)
    {
        $this->dtoi = new ArrayObject();
        $this->itod = new ArrayObject();

        if (!empty($directReferences)) {
            $this->update($directReferences);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function iterator()
    {
        return $this->dtoi->getIterator();
    }

    /**
     * {@inheritDoc}
     */
    public function getIndirectReference($direct)
    {
        if (empty($direct)) {
            return null;
        }

        $hash = $this->getHash($direct);

        if (!($this->dtoi->offsetExists($hash))) {
            return null;
        }

        return $this->dtoi->offsetGet($hash);
    }

    /**
     * {@inheritDoc}
     */
    public function getDirectReference($indirectReference)
    {
        if (!empty($indirectReference) && $this->itod->offsetExists($indirectReference)) {
            return $this->itod->offsetGet($indirectReference);
        }

        throw new AccessControlException("Access denied", "Request for invalid indirect reference: " + $indirectReference);

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function addDirectReference($direct)
    {
        if (empty($direct)) {
            return null;
        }

        $hash = $this->getHash($direct);

        if ($this->dtoi->offsetExists($hash)) {
            return $this->dtoi->offsetGet($hash);
        }

        $indirect = $this->getUniqueReference();

        $this->itod->offsetSet($indirect, $direct);
        $this->dtoi->offsetSet($hash, $indirect);

        return $indirect;
    }

    /**
     * Create a new random reference that is guaranteed to be unique.
     *
     * @return string A random reference that is guaranteed to be unique
     */
    public function getUniqueReference()
    {
        return (string) $this->count++;
    }

    /**
     * @param unknown $direct
     *
     * @return NULL|number
     */
    public function getHash($direct)
    {
        if (empty($direct)) {
            return null;
        }

        $hash = hexdec(substr(md5(serialize($direct)), -7));

        return $hash;
    }

    /**
     * {@inheritDoc}
     */
    public function removeDirectReference($direct)
    {
        if (empty($direct)) {
            return null;
        }

        $hash = $this->getHash($direct);

        if ($this->dtoi->offsetExists($hash)) {
            $indirect = $this->dtoi->offsetGet($hash);
            $this->itod->offsetUnset($indirect);
            $this->dtoi->offsetUnset($hash);

            return $indirect;
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function update($directReferences)
    {
        $dtoi_old = clone $this->dtoi;

        unset($this->dtoi);
        unset($this->itod);

        $this->dtoi = new ArrayObject();
        $this->itod = new ArrayObject();

        $dir = new ArrayObject($directReferences);
        $directIterator = $dir->getIterator();

        while ($directIterator->valid()) {
            $indirect = null;
            $direct = $directIterator->current();
            $hash = $this->getHash($direct);
            
            // Try to get the old direct object reference (if it exists)
            // otherwise, create a new entry
            if (!empty($direct) && $dtoi_old->offsetExists($hash)) {
                $indirect = $dtoi_old->offsetGet($hash);
            }
            
            if (empty($indirect)) {
                $indirect = $this->getUniqueReference();
            }
            $this->itod->offsetSet($indirect, $direct);
            $this->dtoi->offsetSet($hash, $indirect);
            $directIterator->next();
        }
    }
}
