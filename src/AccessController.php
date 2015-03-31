<?php

/**
 * OWASP Enterprise Security API (ESAPI).
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
 *
 * @package   ESAPI
 *
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Use this ESAPI security control to wrap your access control functions.
 *
 * The idea behind this interface is to centralize access control logic
 * behind easy to use calls so that access control is easy to use and
 * easy to verify.
 *
 * @category  OWASP
 *
 * @package   ESAPI
 *
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    Andrew van der Stock <vanderaj@owasp.org>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
interface AccessController
{

    /**
     * Checks if an account is authorized to access the referenced URL. Generally, this method should be invoked in the
     * application's controller or a filter as follows:
     * <pre>ESAPI::getAccessController()->isAuthorizedForURL($_SERVER['REQUEST_URI']);</pre>.
     *
     * The implementation of this method should call assertAuthorizedForURL($url), and if an AccessControlException is
     * not thrown, this method should return TRUE. This way, if the user is not authorized, FALSE would be returned, and the
     * exception would be logged.
     *
     * @param string $url The URL as returned by $_SERVER['REQUEST_URI']
     *
     * @return bool TRUE, if is authorized for URL
     */
    public function isAuthorizedForURL($url);

    /**
     * Checks if an account is authorized to access the referenced function.
     *
     * The implementation of this method should call assertAuthorizedForFunction($functionName), and if an
     * AccessControlException is not thrown, this method should return TRUE.
     *
     * @param string $functionName The name of the function
     *
     * @return bool TRUE, if is authorized for function
     */
    public function isAuthorizedForFunction($functionName);

    /**
     * Checks if an account is authorized to access the referenced data, represented as a String.
     *
     * The implementation of this method should call assertAuthorizedForData($key), and if an AccessControlException
     * is not thrown, this method should return TRUE.
     *
     * @param string $key The name of the referenced data object
     *
     * @return bool TRUE, if is authorized for the data
     */
    public function isAuthorizedForDataByKey($key);

    /**
     * Checks if an account is authorized to access the referenced data, represented as an Object.
     *
     * The implementation of this method should call assertAuthorizedForData($action, Object data), and if an
     * AccessControlException is not thrown, this method should return TRUE.
     *
     * @param string $action The action to check for in the configuration file in the resource directory
     * @param string $data The data to check for in the configuration file in the resource directory
     *
     * @return bool TRUE, if is authorized for the data
     */
    public function isAuthorizedForData($action, $data);

    /**
     * Checks if an account is authorized to access the referenced file.
     *
     * The implementation of this method should call assertAuthorizedForFile($filepath), and if an AccessControlException
     * is not thrown, this method should return TRUE.
     *
     * @param string filepath The path of the file to be checked, including filename
     *
     * @return bool TRUE, if is authorized for the file
     */
    public function isAuthorizedForFile($filepath);

    /**
     * Checks if an account is authorized to access the referenced service. This can be used in applications that
     * provide access to a variety of back end services.
     *
     * The implementation of this method should call assertAuthorizedForService($serviceName), and if an
     * AccessControlException is not thrown, this method should return TRUE.
     *
     * @param string $serviceName The service name
     *
     * @return bool TRUE, if is authorized for the service
     */
    public function isAuthorizedForService($serviceName);

    /**
     * Checks if an account is authorized to access the referenced URL. The implementation should allow
     * access to be granted to any part of the URL. Generally, this method should be invoked in the
     * application's controller or a filter as follows:
     * <pre>ESAPI::getAccessController()->assertAuthorizedForURL($_SERVER['REQUEST_URI']);</pre>.
     *
     * This method throws an AccessControlException if access is not authorized, or if the referenced URL does not exist.
     * If the User is authorized, this method simply returns.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the resource exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *             <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $url The URL as returned by $_SERVER['REQUEST_URI']
     *
     * @throws AccessControlException if access is not permitted
     */
    public function assertAuthorizedForURL($url);

    /**
     * Checks if an account is authorized to access the referenced function. The implementation should define the
     * function "namespace" to be enforced. Choosing something simple like the class name of action classes or menu item
     * names will make this implementation easier to use.
     *
     * This method throws an AccessControlException if access is not authorized, or if the referenced function does not exist.
     * If the User is authorized, this method simply returns.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the function exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *              <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $functionName The function name
     *
     * @throws AccessControlException if access is not permitted
     */
    public function assertAuthorizedForFunction($functionName);

    /**
     * Checks if the current user is authorized to access the referenced data.  This method simply returns if access is authorized.
     * It throws an AccessControlException if access is not authorized, or if the referenced data does not exist.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the resource exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *             <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $key The name of the target data object
     *
     * @throws AccessControlException if access is not permitted
     */
    public function assertAuthorizedForDataByKey($key);

    /**
     * Checks if the current user is authorized to access the referenced data.  This method simply returns if access is authorized.
     * It throws an AccessControlException if access is not authorized, or if the referenced data does not exist.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the resource exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *             <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $action The action to check for in the configuration file in the resource directory
     * @param string $data The data to check for in the configuration file in the resource directory
     *
     * @throws AccessControlException if access is not permitted
     */
    public function assertAuthorizedForData($action, $data);

    /**
     * Checks if an account is authorized to access the referenced file. The implementation should validate and canonicalize the
     * input to be sure the filepath is not malicious.
     *
     * This method throws an AccessControlException if access is not authorized, or if the referenced File does not exist.
     * If the User is authorized, this method simply returns.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the File exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *             <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $filepath Path to the file to be checked
     *
     * @throws AccessControlException if access is denied
     */
    public function assertAuthorizedForFile($filepath);

    /**
     * Checks if an account is authorized to access the referenced service. This can be used in applications that
     * provide access to a variety of backend services.
     *
     * This method throws an AccessControlException if access is not authorized, or if the referenced service does not exist.
     * If the User is authorized, this method simply returns.
     *
     * Specification:  The implementation should do the following:
     * <ol>
     *     <li>Check to see if the service exists and if not, throw an AccessControlException</li>
     *     <li>Use available information to make an access control decision</li>
     *         <ol type="a">
     *             <li>Ideally, this policy would be data driven</li>
     *             <li>You can use the current User, roles, data type, data name, time of day, etc.</li>
     *             <li>Access control decisions must deny by default</li>
     *         </ol>
     *     </li>
     *     <li>If access is not permitted, throw an AccessControlException with details</li>
     * </ol>
     *
     * @param string $serviceName The service name
     *
     * @throws AccessControlException if access is not permitted
     */
    public function assertAuthorizedForService($serviceName);
}
