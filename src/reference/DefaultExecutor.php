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
 * @package   ESAPI_Reference
 *
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    Linden Darling <linden.darling@jds.net.au>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   SVN: $Id$
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */

/**
 * Reference Implementation of the Executor interface.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @author    Mike Boberski <boberski_michael@bah.com>
 * @author    Linden Darling <linden.darling@jds.net.au>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
namespace PHPESAPI\PHPESAPI\Reference;

class DefaultExecutor implements \PHPESAPI\PHPESAPI\Executor
{

    // Logger
    private $_auditor;
    //SecurityConfiguration
    private $_config;

    /**
     * Executor constructor.
     *
     * @return does not return a value.
     */
    public function __construct()
    {
        $this->_auditor = \PHPESAPI\PHPESAPI\ESAPI::getAuditor('Executor');
        $this->_config = \PHPESAPI\PHPESAPI\ESAPI::getSecurityConfiguration();
    }

    /**
     * @inheritdoc
     */
    public function executeSystemCommand($executable, $params)
    {
        $workdir = $this->_config->getWorkingDirectory();
        $logParams = false;

        return $this->executeSystemCommandLonghand($executable, $params, $workdir, $logParams);
    }

    /**
     * @inheritdoc
     */
    public function executeSystemCommandLonghand($executable, $params, $workdir, $logParams)
    {
        try {
            // executable must exist
            $resolved = $executable;

            // resolve environment variables on Windows
            if (substr(PHP_OS, 0, 3) == 'WIN') {
                $resolved = preg_replace_callback('/%(\w+)%/', function ($matches) {
                    return getenv($matches[1]);
                }, $executable);
            }

            if (!file_exists($resolved)) {
                throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                    "Execution failure, No such " .
                    "executable: $executable"
                );
            }

            // executable must use canonical path
            if (substr(PHP_OS, 0, 3) == 'WIN') {
                if (strcasecmp($resolved, realpath($resolved)) != 0) {
                    throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                        "Execution failure, Attempt " .
                        "to invoke an executable using a non-absolute path: [" . realpath($resolved) . "] != [$executable]"
                    );
                }
            } else {
                if (strcmp($resolved, realpath($resolved)) != 0) {
                    throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                        "Execution failure, Attempt " .
                        "to invoke an executable using a non-absolute path: [" . realpath($resolved) . "] != [$executable]"
                    );
                }
            }

            // exact, absolute, canonical path to executable must be listed in ESAPI configuration
            $approved = $this->_config->getAllowedExecutables();
            if (substr(PHP_OS, 0, 3) == 'WIN') {
                if (!array_reduce($approved, function ($carry, $item) use ($executable) {
                    return $carry || !strcasecmp($item, $executable);
                }, false)) {
                    throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                        "Execution failure, Attempt to invoke executable that " .
                        "is not listed as an approved executable in ESAPI " .
                        "configuration: " . $executable . " not listed in " . implode(';', $approved)
                    );
                }
            } else {
                if (!in_array($executable, $approved)) {
                    throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                        "Execution failure, Attempt to invoke executable that " .
                        "is not listed as an approved executable in ESAPI " .
                        "configuration: " . $executable . " not listed in " . implode(';', $approved)
                    );
                }
            }

            // escape any special characters in the parameters
            $params = array_map('escapeshellcmd', $params);

            // working directory must exist
            $resolved_workdir = $workdir;
            if (substr(PHP_OS, 0, 3) == 'WIN') {
                $resolved_workdir = preg_replace_callback('/%(\w+)%/', function ($matches) {
                    return getenv($matches[1]);
                }, $workdir);
            }

            if (!file_exists($resolved_workdir)) {
                throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException(
                    "Execution failure, No such" .
                    " working directory for running executable: $workdir"
                );
            }

            // run the command
            $paramstr = "";
            foreach ($params as $param) {
                //note: will yield a paramstr with a leading whitespace
                $paramstr .= " " . $param;
            }
            //note: no whitespace between $executable and $paramstr since
            //$paramstr already has a leading whitespace
            $output = shell_exec($executable . $paramstr);

            return $output;
        } catch (\PHPESAPI\PHPESAPI\Errors\ExecutorException $e) {
            $this->_auditor->warning(\PHPESAPI\PHPESAPI\Auditor::SECURITY, true, $e->getMessage());
            throw new \PHPESAPI\PHPESAPI\Errors\ExecutorException($e->getMessage());
        }
    }
}
