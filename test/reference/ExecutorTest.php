<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2010 The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author  Andrew van der Stock <vanderaj @ owasp.org>
 * @author  Linden Darling <linden.darling@jds.net.au>
 * @created 2009
 */

class ExecutorTest extends PHPUnit_Framework_TestCase
{
    private $_instance;
    
    private $_executable;
    private $_params;
    private $_workdir;
    
    protected function setUp()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_executable = '%SYSTEMROOT%\\system32\\cmd.exe';
            $this->_params = array("/C", "dir");
            $this->_workdir = '%SYSTEMROOT%\\Temp';
        } else {
            $this->_executable = realpath('/bin/sh');
            $this->_params = array("-c", "'ls /'");
            $this->_workdir = '/tmp';
        }
        
        $this->_instance = new DefaultExecutor();
    }
        
    /**
     * Test of executeSystemCommand method, of Executor
     */
    public function testExecuteLegalSystemCommand()
    {
        try {
            $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }

    /**
     * Test to ensure that bad commands fail
     */
    public function testExecuteInjectIllegalSystemCommand()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_executable = '%SYSTEMROOT%\\System32\\;notepad.exe';
        } else {
            $this->_executable .= ';./inject';
        }
        
        $this->setExpectedException('ExecutorException');
        
        $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
        $this->fail('Should not execute injected command');
    }
    
    /**
     * Test of file system canonicalization
     */
    public function testExecuteCanonicalization()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_executable = '%SYSTEMROOT%\\System32\\..\\cmd.exe';
        } else {
            $this->_executable = '/bin/sh/../bin/sh';
        }
        
        $this->setExpectedException('ExecutorException');
        
        $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
        $this->fail('Should not execute uncanonicalized command');
    }
    
    /**
     * Test to see if a good work directory is properly handled.
     */
    public function testExecuteGoodWorkDirectory()
    {
        try {
            $result = $this->_instance->executeSystemCommandLonghand($this->_executable, $this->_params, $this->_workdir, false);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }
    
    /**
     * Test to see if a non-existent work directory is properly handled.
     */
    public function testExecuteBadWorkDirectory()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_workdir = 'C:\\ridiculous';
        } else {
            $this->_workdir = '/ridiculous/';
        }
        
        $this->setExpectedException('ExecutorException');
        
        $result = $this->_instance->executeSystemCommandLonghand($this->_executable, $this->_params, $this->_workdir, false);
        $this->fail('Should not execute with a bad working directory');
    }
    
    /**
     * Test to prevent chained command execution
     */
    public function testExecuteChainedCommand()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_executable .= " & dir & rem ";
        } else {
            $this->_executable .= " ; ls / ; # ";
        }
        
        $this->setExpectedException('ExecutorException');
        
        $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
        $this->fail("Executed chained command, output: " . $result);
    }
    
    /**
     * Test to prevent chained command execution
     */
    public function testExecuteChainedParameter()
    {
        if (substr(PHP_OS, 0, 3) === 'WIN') {
            $this->_params[] = "&dir";
        } else {
            $this->_params[] = ";ls";
        }
        
        try {
            $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }
    
    /**
     * Test to see if the escaping mechanism renders supplemental results safely
     */
    public function testExecuteWindowsDoubleArgs()
    {
        if (substr(PHP_OS, 0, 3) !== 'WIN') {
            $this->markTestSkipped('Not Windows.');
        }
                
        try {
            $this->_params[] = "%SYSTEMROOT%\\explorer.exe %SYSTEMROOT%\\notepad.exe";
            $result = $this->_instance->executeSystemCommand($this->_executable, $this->_params);
            $this->assertNotNull($result);
        } catch (ExecutorException $e) {
            $this->fail($e->getMessage());
        }
    }
}
