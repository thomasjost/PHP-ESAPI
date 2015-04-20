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
 * @author Bipin Upadhyay <http://projectbee.org/blog/contact/>
 * @created 2009
 *
 * @since 1.4
 *
 * @version 1.07
 *
 * @package ESAPI_Reference
 */

//FIXME: Cleanup to be done, as suggested by Mike

define("MAX_ROLE_LENGTH", 250);

/**
 * Reference Implementation of the DefaultUser interface.
 *
 * @category  OWASP
 *
 * @package   ESAPI_Reference
 *
 * @author    Bipin Upadhyay <http://projectbee.org/blog/contact/>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 *
 * @version   Release: @package_version@
 *
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class DefaultUser implements User
{

    //Configs
    public $allowedLoginAttempts = 3;
    public $sessionTimeout = 3600; #one hour
    public $sessionAbsoluteTimeout = 7200; #2 hours
    //TODO: load these from config
    private $_username;
    private $_password;
    private $_uid;
    private $_userInfo = array();
    private $_PathToUsersFiles = "../../test/testresources/users.txt";

    private static $IDLE_TIMEOUT_LENGTH = null;
    private static $ABSOLUTE_TIMEOUT_LENGTH = null;

    /** This user's account id. */
    private $_accountId = 0;

    /** This user's account name. */
    private $_accountName = "";

    /** This user's screen name (account name alias). */
    private $_screenName = "";

    /** This user's CSRF token. */
    private $_csrfToken = "";

    /** This user's assigned roles. */
    private $_roles = array();

    /** Whether this user's account is locked. */
    private $_locked = false;

    /** Whether this user is logged in. */
    private $_loggedIn = true;

    /** Whether this user's account is enabled. */
    private $_enabled = false;

    /** The last host address used by this user. */
    private $_lastHostAddress;

    /** The last password change time for this user. */
    //	private $lastPasswordChangeTime = new Date(0);

    /** The last login time for this user. */
    //	private $lastLoginTime = new Date(0);

    /** The last failed login time for this user. */
    //	private $lastFailedLoginTime = new Date(0);

    /** The expiration date/time for this user's account. */
    //	private $expirationTime = new Date(Long.MAX_VALUE);

    /** The session's this user is associated with */
    private $_sessions = array();

    /* A flag to indicate that the password must be changed before the account can be used. */
    // private boolean requiresPasswordChange = true;

    /** The failed login count for this user's account. */
    private $_failedLoginCount = 0;

    const MAX_ROLE_LENGTH = 250;

    public function __construct($accountName)
    {
        $this->setAccountName($accountName);

        //TODO: Not the best way IMHO. I'd rather call the method via factory object each time. Needs discussion..
        $this->IDLE_TIMEOUT_LENGTH = ESAPI::getSecurityConfiguration()->getSessionIdleTimeoutLength();
        $this->ABSOLUTE_TIMEOUT_LENGTH = ESAPI::getSecurityConfiguration()->getSessionAbsoluteTimeoutLength();

        do {
            $id = ESAPI::getRandomizer()->getRandomLong();
            if (ESAPI::getAuthenticator()->getUserById($id) == null && $id != 0) {
                $this->setAccountID($id);
            }
        } while ($this->getAccountID() == 0);
    }

    public function __destruct()
    {
        $this->writeUserInfo();
    }

    /**
     * This is intended to compute the password hash for a password.
     *
     * @param string $password
     *
     * @return string The hash
     */
    public function hashPassword($password)
    {
        //TODO: code this
        return "";
    }
    
    /**
     * This array holds the keys for users fields in order and is used in parseUserInfo().
     *
     * @var array
     */
    private $UserInfoFields = array("accountName" , "hashedPassword" , "roles" , "locked" , "enabled" , "rememberToken" , "csrfToken" , "oldPasswordHashes" , "lastPasswordChangeTime" , "lastLoginTime" , "lastFailedLoginTime" , "expirationTime" , "failedLoginCount");
    
    private function setUserInfo($field, $value)
    {
        $this->_userInfo[$field] = $value;
    }

    private function getUserInfo($field)
    {
        if (! array_key_exists($field, $this->_userInfo)) {
            return null;
        }

        return $this->_userInfo[$field];
    }

    private function parseUserInfo($data)
    {
        $data = explode(" | ", $data);
        $n = 0;
        $this->_userInfo = array();
        foreach ($data as $D) {
            $this->_userInfo[$this->_userInfoFields[$n ++]] = $D;
        }
    }

    private function readUserInfo()
    {
        $Compare = $this->_username;
        $fp = fopen(__DIR__ . "/" . $this->_PathToUsersFiles, "r");
        if (! $fp) {
            throw new Exception("Can not open the users.txt file!");
        }
        while (! feof($fp)) {
            $Line = fgets($fp);
            if (substr($Line, 0, strlen($Compare)) == $Compare) {
                $Data = $Line;
                $this->parseUserInfo($Data);
                break;
            }
        }
        fclose($fp);
    }

    private function writeUserInfo()
    {
        $Compare = $this->_username;
        $fp = fopen(__DIR__ . "/" . $this->_PathToUsersFiles, "r");
        if (! $fp) {
            throw new Exception("Can not open the users.txt file!");
        }
        $Data = "";
        while (! feof($fp)) {
            $Line = fgets($fp);
            $Line = trim($Line);
            if (strlen($Line) > strlen($Compare) and substr($Line, 0, strlen($Compare)) != $Compare) {
                $Data .= $Line . "\n";
            }
        }
        fclose($fp);
        $fp = fopen(__DIR__ . "/" . $this->_PathToUsersFiles, "w+");
        if (! $fp) {
            throw new Exception("Can not open the users.txt file for writing!!");
        }
        fwrite($fp, $Data);
        if ($this->_userInfo) {
            fwrite($fp, implode(" | ", $this->_userInfo));
        }
        fclose($fp);
    }

    public function getAccountName()
    {
        //TODO: Redo
        return $this->_accountName;
    }

    /**
     * {@inheritDoc}
     */
    public function getLocale()
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }
    
    /**
     * {@inheritDoc}
     */
    public function setLocale(Locale $locale)
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }
    
    /**
     * {@inheritDoc}
     */
    public function addRole($role)
    {
        $roleName = strtolower($role);
        if (false/*ESAPI::getValidator()->isValidInput("addRole", $roleName, "RoleName", MAX_ROLE_LENGTH, false) */) {
            //TODO: Verify if this is correct
            $this->_roles[] = $roleName;
            ESAPI::getLogger("DefaultUser")->info(
                ESAPILogger::SECURITY,
                true,
                "Role " . $roleName . " added to " . $this->getAccountName()
            );
        } else {
            //TODO: Not done in Java, but shouldn't this be logged as well?
            throw new AuthenticationAccountsException(
                "Add role failed",
                "Attempt to add invalid role " . $roleName . " to " . $this->getAccountName()
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    public function addRoles($newRoles)
    {
        foreach ($newRoles as $role) {
            $this->addRole($role);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function changePassword($oldPassword, $newPassword1, $newPassword2)
    {
        ESAPI::getAuthenticator()->changePassword($this, $oldPassword, $newPassword1, $newPassword2);
    }

    /**
     * {@inheritDoc}
     */
    public function disable()
    {
        $this->_enabled = false;
        ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "Account disabled: " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function enable()
    {
        $this->enable = true;
        ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "Account enabled: " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function getAccountId()
    {
        return $this->_accountId;
    }

    /**
     * {@inheritDoc}
     */
    public function getCSRFToken()
    {
        return $this->_csrfToken;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpirationTime()
    {
        //TODO: Redo
        return $this->getUserInfo("expirationTime");
    }

    /**
     * {@inheritDoc}
     */
    public function getFailedLoginCount()
    {
        return $this->_failedLoginCount;
    }

    /**
     * {@inheritDoc}
     */
    public function getLastHostAddress()
    {
        if ($this->_lastHostAddress == null) {
            return "local";
        } else {
            return $this->_lastHostAddress;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getLastFailedLoginTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastFailedLoginTime");
    }

    /**
     * {@inheritDoc}
     */
    public function getLastLoginTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastLoginTime");
    }

    /**
     * {@inheritDoc}
     */
    public function getLastPasswordChangeTime()
    {
        //TODO: Redo
        return $this->getUserInfo("lastPasswordChangeTime");
    }

    /**
     * {@inheritDoc}
     */
    public function getRoles()
    {
        //TODO: Redo
        return explode(",", $this->getUserInfo("roles"));
    }

    /**
     * {@inheritDoc}
     */
    public function getScreenName()
    {
        return $this->_screenName;
        //return $this->getUserInfo("accountName");
    }

    /**
     * {@inheritDoc}
     */
    public function addSession($HttpSession = null)
    {
        //TODO: Redo
        if (session_id() == "") {
            //TODO no session established, throw some errors
        }
        
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        
        $_SESSION[$this->getAccountId()][$HttpSession] = array("start" => time() , "lastUpdate" => time());
    }

    /**
     * {@inheritDoc}
     */
    public function removeSession($HttpSession = null)
    {
        //TODO: Redo
        if ($HttpSession === null) {
            $HttpSession = session_id();
        }
        unset($_SESSION[$this->getAccountId()][$HttpSession]);
    }

    /**
     * {@inheritDoc}
     */
    public function getSessions()
    {
        //TODO: Redo
        return $_SESSION[$this->getAccountId()];
    }

    /**
     * {@inheritDoc}
     */
    public function incrementFailedLoginCount()
    {
        $this->_failedLoginCount++;
    }

    /**
     * @param unknown $count
     */
    public function setFailedLoginCount($count)
    {
        //TODO: Redo
        $this->setUserInfo("failedLoginCount", $count);
        if ($this->getFailedLoginCount() >= $this->allowedLoginAttempts) {
            $this->lock();
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isAnonymous()
    {
        //TODO: Redo
        //Need to discuss the concept of anonymous in context with PHP
        if ($this->_uid === null) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isEnabled()
    {
        return $this->_enabled;
    }

    /**
     * {@inheritDoc}
     */
    public function isExpired()
    {
        //TODO: Redo
        $ExpTime = $this->getUserInfo("expirationTime");
        if ($ExpTime < time()) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function isInRole($role)
    {
        return in_array(strtolower($role), $this->_roles);
    }

    /**
     * {@inheritDoc}
     */
    public function isLocked()
    {
        return $this->_locked;
    }

    /**
     * {@inheritDoc}
     */
    public function isLoggedIn()
    {
        return $this->_loggedIn;
    }

    /**
     * {@inheritDoc}
     *
     * @param string $session Optional session id
     */
    public function isSessionAbsoluteTimeout($session = null)
    {
        //TODO: Redo
        if ($session === null) {
            $session = session_id();
        }
        if (isset($_SESSION[$this->getAccountId()][$session]['start'])) {
            return (time() - $_SESSION[$this->getAccountId()][$session]['start']) > $this->sessionAbsoluteTimeout;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @param string $session Optional session id
     */
    public function isSessionTimeout($session = null)
    {
        //TODO: Redo
        if ($session === null) {
            $session = session_id();
        }
        #XXX: You should add some logic to update session time somewhere!
        if (isset($_SESSION[$this->getAccountId()][$session]['lastUpdate'])) {
            return (time() - $_SESSION[$this->getAccountId()][$session]['lastUpdate']) > $this->sessionTimeout;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function lock()
    {
        $this->_locked = true;
        ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "Account locked: " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function loginWithPassword($password)
    {
        //FIXME: time() might not be the correct format to be used?
        if (is_null($password) || $password == "") {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Missing password: " . $this->getAccountName());
        }

        // don't let disabled users log in
        if (! $this->isEnabled()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Disabled user attempt to login: " . $this->getAccountName());
        }

        // don't let locked users log in
        if ($this->isLocked()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Locked user attempt to login: " . $this->getAccountName());
        }

        // don't let expired users log in
        if ($this->isExpired()) {
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Expired user attempt to login: " . $this->getAccountName());
        }

        $this->logout();

        if ($this->verifyPassword($password)) {
            $this->_loggedIn = true;
            ESAPI::getHttpUtilities()->changeSessionIdentifier(ESAPI::currentRequest());
            ESAPI::getAuthenticator()->setCurrentUser($this);
            $this->setLastLoginTime(time());
            $this->setLastHostAddress(ESAPI::getHttpUtilities()->getCurrentRequest()->getRemoteHost());
            ESAPI::getLogger("DefaultUser")->trace(ESAPILogger::SECURITY, "User logged in: " . $this->_accountName);
        } else {
            $this->_loggedIn = false;
            $this->setLastFailedLoginTime(time());
            $this->incrementFailedLoginCount();
            throw new AuthenticationLoginException("Login failed", "Incorrect password provided for " . $this->getAccountName());
        }
    }

    /**
     * {@inheritDoc}
     */
    public function logout()
    {
        //TODO: Redo
        //TODO: ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME);
        //HttpSession session = ESAPI.currentRequest().getSession(false);
        if (isset($_SESSION[$this->getAccountId()])) {
            unset($_SESSION[$this->getAccountId()]);
        }
        //TODO: ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), "PHPSESSIONID");
        $this->_loggedIn = false;
        //logger.info(Logger.SECURITY_SUCCESS, "Logout successful");
        //ESAPI.authenticator().setCurrentUser(User.ANONYMOUS);
    }

    /**
     * {@inheritDoc}
     */
    public function removeRole($role)
    {
        $role = strtolower($role);
        unset($this->_roles[$role]);
        ESAPI::getLogger("DefaultLogger")->trace(ESAPILogger::SECURITY, true, "Role " . $role . " removed from " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function resetCSRFToken() //throws AuthenticationException;
    {
        //TODO: Uncomment when Encoder's implemented
        //        $this->_csrfToken = ESAPI::getRandomizer()->getRandomString(8, DefaultEncoder::CHAR_ALPHANUMERICS);
        return $csrfToken;
    }

    /**
     * {@inheritDoc}
     */
    public function setAccountName($accountName)
    {
        $oldAccountName = $this->getAccountName();
        $this->_accountName = strtolower($accountName);
        if (!is_null($oldAccountName)) {
            ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "Account name changed from " . $oldAccountName . " to " . $this->getAccountName());
        }
    }

    /**
     * Sets this user's account ID.
     *
     * @param integer $accountId
     */
    public function setAccountID($accountId)
    {
        $this->_accountId = $accountId;
    }

    /**
     * {@inheritDoc}
     */
    public function setExpirationTime(DateTime $expirationTime)
    {
        //TODO: Redo
        $this->setUserInfo("expirationTime", $expirationTime);
    }

    /**
     * {@inheritDoc}
     */
    public function setRoles($roles)
    {
        //TODO: Redo
        $this->setUserInfo("roles", implode(",", $Roles));
    }

    /**
     * {@inheritDoc}
     */
    public function setScreenName($screenName)
    {
        $this->_screenName = $screenName;
        ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "ScreenName changed to " . $screenName . " for " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function unlock()
    {
        $this->_locked = false;
        $this->_failedLoginCount = 0;
        ESAPI::getLogger("DefaultUser")->info(ESAPILogger::SECURITY, true, "Account unlocked: " . $this->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function verifyPassword($password)
    {
        return ESAPI::getAuthenticator()->verifyPassword($this, $password);
    }

    /**
     * {@inheritDoc}
     */
    public function setLastFailedLoginTime($lastFailedLoginTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastFailedLoginTime", $lastFailedLoginTime);
    }

    public function setLastHostAddress($remoteHost)
    {
        //TODO: Redo
        if ($this->_lastHostAddress != null && $this->_lastHostAddress != $remoteHost) {
            // returning remote address not remote hostname to prevent DNS lookup
            new AuthenticationHostException("Host change", "User session just jumped from " . $this->_lastHostAddress . " to " . $remoteHost);
        }
        $this->_lastHostAddress = $remoteHost;
    }

    /**
     * {@inheritDoc}
     */
    public function setLastLoginTime($lastLoginTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastLoginTime", $lastLoginTime);
    }

    /**
     * {@inheritDoc}
     */
    public function setLastPasswordChangeTime($lastPasswordChangeTime)
    {
        //TODO: Redo
        $this->setUserInfo("lastPasswordChangeTime", $lastPasswordChangeTime);
    }

    /**
     * {@inheritDoc}
     */
    public function getEventMap()
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }
    
    /*
     * The ANONYMOUS user is used to represent an unidentified user. Since there is
     * always a real user, the ANONYMOUS user is better than using NULL to represent
     * this.
     */
    //FIXME:
    public $ANONYMOUS;
}
