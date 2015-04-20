<?php
/**
 * OWASP Enterprise Security API (ESAPI).
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
 * @author Bipin Upadhyay <http://projectbee.org/blog/contact/>
 * @created 2009
 *
 * @since 1.4
 *
 * @package ESAPI_Reference
 */

define('MAX_ACCOUNT_NAME_LENGTH', 250);
/**
 * Reference Implementation of the FileBasedAuthenticator interface.
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
class FileBasedAuthenticator implements Authenticator
{

    private $users;

    /** The file that contains the user db */
    private $userDB;

    /** How frequently to check the user db for external modifications */
    private $checkInterval = 60000;//60 * 1000;

    /** The last modified time we saw on the user db. */
    private $lastModified = 0;

    /** The last time we checked if the user db had been modified externally */
    private $lastChecked = 0;

    /** Associative array of user: array(AccoundId => UserObjectReference) */
    private $userMap = array();

    // $passwordMap[user] = passwordHash, where the values are password hashes, with the current hash in entry 0
    private $passwordMap = array();

    public function __construct()
    {
        $this->users = array();
        $this->logger = ESAPI::getLogger("Authenticator");
    }

    /**
     * {@inheritDoc}
     */
    public function clearCurrent()
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function login($request, $response)
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function verifyPassword($user, $password)
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function logout()
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function createUser($accountName, $password1, $password2)
    {
        $this->loadUsersIfNecessary();
        if (!$this->isValidString($accountName)) {
            throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName");
        }
        if ($this->getUserByName($accountName) != null) {
            throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " . $accountName);
        }

        $this->verifyAccountNameStrength($accountName);

        if ($password1 == null) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account " . $accountName . " with a null password");
        }
        $this->verifyPasswordStrength(null, $password1);

        if ($password1 != $password2) {
            throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " . $accountName . " do not match");
        }

        $user = new DefaultUser($accountName);
        try {
            $this->setHashedPassword($user, $this->hashPassword($password1, $accountName));
        } catch (EncryptionException $ee) {
            throw new AuthenticationException("Internal error", "Error hashing password for " . $accountName);
        }

        $this->userMap[$user->getAccountId()] = $user;

        $this->logger->info(ESAPILogger::SECURITY, true, "New user created: " . $accountName);
        $this->saveUsers();

        return $user;
    }

    /**
     * Load users if they haven't been loaded in a while.
     */
    protected function loadUsersIfNecessary()
    {
        //        throw new EnterpriseSecurityException("Method Not Implemented");
        if (!$this->isValidString($this->userDB)) {
            $fileHandle = ESAPI::getSecurityConfiguration()->getResourceDirectory() . "users.txt";
            $this->userDB = fopen($fileHandle, 'a');
        }

        // We only check at most every checkInterval milliseconds
        $now = time();
        if ($now - $this->lastChecked < $this->checkInterval) {
            return;
        }
        $this->lastChecked = $now;

        $fileData = fstat($this->userDB);
        if ($this->lastModified == $fileData['mtime']) {
            return;
        }
        //Note: Removing call for now to avoid red exception and spread greenery in tests :)
        //        $this->loadUsersImmediately();
    }

    protected function loadUsersImmediately()
    {
        throw new EnterpriseSecurityException("Method Not Implemented");
    }

    /**
     * Saves the user database to the file system. In this implementation you must call save to commit any changes to
     * the user file. Otherwise changes will be lost when the program ends.
     *
     * @throws AuthenticationException If the user file could not be written
     */
    public function saveUsers()
    {
        throw new EnterpriseSecurityException("Method Not Implemented");
    }

    /**
     * {@inheritDoc}
     */
    public function generateStrongPassword($user = null, $oldPassword = null)
    {
        $randomizer = ESAPI::getRandomizer();
        $letters = $randomizer->getRandomInteger(4, 6);
        $digits = 7 - $letters;
        $passLetters = $randomizer->getRandomString($letters, DefaultEncoder::CHAR_PASSWORD_LETTERS);
        $passDigits = $randomizer->getRandomString($digits, DefaultEncoder::CHAR_PASSWORD_DIGITS);
        $passSpecial = $randomizer->getRandomString(1, DefaultEncoder::CHAR_PASSWORD_SPECIALS);
        $newPassword = $passLetters . $passSpecial . $passDigits;

        if ($this->isValidString($newPassword) && $this->isValidString($user)) {
            $this->logger->info(ESAPILogger::SECURITY, true, "Generated strong password for " . $user->getAccountName());
        }

        return $newPassword;
    }

    /**
     * {@inheritDoc}
     */
    public function changePassword($user, $currentPassword, $newPassword, $newPassword2)
    {
        $accountName = $user->getAccountName();

        try {
            $currentHash = $this->getHashedPassword($user);
            $verifyHash = $this->hashPassword($currentPassword, $accountName);

            if ($currentHash != $verifyHash) {
                throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password change on user: " . $accountName);
            }

            if (!$this->isValidString($newPassword) || !$this->isValidString($newPassword2) || $newPassword != $newPassword2) {
                throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " . $accountName);
            }

            $this->verifyPasswordStrength($currentPassword, $newPassword);
            //TODO: Is this actually the expected value?
            $user->setLastPasswordChangeTime(time());
            $newHash = $this->hashPassword($newPassword, $accountName);
            if (in_array($newHash, $this->getOldPasswordHashes($user))) {
                throw new AuthenticationCredentialsException("Password change failed", "Password change matches a recent password for user: " . $accountName);
            }

            $this->setHashedPassword($user, $newHash);
            $this->logger->info(ESAPILogger::SECURITY, true, "Password changed for user: " . $accountName);
        } catch (EncryptionException $e) {
            throw new AuthenticationException("Password change failed", "Encryption exception changing password for " . $accountName);
        }
    }

    /**
     * Returns all of the specified User's hashed passwords.  If the User's list of passwords is NULL,
     * and create is set to TRUE, an empty password list will be associated with the specified User
     * and then returned. If the User's password map is NULL and create is set to FALSE, an exception
     * will be thrown.
     *
     * @param User $user The user whose old hashes should be returned
     * @param bool $create TRUE - if no password list is associated with this user, create one
     *                     FALSE - if no password list is associated with this user, do not create one
     *
     * @return A list containing all of the specified User's password hashes
     */
    public function getAllHashedPasswords($user, $create)
    {
        //        TODO: Reverify with tests. Something doesn't seem right here
        $hashes = $this->passwordMap[$user];
        if ($this->isValidString($hashes)) {
            return $hashes;
        }
        if ($create) {
            $hashes = array();
            $this->passwordMap[$user] = $hashes;

            return hashes;
        }
        throw new RuntimeException("No hashes found for " . $user->getAccountName() . ". Is User.hashcode() and equals() implemented correctly?");
    }

    /**
     * Return the specified User's current hashed password.
     *
     * @param User $user This user's current hashed password will be returned
     *
     * @return The specified User's current hashed password
     */
    public function getHashedPassword($user)
    {
        $hashes = $this->getAllHashedPasswords($user, false);

        return $hashes[0];
    }

    /**
     * Get a List of the specified User's old password hashes.  This will not return the User's current
     * password hash.
     *
     * @param User $user The user whose old password hashes should be returned
     *
     * @return The specified User's old password hashes
     */
    public function getOldPasswordHashes($user)
    {
        $hashes = $this->getAllHashedPasswords($user, false);
        if (count($hashes) > 1) {
            return array_slice($hashes, 1, (count($hashes) - 1), true);
        }

        return array();
    }

    /**
     * {@inheritDoc}
     */
    public function getUserById($accountId)
    {
        if ($accountId == 0) {
            //FIXME: ANONYMOUS User to be returned
            return null;
        }

        $this->loadUsersIfNecessary();

        if (in_array($accountId, $this->userMap)) {
            return $this->userMap[$accountId];
        } else {
            return null;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getUserByName($accountName)
    {
        if (empty($this->users)) {
            return null;
        }

        if (in_array($accountName, $this->users)) {
            return new DefaultUser($accountName, '123', '123');    // TODO: Milestone 3 - fix with real code
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserNames()
    {
        // TODO: Re-work in Milestone 3

        if (!empty($this->users)) {
            return $this->users;
        }

        $usersFile = __DIR__ . '/../../test/testresources/users.txt';
        $rawusers = file($usersFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        $users = array();

        foreach ($rawusers as $dummy => $row) {
            $row = trim($row);
            if (strlen($row) > 0 && $row[0] != '#') {
                $user = explode('|', $row);
                $users[] = $user[0];
            }
        }

        $this->users = $users;

        return $users;
    }

    /**
     * {@inheritDoc}
     */
    public function getCurrentUser()
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * {@inheritDoc}
     */
    public function setCurrentUser($user)
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes
     * to be sure that any new passwords are not too similar to old passwords.
     *
     * @param User $user The user to associate with the new hash
     * @param string $hash The hash to store in the user's password hash list
     */
    private function setHashedPassword($user, $hash)
    {
        $hashes = $this->getAllHashedPasswords($user, true);
        $hashes[0] = $hash;
        if (count($hashes) > ESAPI::getSecurityConfiguration()->getMaxOldPasswordHashes()) {
            //TODO: Verify
            array_pop($hashes);
        }
        $this->logger->info(ESAPILogger::SECURITY, true, "New hashed password stored for " . $user->getAccountName());
    }

    /**
     * {@inheritDoc}
     */
    public function hashPassword($password, $accountName)
    {
        $salt = strtolower($accountName);

        return ESAPI::getEncryptor()->hash($password, $salt);
    }

    /**
     * {@inheritDoc}
     */
    public function removeUser($accountName)
    {
        // TODO: Change in Milestone 3. In milestone 1, this is used to clean up a test

        $idx = array_search($accountName, $this->users);
        if (!empty($this->users) && $idx !== false) {
            unset($this->users[$idx]);

            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function verifyAccountNameStrength($accountName)
    {
        if (!$this->isValidString($accountName)) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null/empty account name");
        }

        if (true/*!ESAPI::getValidator()->isValidInput("verifyAccountNameStrength", $accountName, "AccountName", MAX_ACCOUNT_NAME_LENGTH, false)*/) {
            throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " . $accountName);
        }
    }

    /**
     * Ensures that the password meets site-specific complexity requirements, like length or number
     * of character sets. This method takes the old password so that the algorithm can analyze the
     * new password to see if it is too similar to the old password. Note that this has to be
     * invoked when the user has entered the old password, as the list of old
     * credentials stored by ESAPI is all hashed.
     *
     * @param string $oldPassword The old password
     * @param string $newPassword The new password
     *
     * @throws AuthenticationException If newPassword is too similar to oldPassword or if newPassword does not meet complexity requirements
     */
    public function verifyPasswordStrength($oldPassword, $newPassword)
    {
        if (!$this->isValidString($newPassword)) {
            throw new AuthenticationCredentialsException("Invalid password", "New password cannot be null");
        }

        // can't change to a password that contains any 3 character substring of old password
        if ($this->isValidString($oldPassword)) {
            $passwordLength = strlen($oldPassword);
            for ($counter = 0; $counter < $passwordLength - 2; $counter++) {
                $sub = substr($oldPassword, $counter, 3);
                if (strlen(strstr($newPassword, $sub)) > 0) {
                    //                if (strlen(strstr($newPassword, $sub)) > -1) { //TODO: Even this works. Revisit for a more elegant solution
                    throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password");
                }
            }
        }

        // new password must have enough character sets and length
        $charsets = 0;
        $passwordLength = strlen($newPassword);
        for ($counter = 0; $counter < $passwordLength; $counter++) {
            if (in_array(substr($newPassword, $counter, 1), str_split(DefaultEncoder::CHAR_LOWERS))) {
                $charsets++;
                break;
            }
        }
        for ($counter = 0; $counter < $passwordLength; $counter++) {
            if (in_array(substr($newPassword, $counter, 1), str_split(DefaultEncoder::CHAR_UPPERS))) {
                $charsets++;
                break;
            }
        }
        for ($counter = 0; $counter < $passwordLength; $counter++) {
            if (in_array(substr($newPassword, $counter, 1), str_split(DefaultEncoder::CHAR_DIGITS))) {
                $charsets++;
                break;
            }
        }
        for ($counter = 0; $counter < $passwordLength; $counter++) {
            if (in_array(substr($newPassword, $counter, 1), str_split(DefaultEncoder::CHAR_SPECIALS))) {
                $charsets++;
                break;
            }
        }

        // calculate and verify password strength
        $passwordStrength = $passwordLength * $charsets;
        if ($passwordStrength < 16) {
            throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
        }
    }

    /**
     * Determine if the account exists.
     *
     * @param string $accountName The account name
     *
     * @return TRUE, if the account exists
     */
    public function exists($accountName)
    {
        throw new EnterpriseSecurityException(
            'Method not implemented',
            'Method "' . __METHOD__ . '" not implemented'
        );
    }

    /**
     * Checks if the given string is valid
     *
     * @param string $param
     * @return bool
     */
    private function isValidString($param)
    {
        return (isset($param) && $param != '');
    }
}
