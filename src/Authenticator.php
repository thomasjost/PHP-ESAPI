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
 * @author Jeff Williams <jeff.williams@aspectsecurity.com>
 *
 * @created 2007
 */

/**
 * The Authenticator interface defines a set of methods for generating and
 * handling account credentials and session identifiers. The goal of this
 * interface is to encourage developers to protect credentials from disclosure
 * to the maximum extent possible.
 * <P>
 * One possible implementation relies on the use of a thread local variable to
 * store the current user's identity. The application is responsible for calling
 * setCurrentUser() as soon as possible after each HTTP request is received. The
 * value of getCurrentUser() is used in several other places in this API. This
 * eliminates the need to pass a user object to methods throughout the library.
 * For example, all of the logging, access control, and exception calls need
 * access to the currently logged in user.
 * <P>
 * The goal is to minimize the responsibility of the developer for
 * authentication. In this example, the user simply calls authenticate with the
 * current request and the name of the parameters containing the username and
 * password. The implementation should verify the password if necessary, create
 * a session if necessary, and set the user as the current user.
 *
 * <pre>
 *     public function doPost($request, $response) {
 *         try {
 *             User user = ESAPI::getAuthenticator()->login($request, $response);
 *             // continue with authenticated user
 *         } catch (AuthenticationException $e) {
 *             // handle failed authentication (it's already been logged)
 *         }
 * </pre>
 *
 * @author Jeff Williams <jeff.williams@aspectsecurity.com>
 *
 * @since June 1, 2007
 */
interface Authenticator
{

    /**
     * Clears the current User. This allows the thread to be reused safely.
     *
     * This clears all threadlocal variables from the thread. This should ONLY be called after
     * all possible ESAPI operations have concluded. If you clear too early, many calls will
     * fail, including logging, which requires the user identity.
     */
    public function clearCurrent();

    /**
     * This method should be called for every HTTP request, to login the current user either from the session of HTTP
     * request. This method will set the current user so that getCurrentUser() will work properly.
     *
     * Authenticates the user's credentials from the HttpServletRequest if
     * necessary, creates a session if necessary, and sets the user as the
     * current user.
     *
     * Uses the current request and response if called without parameters.
     * @see HTTPUtilities::setCurrentHTTP($request, $response)
     *
     * Specification:  The implementation should do the following:
     * 1) Check if the User is already stored in the session
     *     a. If so, check that session absolute and inactivity timeout have not expired
     *     b. Step 2 may not be required if 1a has been satisfied
     * 2) Verify User credentials
     *     a. It is recommended that you use
     *         loginWithUsernameAndPassword($request, $response) to verify credentials
     * 3) Set the last host of the User (ex.  $user->setLastHostAddress($address) )
     * 4) Verify that the request is secure (ex. over SSL)
     * 5) Verify the User account is allowed to be logged in
     *     a. Verify the User is not disabled, expired or locked
     * 6) Assign User to session variable
     *
     * @param $request The current HTTP request
     * @param $response The HTTP response
     *
     * @throws AuthenticationException If the credentials are not verified, or if the account is disabled, locked,
     *                                 expired, or timed out
     *
     * @return The user
     */
    public function login($request = null, $response = null);

    /**
     * Verify that the supplied password matches the password for this user. Password should
     * be stored as a hash. It is recommended you use the hashPassword(password, accountName) method
     * in this class.
     * This method is typically used for "reauthentication" for the most sensitive functions, such
     * as transactions, changing email address, and changing other account information.
     *
     * @param User $user The user who requires verification
     * @param string $password The hashed user-supplied password
     *
     * @return TRUE, if the password is correct for the specified user
     */
    public function verifyPassword(User $user, $password);

    /**
     * Logs out the current user.
     *
     * This is usually done by calling User::logout on the current user.
    */
    public function logout();

    /**
     * Creates a new User with the information provided. Implementations should check
     * accountName and password for proper format and strength against brute force
     * attacks ( verifyAccountNameStrength(String), verifyPasswordStrength(String, String)  ).
     *
     * Two copies of the new password are required to encourage user interface designers to
     * include a "re-type password" field in their forms. Implementations should verify that
     * both are the same.
     *
     * @param string $accountName The account name of the new user
     * @param string $password1 The password of the new user
     * @param string $password2 The password of the new user.  This field is to encourage user interface designers to include two password fields in their forms.
     *
     * @throws AuthenticationException If user creation fails due to any of the qualifications listed in this method's description
     *
     * @return The User that has been created
     */
    public function createUser($accountName, $password1, $password2);

    /**
     * Generate a strong password. Implementations should use a large character set that does not
     * include confusing characters, such as i I 1 l 0 o and O.  There are many algorithms to
     * generate strong memorable passwords that have been studied in the past.
     *
     * If user and password are supplied, generate strong password that takes into account the user's information and
     * old password. Implementations should verify that the new password does not include information such as the
     * username, fragments of the old password, and other information that could be used to weaken the strength of the
     * password.
     *
     * @param User $user The user whose information to use when generating password
     * @param string $oldPassword The old password to use when verifying strength of new password. The new password may
     *                            be checked for fragments of oldPassword.
     *
     * @return A password with strong password strength
     */
    public function generateStrongPassword($user = null, $oldPassword = null);

    /**
     * Changes the password for the specified user. This requires the current password, as well as
     * the password to replace it with. The new password should be checked against old hashes to be sure the new password does not closely resemble or equal any recent passwords for that User.
     * Password strength should also be verified.  This new password must be repeated to ensure that the user has typed it in correctly.
     *
     * @param User $user The user to change the password for
     * @param string $currentPassword The current password for the specified user
     * @param string $newPassword The new password to use
     * @param string $newPassword2 A verification copy of the new password
     *
     * @throws AuthenticationException If any errors occur
     */
    public function changePassword($user, $currentPassword, $newPassword, $newPassword2);

    /**
     * Returns the User matching the provided accountId.  If the accoundId is not found, an Anonymous
     * User or NULL may be returned.
     *
     * @param int $accountId The account id
     *
     * @return User The matching User object, or the Anonymous User if no match exists
     */
    public function getUserById($accountId);

    /**
     * Returns the User matching the provided accountName.  If the accountName is not found, an Anonymous
     * User or NULL may be returned.
     *
     * @param string $accountName The account name
     *
     * @return User The matching User object, or the Anonymous User if no match exists
     */
    public function getUserByName($accountName);

    /**
     * Gets a collection containing all the existing user names.
     *
     * @return array A set of all user names
    */
    public function getUserNames();

    /**
     * Returns the currently logged in User.
     *
     * @return The matching User object, or the Anonymous User if no match exists
     */
    public function getCurrentUser();

    /**
     * Sets the currently logged in User.
     *
     * @param User $user The user to set as the current user
     */
    public function setCurrentUser($user);

    /**
     * Returns a $representation of the hashed password, using the
     * accountName as the salt. The salt helps to prevent against "rainbow"
     * table attacks where the attacker pre-calculates hashes for known strings.
     * This method specifies the use of the user's account name as the "salt"
     * value. The Encryptor.hash method can be used if a different salt is
     * required.
     *
     * @param string $password The password to hash
     * @param string $accountName The account name to use as the salt
     *
     * @return The hashed password
     */
    public function hashPassword($password, $accountName);

    /**
     * Removes the account of the specified accountName.
     *
     * @param string $accountName The account name to remove
     *
     * @throws AuthenticationException The authentication exception if user does not exist
     */
    public function removeUser($accountName);

    /**
     * Ensures that the account name passes site-specific complexity requirements, like minimum length.
     *
     * @param string $accountName The account name
     *
     * @throws AuthenticationException If account name does not meet complexity requirements
     */
    public function verifyAccountNameStrength($accountName);

    /**
     * Ensures that the password meets site-specific complexity requirements, like length or number
     * of character sets. This method takes the old password so that the algorithm can analyze the
     * new password to see if it is too similar to the old password. Note that this has to be
     * invoked when the user has entered the old password, as the list of old
     * credentials stored by ESAPI is all hashed.
     * Additionally, the user object is taken in order to verify the password and account name differ.
     *
     * @param string $oldPassword The old password
     * @param string $newPassword The new password
     * @param User $user The user
     *
     * @throws AuthenticationException If newPassword is too similar to oldPassword or if newPassword does not meet complexity requirements
     */
    public function verifyPasswordStrength($oldPassword, $newPassword, User $user);

    /**
     * Determine if the account exists.
     *
     * @param string $accountName The account name
     *
     * @return TRUE, if the account exists
     */
    public function exists($accountName);
}
