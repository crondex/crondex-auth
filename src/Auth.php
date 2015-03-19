<?php namespace CrondexAuth;

use CrondexAuth\AuthInterface;
use Crondex\Model\Model;
use Crondex\Security\Random;
use Crondex\Security\RandomInterface;
use Crondex\Config\EnvironmentInterface;

class Auth extends Model implements AuthInterface
{
    public $loggedInUser;
    protected $random;
    protected $user;
    protected $token;
    private $loggedInUsersTable;
    private $sessionIdColumn;
    private $tokenColumn;
    private $userIdColumn;
    private $usersTable;
    private $usernameColumn;

    public function __construct($config, RandomInterface $randomObj, $sessionManagerObj)
    {
        //call the parent constructor
        parent::__construct($config);

        //inject objects
        $this->config = $config;
        $this->random = $randomObj;
        $this->session = $sessionManagerObj;

        //get database table and column names (from main.ini config)
        $this->loggedInUsersTable = $config->get('loggedInUsersTable');
        $this->sessionIdColumn = $config->get('sessionIdColumn');
        $this->tokenColumn = $config->get('tokenColumn');
        $this->userIdColumn = $config->get('userIdColumn');
        $this->usersTable = $config->get('usersTable');
        $this->usernameColumn = $config->get('usernameColumn');
    }

    protected function setToken() {

        /*
         * Assign a random value to $token
         */
        $token = $this->random->get_random_bytes(50);

        /*
         * hash the token
         * although not a password, we're using the password_hash function
         */
        $this->token = password_hash($token, PASSWORD_BCRYPT, array("cost" => 5));
        return true;
    }

    protected function refresh($userID)
    {
        //Regenerate id
        //session_regenerate_id(true);
        $this->session->regenerate();

        //set session token and update database
        if ($this->setToken()) {
            $_SESSION['token'] = $this->token;

            //set sql to update token logged-in-users
            $sql = "UPDATE $this->loggedInUsersTable SET $this->sessionIdColumn=?, $this->tokenColumn=? WHERE $this->userIdColumn=?";
            $params = array(session_id(), $this->token, $userID);

            //update database
            if ($this->query($sql, $params, 'names')) {

                //session details have been updated in database
                return true;
            }
            //updating database failed
            return false;
        }
        //session database update failed - new token not set
        return false;
    }

    public function removeLoggedInUser() {

        //if $_SESSION variables are set
        if (isset($_SESSION['user_id']) || isset($_SESSION['token'])) {

            //delete logged-in users
            $sql = "DELETE FROM $this->loggedInUsersTable WHERE $this->userIdColumn=? OR $this->sessionIdColumn=? OR $this->tokenColumn=?";
            $params = array($_SESSION['user_id'], session_id(), $_SESSION['token']);
        
            if ($this->query($sql, $params, 'names')) {
                return true;
            }
            return false;
        }
        return false;
    }

    public function login($user)
    {
        //grab user row based on username
        $sql = "SELECT * FROM $this->usersTable WHERE $this->usernameColumn=?";
        $params = array($user);
        $rows = $this->query($sql, $params, 'names');

        //get user's 'id' and assign to $user_id
        if ($rows) {
            //loop through each row (there should only be one match)
            foreach ($rows as $row) {
                $user_id = $row['id'];
            }
        } else {
            return false;
        }

        //setup session vars
        if ($this->setToken()) {

            $_SESSION['token'] = $this->token;
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $user;

        } else {
            return false;
        }

        //first remove logged-in users
        if ($this->removeLoggedInUser()) {

            //next insert new 'logged_in_user' record
            $sql = "INSERT INTO $this->loggedInUsersTable ($this->userIdColumn, $this->sessionIdColumn, $this->tokenColumn) VALUES (?, ?, ?)";
            $params = array($user_id, session_id(), $this->token);

            if ($this->query($sql, $params, 'names')) {
	        return true;
            } else {
                return false;
            }

        } else {
            return false;
        }
    }

    public function getLoggedInUserDetails($user_id)
    {
        //if (isset($user_id) && $this->check($user_id)) {
        //We don't need to run $this->check because it's run by the bootstrap

        if (isset($user_id)) {

            //set prepared statements
            $sql = "SELECT * FROM $this->usersTable WHERE id=?";
            $params = array($user_id);
            $rows = $this->query($sql, $params, 'names');

            //was the query successful
            if ($rows) {

                //loop through each row (there should only be one match)
                foreach ($rows as $row) {
                    $this->username = $row['username'];
                    $this->first_name = $row['first_name'];
                    $this->last_name = $row['last_name'];
                    $this->email = $row['email'];
                    $this->role_id = $row['role_id'];
                }    
            } else {
                return false;
            }
        } else {
            return false;
        } 
    }

    //check if logged in
    public function check($user_id)
    {
        if (isset($user_id)) {

            $sql = "SELECT * FROM $this->loggedInUsersTable WHERE $this->userIdColumn=?";
            $params = array($user_id);
            $rows = $this->query($sql, $params, 'names');

            if ($rows) {

                //loop through each row (there should only be one match)
                foreach ($rows as $row) {

                    $session_id = $row['session_id'];
                    $token = $row['token'];
                }

                //check to see if the session_id and token match the database
                if ($session_id === session_id() && $token === $_SESSION['token']) {

                    //they are the same
                    $this->refresh($user_id);
                    return true;

                } else {

                    //they are different
                    $this->logout();
                    return false;
                }
            }
            return false;
        }
        return false;
    }

    public function logout()
    {
        if ($this->removeLoggedInUser()) {

            session_unset();
            //$_SESSION = '';
            session_destroy();

            return true;
        }
        return false;
    }
}

