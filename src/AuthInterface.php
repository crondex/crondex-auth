<?php namespace CrondexAuth;

interface AuthInterface
{
    public function removeLoggedInUser();
    public function login($user);
    public function getLoggedInUserDetails($user_id);
    public function check($user_id);
    public function logout();
}
