<?php

/**
 * DefaultAcl
 * @copyright Copyright (c) 2011 - 2015 Aleksandr Torosh (http://wezoom.com.ua)
 * @author Aleksandr Torosh <webtorua@gmail.com>
 */

namespace Application\Acl;

use  Admin\Model\AdminUser;

class DefaultAcl extends \Phalcon\Acl\Adapter\Memory
{

    private $front_roles = ['guest','member'];
    
    public function __construct()
    {
        parent::__construct();

        $this->setDefaultAction(\Phalcon\Acl::DENY);

        /**
         * Full list of Roles
         */
         $roles = [];
        $available_roles = array_merge($this->front_roles, AdminUser::$roles);
        foreach ($available_roles as as $role_key => $role) {
            $roles[$role]  = new \Phalcon\Acl\Role($role, ucfirst($role));
            if ($role == 'guest') {
                $this->addRole($roles[$role]);
            } elseif (in_array($role,['member','journalist'])) {
                $this->addRole($roles[$role], $roles['guest');
            }else {
                $this->addRole($roles[$role], $roles[$available_roles[$role_key - 1]]);
            }
        }
  
        /**
         * Include resources permissions list from file /app/config/acl.php
         */
        $resources = include APPLICATION_PATH . '/config/acl.php';

        foreach ($resources as $roles_resources) {
            foreach ($roles_resources as $resource => $actions) {
                $this->addResource(new \Phalcon\Acl\Resource($resource), $actions);
            }
        }

        /**
         * Make unlimited access for admin role
         */
        $this->allow('admin', '*', '*');

        /**
         * Set roles permissions
         */
        foreach ($roles as $k => $role) {
            $user_resource = $resources[$k];
            foreach ($user_resource as $roles_resources => $method) {
                $this->allow($k, $roles_resources, $method);
            }
        }
    }

}
