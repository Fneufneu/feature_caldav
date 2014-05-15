<?php

/**
 * Abstract interface class for Kolab storage IMAP folder objects
 *
 * @author Thomas Bruederli <bruederli@kolabsys.com>
 *
 * Copyright (C) 2014, Kolab Systems AG <contact@kolabsys.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
abstract class kolab_storage_folder_api
{
    /**
     * Folder identifier
     * @var string
     */
    public $id;

    /**
     * The folder name.
     * @var string
     */
    public $name;

    /**
     * The type of this folder.
     * @var string
     */
    public $type;

    /**
     * Is this folder set to be the default for its type
     * @var boolean
     */
    public $default = false;

    /**
     * List of direct child folders
     * @var array
     */
    public $children = array();
    
    /**
     * Name of the parent folder
     * @var string
     */
    public $parent = '';

    protected $imap;
    protected $owner;
    protected $info;
    protected $idata;
    protected $namespace;


    /**
     * Private constructor
     */
    protected function __construct($name)
    {
      $this->name = $name;
      $this->id   = kolab_storage::folder_id($name);
      $this->imap = rcube::get_instance()->get_storage();
    }


    /**
     * Returns the owner of the folder.
     *
     * @return string  The owner of this folder.
     */
    public function get_owner()
    {
        // return cached value
        if (isset($this->owner))
            return $this->owner;

        $info = $this->get_folder_info();
        $rcmail = rcube::get_instance();

        switch ($info['namespace']) {
        case 'personal':
            $this->owner = $rcmail->get_user_name();
            break;

        case 'shared':
            $this->owner = 'anonymous';
            break;

        default:
            list($prefix, $user) = explode($this->imap->get_hierarchy_delimiter(), $info['name']);
            if (strpos($user, '@') === false) {
                $domain = strstr($rcmail->get_user_name(), '@');
                if (!empty($domain))
                    $user .= $domain;
            }
            $this->owner = $user;
            break;
        }

        return $this->owner;
    }


    /**
     * Getter for the name of the namespace to which the IMAP folder belongs
     *
     * @return string Name of the namespace (personal, other, shared)
     */
    public function get_namespace()
    {
        if (!isset($this->namespace))
            $this->namespace = $this->imap->folder_namespace($this->name);
        return $this->namespace;
    }


    /**
     * Get the display name value of this folder
     *
     * @return string Folder name
     */
    public function get_name()
    {
        return kolab_storage::object_name($this->name, $this->get_namespace());
    }


    /**
     * Getter for the top-end folder name (not the entire path)
     *
     * @return string Name of this folder
     */
    public function get_foldername()
    {
        $parts = explode('/', $this->name);
        return rcube_charset::convert(end($parts), 'UTF7-IMAP');
    }


    /**
     * Get the color value stored in metadata
     *
     * @param string Default color value to return if not set
     * @return mixed Color value from IMAP metadata or $default is not set
     */
    public function get_color($default = null)
    {
        // color is defined in folder METADATA
        $metadata = $this->get_metadata(array(kolab_storage::COLOR_KEY_PRIVATE, kolab_storage::COLOR_KEY_SHARED));
        if (($color = $metadata[kolab_storage::COLOR_KEY_PRIVATE]) || ($color = $metadata[kolab_storage::COLOR_KEY_SHARED])) {
            return $color;
        }

        return $default;
    }


    /**
     * Returns IMAP metadata/annotations (GETMETADATA/GETANNOTATION)
     *
     * @param array List of metadata keys to read
     * @return array Metadata entry-value hash array on success, NULL on error
     */
    public function get_metadata($keys)
    {
        $metadata = rcube::get_instance()->get_storage()->get_metadata($this->name, (array)$keys);
        return $metadata[$this->name];
    }


    /**
     * Sets IMAP metadata/annotations (SETMETADATA/SETANNOTATION)
     *
     * @param array  $entries Entry-value array (use NULL value as NIL)
     * @return boolean True on success, False on failure
     */
    public function set_metadata($entries)
    {
        return $this->imap->set_metadata($this->name, $entries);
    }


    /**
     *
     */
    public function get_folder_info()
    {
        if (!isset($this->info))
            $this->info = $this->imap->folder_info($this->name);

        return $this->info;
    }

    /**
     * Make IMAP folder data available for this folder
     */
    public function get_imap_data()
    {
        if (!isset($this->idata))
            $this->idata = $this->imap->folder_data($this->name);

        return $this->idata;
    }


    /**
     * Get IMAP ACL information for this folder
     *
     * @return string  Permissions as string
     */
    public function get_myrights()
    {
        $rights = $this->info['rights'];

        if (!is_array($rights))
            $rights = $this->imap->my_rights($this->name);

        return join('', (array)$rights);
    }


    /**
     * Check activation status of this folder
     *
     * @return boolean True if enabled, false if not
     */
    public function is_active()
    {
        return kolab_storage::folder_is_active($this->name);
    }

    /**
     * Change activation status of this folder
     *
     * @param boolean The desired subscription status: true = active, false = not active
     *
     * @return True on success, false on error
     */
    public function activate($active)
    {
        return $active ? kolab_storage::folder_activate($this->name) : kolab_storage::folder_deactivate($this->name);
    }

    /**
     * Check subscription status of this folder
     *
     * @return boolean True if subscribed, false if not
     */
    public function is_subscribed()
    {
        return kolab_storage::folder_is_subscribed($this->name);
    }

    /**
     * Change subscription status of this folder
     *
     * @param boolean The desired subscription status: true = subscribed, false = not subscribed
     *
     * @return True on success, false on error
     */
    public function subscribe($subscribed)
    {
        return $subscribed ? kolab_storage::folder_subscribe($this->name) : kolab_storage::folder_unsubscribe($this->name);
    }

}

