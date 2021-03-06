<?php

/**
 * Kolab Authentication
 *
 * @version @package_version@
 * @author Aleksander Machniak <machniak@kolabsys.com>
 *
 * Copyright (C) 2011-2013, Kolab Systems AG <contact@kolabsys.com>
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

/**
 * Wrapper class for rcube_ldap_generic
 */
class kolab_auth_ldap extends rcube_ldap_generic
{
    private $conf     = array();
    private $fieldmap = array();


    function __construct($p)
    {
        $rcmail = rcube::get_instance();

        $this->conf = $p;
        $this->conf['kolab_auth_user_displayname'] = $rcmail->config->get('kolab_auth_user_displayname', '{name}');

        $this->fieldmap = $p['fieldmap'];
        $this->fieldmap['uid'] = 'uid';

        $p['attributes'] = array_values($this->fieldmap);
        $p['debug']      = (bool) $rcmail->config->get('ldap_debug');

        // Connect to the server (with bind)
        parent::__construct($p);
        $this->_connect();

        $rcmail->add_shutdown_function(array($this, 'close'));
    }

    /**
    * Establish a connection to the LDAP server
    */
    private function _connect()
    {
        // try to connect + bind for every host configured
        // with OpenLDAP 2.x ldap_connect() always succeeds but ldap_bind will fail if host isn't reachable
        // see http://www.php.net/manual/en/function.ldap-connect.php
        foreach ((array)$this->config['hosts'] as $host) {
            // skip host if connection failed
            if (!$this->connect($host)) {
                continue;
            }

            $bind_pass = $this->config['bind_pass'];
            $bind_user = $this->config['bind_user'];
            $bind_dn   = $this->config['bind_dn'];

            if (empty($bind_pass)) {
                $this->ready = true;
            }
            else {
                if (!empty($bind_dn)) {
                    $this->ready = $this->bind($bind_dn, $bind_pass);
                }
                else if (!empty($this->config['auth_cid'])) {
                    $this->ready = $this->sasl_bind($this->config['auth_cid'], $bind_pass, $bind_user);
                }
                else {
                    $this->ready = $this->sasl_bind($bind_user, $bind_pass);
                }
            }

            // connection established, we're done here
            if ($this->ready) {
                break;
            }

        }  // end foreach hosts

        if (!is_resource($this->conn)) {
            rcube::raise_error(array('code' => 100, 'type' => 'ldap',
                'file' => __FILE__, 'line' => __LINE__,
                'message' => "Could not connect to any LDAP server, last tried $host"), true);

            $this->ready = false;
        }

        return $this->ready;
    }

    /**
     * Fetches user data from LDAP addressbook
     */
    function get_user_record($user, $host)
    {
        $rcmail  = rcube::get_instance();
        $filter  = $rcmail->config->get('kolab_auth_filter');
        $filter  = $this->parse_vars($filter, $user, $host);
        $base_dn = $this->parse_vars($this->config['base_dn'], $user, $host);
        $scope   = $this->config['scope'];

        // @TODO: print error if filter is empty

        // get record
        if ($result = parent::search($base_dn, $filter, $scope, $this->attributes)) {
            if ($result->count() == 1) {
                $entries = $result->entries(true);
                $dn      = key($entries);
                $entry   = array_pop($entries);
                $entry   = $this->field_mapping($dn, $entry);

                return $entry;
            }
        }
    }

    /**
     * Fetches user data from LDAP addressbook
     */
    function get_user_groups($dn, $user, $host)
    {
        if (empty($dn) || empty($this->config['groups'])) {
            return array();
        }

        $base_dn     = $this->parse_vars($this->config['groups']['base_dn'], $user, $host);
        $name_attr   = $this->config['groups']['name_attr'] ? $this->config['groups']['name_attr'] : 'cn';
        $member_attr = $this->get_group_member_attr();
        $filter      = "(member=$dn)(uniqueMember=$dn)";

        if ($member_attr != 'member' && $member_attr != 'uniqueMember')
            $filter .= "($member_attr=$dn)";
        $filter = strtr("(|$filter)", array("\\" => "\\\\"));

        $result = parent::search($base_dn, $filter, 'sub', array('dn', $name_attr));

        if (!$result) {
            return array();
        }

        $groups = array();
        foreach ($result as $entry) {
            $dn    = $entry['dn'];
            $entry = rcube_ldap_generic::normalize_entry($entry);

            $groups[$dn] = $entry[$name_attr];
        }

        return $groups;
    }

    /**
     * Get a specific LDAP record
     *
     * @param string DN
     *
     * @return array Record data
     */
    function get_record($dn)
    {
        if (!$this->ready) {
            return;
        }

        if ($rec = $this->get_entry($dn)) {
            $rec = rcube_ldap_generic::normalize_entry($rec);
            $rec = $this->field_mapping($dn, $rec);
        }

        return $rec;
    }

    /**
     * Replace LDAP record data items
     *
     * @param string $dn    DN
     * @param array  $entry LDAP entry
     *
     * return bool True on success, False on failure
     */
    function replace($dn, $entry)
    {
        // fields mapping
        foreach ($this->fieldmap as $field => $attr) {
            if (array_key_exists($field, $entry)) {
                $entry[$attr] = $entry[$field];
                if ($attr != $field) {
                    unset($entry[$field]);
                }
            }
        }

        return $this->mod_replace($dn, $entry);
    }

    /**
     * Search records (simplified version of rcube_ldap::search)
     *
     * @param string  $fields   The field name or array of field names to search in
     * @param mixed   $value    Search value (or array of values when $fields is array)
     * @param int     $mode     Matching mode:
     *                          0 - partial (*abc*),
     *                          1 - strict (=),
     *                          2 - prefix (abc*)
     * @param array   $required List of fields that cannot be empty
     * @param int     $limit    Number of records
     * @param int     $count    Returns the number of records found
     *
     * @return array List or false on error
     */
    function dosearch($fields, $value, $mode=1, $required = array(), $limit = 0, &$count = 0)
    {
        if (empty($fields)) {
            return array();
        }

        $mode = intval($mode);

        // compose a full-text-search-like filter
        if (is_array($fields) && (count($fields) > 1 || $mode != 1)) {
            $filter = self::fulltext_search_filter($value, $fields, $mode);
        }
        // direct search
        else {
            $field = is_array($fields) ? $fields[0] : strval($fields);
            $filter = "($field=" . self::quote_string($value) . ")";
        }

        // add required (non empty) fields filter
        $req_filter = '';

        foreach ((array)$required as $field) {
            if (in_array($field, (array)$fields))  // required field is already in search filter
                continue;

            $attrs = (array) $this->fieldmap[$field];

            if (empty($attrs)) {
                $req_filter .= "($field=*)";
            }
            else {
                if (count($attrs) > 1)
                    $req_filter .= '(|';
                foreach ($attrs as $f)
                    $req_filter .= "($f=*)";
                if (count($attrs) > 1)
                    $req_filter .= ')';
            }
        }

        if (!empty($req_filter)) {
            $filter = '(&' . $req_filter . $filter . ')';
        }

        // avoid double-wildcard if $value is empty
        $filter = preg_replace('/\*+/', '*', $filter);

        // add general filter to query
        if (!empty($this->config['filter'])) {
            $filter = '(&(' . preg_replace('/^\(|\)$/', '', $this->config['filter']) . ')' . $filter . ')';
        }

        $base_dn = $this->parse_vars($this->config['base_dn']);
        $scope   = $this->config['scope'];
        $attrs   = array_values($this->fieldmap);
        $list    = array();

        if ($result = $this->search($base_dn, $filter, $scope, $attrs)) {
            $count = $result->count();
            $i = 0;
            foreach ($result as $entry) {
                if ($limit && $limit <= $i) {
                    break;
                }

                $dn        = $entry['dn'];
                $entry     = rcube_ldap_generic::normalize_entry($entry);
                $list[$dn] = $this->field_mapping($dn, $entry);
                $i++;
            }
        }

        return $list;
    }

    /**
     * Set filter used in search()
     */
    function set_filter($filter)
    {
        $this->config['filter'] = $filter;
    }

    /**
     * Maps LDAP attributes to defined fields
     */
    protected function field_mapping($dn, $entry)
    {
        $entry['dn'] = $dn;

        // fields mapping
        foreach ($this->fieldmap as $field => $attr) {
            // $entry might be indexed by lower-case attribute names
            $attr_lc = strtolower($attr);
            if (isset($entry[$attr_lc])) {
                $entry[$field] = $entry[$attr_lc];
            }
            else if (isset($entry[$attr])) {
                $entry[$field] = $entry[$attr];
            }
        }

        // compose display name according to config
        if (empty($this->fieldmap['displayname'])) {
            $entry['displayname'] = rcube_addressbook::compose_search_name(
                $entry,
                $entry['email'],
                $entry['name'],
                $this->conf['kolab_auth_user_displayname']
            );
        }

        return $entry;
    }

    /**
     * Detects group member attribute name
     */
    private function get_group_member_attr($object_classes = array())
    {
        if (empty($object_classes)) {
            $object_classes = $this->config['groups']['object_classes'];
        }
        if (!empty($object_classes)) {
            foreach ((array)$object_classes as $oc) {
                switch (strtolower($oc)) {
                    case 'group':
                    case 'groupofnames':
                    case 'kolabgroupofnames':
                        $member_attr = 'member';
                        break;

                    case 'groupofuniquenames':
                    case 'kolabgroupofuniquenames':
                        $member_attr = 'uniqueMember';
                        break;
                }
            }
        }

        if (!empty($member_attr)) {
            return $member_attr;
        }

        if (!empty($this->config['groups']['member_attr'])) {
            return $this->config['groups']['member_attr'];
        }

        return 'member';
    }

    /**
     * Prepares filter query for LDAP search
     */
    function parse_vars($str, $user = null, $host = null)
    {
        // When authenticating user $user is always set
        // if not set it means we use this LDAP object for other
        // purposes, e.g. kolab_delegation, then username with
        // correct domain is in a session
        if (!$user) {
            $user = $_SESSION['username'];
        }

        if (isset($this->icache[$user])) {
            list($user, $dc) = $this->icache[$user];
        }
        else {
            $orig_user = $user;
            $rcmail = rcube::get_instance();

            // get default domain
            if ($username_domain = $rcmail->config->get('username_domain')) {
                if ($host && is_array($username_domain) && isset($username_domain[$host])) {
                    $domain = rcube_utils::parse_host($username_domain[$host], $host);
                }
                else if (is_string($username_domain)) {
                    $domain = rcube_utils::parse_host($username_domain, $host);
                }
            }

            // realmed username (with domain)
            if (strpos($user, '@')) {
                list($usr, $dom) = explode('@', $user);

                // unrealm domain, user login can contain a domain alias
                if ($dom != $domain && ($dc = $this->find_domain($dom))) {
                    // @FIXME: we should replace domain in $user, I suppose
                }
            }
            else if ($domain) {
                $user .= '@' . $domain;
            }

            $this->icache[$orig_user] = array($user, $dc);
        }

        // replace variables in filter
        list($u, $d) = explode('@', $user);

        // hierarchal domain string
        if (empty($dc)) {
            $dc = 'dc=' . strtr($d, array('.' => ',dc='));
        }

        $replaces = array('%dc' => $dc, '%d' => $d, '%fu' => $user, '%u' => $u);

        $this->parse_replaces = $replaces;

        return strtr($str, $replaces);
    }

    /**
     * Find root domain for specified domain
     *
     * @param string $domain Domain name
     *
     * @return string Domain DN string
     */
    function find_domain($domain)
    {
        if (empty($domain) || empty($this->config['domain_base_dn']) || empty($this->config['domain_filter'])) {
            return null;
        }

        $base_dn   = $this->config['domain_base_dn'];
        $filter    = $this->config['domain_filter'];
        $name_attr = $this->config['domain_name_attribute'];

        if (empty($name_attr)) {
            $name_attr = 'associateddomain';
        }

        $filter = str_replace('%s', rcube_ldap_generic::quote_string($domain), $filter);
        $result = parent::search($base_dn, $filter, 'sub', array($name_attr, 'inetdomainbasedn'));

        if (!$result) {
            return null;
        }

        $entries  = $result->entries(true);
        $entry_dn = key($entries);
        $entry    = $entries[$entry_dn];

        if (is_array($entry)) {
            if (!empty($entry['inetdomainbasedn'])) {
                return $entry['inetdomainbasedn'];
            }

            $domain = is_array($entry[$name_attr]) ? $entry[$name_attr][0] : $entry[$name_attr];

            return $domain ? 'dc=' . implode(',dc=', explode('.', $domain)) : null;
        }
    }

    /**
     * Returns variables used for replacement in (last) parse_vars() call
     *
     * @return array Variable-value hash array
     */
    public function get_parse_vars()
    {
        return $this->parse_replaces;
    }

    /**
     * Register additional fields
     */
    public function extend_fieldmap($map)
    {
        foreach ((array)$map as $name => $attr) {
            if (!in_array($attr, $this->attributes)) {
                $this->attributes[]    = $attr;
                $this->fieldmap[$name] = $attr;
            }
        }
    }

    /**
     * HTML-safe DN string encoding
     *
     * @param string $str DN string
     *
     * @return string Encoded HTML identifier string
     */
    static function dn_encode($str)
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    /**
     * Decodes DN string encoded with _dn_encode()
     *
     * @param string $str Encoded HTML identifier string
     *
     * @return string DN string
     */
    static function dn_decode($str)
    {
        $str = str_pad(strtr($str, '-_', '+/'), strlen($str) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($str);
    }
}
