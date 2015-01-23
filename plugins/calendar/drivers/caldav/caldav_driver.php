<?php

/**
 * CalDAV driver for the Calendar plugin
 *
 * @author Daniel Morlock <daniel.morlock@awesome-it.de>
 *
 * Copyright (C) 2013, Awesome IT GbR <info@awesome-it.de>
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

require_once (dirname(__FILE__).'/../database/database_driver.php');
require_once (dirname(__FILE__).'/caldav_sync.php');
require_once (dirname(__FILE__).'/../../lib/encryption.php');

/**
 * TODO
 * - Database constraint: obj_id, obj_type must be unique.
 * - Postgresql, Sqlite scripts.
 *
 */

class caldav_driver extends database_driver
{
    const OBJ_TYPE_VCAL = "vcal";
    const OBJ_TYPE_VEVENT = "vevent";
    const OBJ_TYPE_VTODO = "vtodo";

    private $db_caldav_props = 'caldav_props';
    private $db_events = 'events';
    private $db_calendars = 'calendars';
    private $db_attachments = 'attachments';

    private $cal;
    private $rc;

    private $crypt_key;

    static private $debug = null;

    // features this backend supports
    public $alarms = true;
    public $attendees = true;
    public $freebusy = false;
    public $attachments = true;
    public $alarm_types = array('DISPLAY');


    private $sync_clients = array();

    // Min. time period to wait until sync check.
    private $sync_period = 10; // seconds

    /**
     * Default constructor
     */
    public function __construct($cal)
    {
        $this->cal = $cal;
        $this->rc = $cal->rc;

        $db = $this->rc->get_dbh();
        $this->db_caldav_props = $this->rc->config->get('db_table_caldav_props', $db->table_name($this->db_caldav_props));
        $this->db_events = $this->rc->config->get('db_table_events', $db->table_name($this->db_events));
        $this->db_calendars = $this->rc->config->get('db_table_calendars', $db->table_name($this->db_calendars));
        $this->db_attachments = $this->rc->config->get('db_table_attachments', $db->table_name($this->db_attachments));

        $this->crypt_key = $this->rc->config->get("calendar_crypt_key", "%E`c{2;<J2F^4_&._BxfQ<5Pf3qv!m{e");

        parent::__construct($cal);

        // Set debug state
        if(self::$debug === null)
            self::$debug = $this->rc->config->get('calendar_caldav_debug', False);

        $this->_init_sync_clients();
    }

    /**
     * Helper method to log debug msg if debug mode is enabled.
     */
    static public function debug_log($msg)
    {
        if(self::$debug === true)
            rcmail::console(__CLASS__.': '.$msg);
    }

    /**
     * Sets caldav properties.
     *
     * @param int $obj_id
     * @param int One of CALDAV_OBJ_TYPE_CAL, CALDAV_OBJ_TYPE_EVENT or CALDAV_OBJ_TYPE_TODO.
     * @param array List of caldav properties:
     *   url: Absolute calendar URL or relative event URL.
     *   tag: Calendar ctag or event etag.
     *  user: Authentication user in case of calendar obj.
     *  pass: Authentication password in case of calendar obj.
     *
     * @return True on success, false otherwise.
     */
    private function _set_caldav_props($obj_id, $obj_type, array $props)
    {
        $this->_remove_caldav_props($obj_id, $obj_type);

        $password = isset($props["pass"]) ? $props["pass"] : null;
        if ($password) {
            $e = new Encryption(MCRYPT_BlOWFISH, MCRYPT_MODE_CBC);
            $p = $e->encrypt($password, $this->crypt_key);
            $password = base64_encode($p);
        }

        $query = $this->rc->db->query(
            "INSERT INTO ".$this->db_caldav_props." (obj_id, obj_type, url, tag, user, pass) ".
            "VALUES (?, ?, ?, ?, ?, ?)",
            $obj_id,
            $obj_type,
            $props["url"],
            isset($props["tag"]) ? $props["tag"] : null,
            isset($props["user"]) ? $props["user"] : null,
            $password);

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Gets caldav properties.
     *
     * @param int $obj_id
     * @param int One of CALDAV_OBJ_TYPE_CAL, CALDAV_OBJ_TYPE_EVENT or CALDAV_OBJ_TYPE_TODO.
     * @return array List of caldav properties or false on error:
     *    url: Absolute calendar URL or relative event URL.
     *    tag: Calendar ctag or event etag.
     *   user: Authentication user in case of calendar obj.
     *   pass: Authentication password in case of calendar obj.
     * last_change: Read-only DateTime obj of the last change.
     */
    private function _get_caldav_props($obj_id, $obj_type)
    {
        $result = $this->rc->db->query(
            "SELECT * FROM ".$this->db_caldav_props." p ".
            "WHERE p.obj_type = ? AND p.obj_id = ? ", $obj_type, $obj_id);

        if ($result && ($prop = $this->rc->db->fetch_assoc($result)) !== false) {
            $password = isset($prop["pass"]) ? $prop["pass"] : null;
            if ($password) {
                $p = base64_decode($password);
                $e = new Encryption(MCRYPT_BlOWFISH, MCRYPT_MODE_CBC);
                $prop["pass"] = $e->decrypt($p, $this->crypt_key);
            }            
            return $prop;
        }

        return false;
    }

    /**
     * Gets caldav properties by url.
     *
     * @param string $obj_url
     * @param int One of CALDAV_OBJ_TYPE_CAL, CALDAV_OBJ_TYPE_EVENT or CALDAV_OBJ_TYPE_TODO.
     * @param int $obj_user (optional) user id
     * @return array List of caldav properties or false on error
     */
    private function _get_caldav_props_by_url($obj_url, $obj_type, $obj_user = null)
    {
        $user_q = isset($obj_user) ? " AND user_id = ?" : "";
        $result = $this->rc->db->query(
            "SELECT * FROM ".$this->db_calendars." c ".
            "LEFT OUTER JOIN ".$this->db_caldav_props. " p ".
            "ON (c.calendar_id = p.obj_id)".
            " WHERE url LIKE ? AND obj_type = ?".$user_q,
            $obj_url, $obj_type, $obj_user
        );

        if ($result && ($prop = $this->rc->db->fetch_assoc($result)) !== false) {
            $password = isset($prop["pass"]) ? $prop["pass"] : null;
            if ($password) {
                $p = base64_decode($password);
                $e = new Encryption(MCRYPT_BlOWFISH, MCRYPT_MODE_CBC);
                $prop["pass"] = $e->decrypt($p, $this->crypt_key);
            }            
            return $prop;
        }

        return false;
    }

    /**
     * Removes caldav properties.
     *
     * @param int $obj_id
     * @param int One of CALDAV_OBJ_TYPE_CAL, CALDAV_OBJ_TYPE_EVENT or CALDAV_OBJ_TYPE_TODO.
     * @return True on success, false otherwise.
     */
    private function _remove_caldav_props($obj_id, $obj_type)
    {
        $query = $this->rc->db->query(
            "DELETE FROM ".$this->db_caldav_props." ".
            "WHERE obj_type = ? AND obj_id = ? ", $obj_type, $obj_id);

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Determines whether the given calendar is in sync regarding
     * calendar's ctag and the configured sync period.
     *
     * @param int Calender id.
     * @return boolean True if calendar is in sync, true otherwise.
     */
    private function _is_synced($cal_id)
    {
        // Atomic sql: Check for exceeded sync period and update last_change.
        $query = $this->rc->db->query(
            "UPDATE ".$this->db_caldav_props." ".
            "SET last_change = CURRENT_TIMESTAMP ".
            "WHERE obj_id = ? AND obj_type = ? ".
            "AND last_change <= (CURRENT_TIMESTAMP - ?);",
        $cal_id, self::OBJ_TYPE_VCAL, $this->sync_period);

        if($query->rowCount() > 0)
        {
            $is_synced = $this->sync_clients[$cal_id]->is_synced();
            self::debug_log("Calendar \"$cal_id\" ".($is_synced ? "is in sync" : "needs update").".");
            return $is_synced;
        }
        else
        {
            self::debug_log("Sync period active: Assuming calendar \"$cal_id\" to be in sync.");
            return true;
        }
    }
    
    
     /**
     * Expand all "%p" occurrences in 'pass' element of calendar object 
     * properties array with RC (imap) password. 
     * Other elements are left untouched.
     * 
     * @param array List of caldav properties
     *    url: Absolute calendar URL or relative event URL.
     *    tag: Calendar ctag or event etag.
     *    user: Authentication user in case of calendar obj.
     *    pass: Authentication password in case of calendar obj.
     *    last_change: Read-only DateTime obj of the last change.
     * 
     * @return array List of caldav properties, with expanded 'pass' element. Original array is modified too.
     *    url: Absolute calendar URL or relative event URL.
     *    tag: Calendar ctag or event etag.
     *    user: Authentication user in case of calendar obj.
     *    pass: Authentication password in case of calendar obj.
     *    last_change: Read-only DateTime obj of the last change.
     *      
     */
    private function _expand_pass(& $props)
    {
        if ($props !== FALSE) {
            if (isset($props['pass'])){
                $props['pass'] = str_replace('%p', $this->rc->get_user_password(), $props['pass']);
            }
            return $props; 
        }    
        return FALSE;        
    }
    
    /**
     * Get a list of available calendars from this source
     *
     * @param bool $active Return only active calendars
     * @param bool $personal Return only personal calendars
     *
     * @return array List of calendars
     */
    public function list_calendars($active = false, $personal = false)
    {
        // Read calendars from database and remove those without iCAL props.
        $calendars = array();
        foreach(parent::list_calendars($active, $personal) as $id => $cal)
        {
            if($this->_get_caldav_props($id, self::OBJ_TYPE_VCAL) !== false)
                $calendars[$id] = $cal;
        }

        return $calendars;
    }

    /**
     * Initializes calendar sync clients.
     *
     * @param array $cal_ids Optional list of calendar ids. If empty, caldav_driver::list_calendars()
     *              will be used to retrieve a list of calendars.
     */
    private function _init_sync_clients($cal_ids = array())
    {
        if(sizeof($cal_ids) == 0) $cal_ids = array_keys($this->list_calendars());
        foreach($cal_ids as $cal_id)
        {
            $props = $this->_get_caldav_props($cal_id, self::OBJ_TYPE_VCAL);
            if($props !== false) {
                $this->_expand_pass($props);
                self::debug_log("Initialize sync client for calendar ".$cal_id);
                $this->sync_clients[$cal_id] = new caldav_sync($cal_id, $props);
            }
        }
    }

    /**
     * Auto discover calenders available to the user on the caldav server
     * @param array $props
     *    url: Absolute URL to calendar server
     *    user: Username
     *    pass: Password
     * @return array
     *    name: Calendar display name
     *    href: Absolute calendar URL
     */
    private function _autodiscover_calendars($props)
    {
        $calendars = array();
        $current_user_principal = array('{DAV:}current-user-principal');
        $calendar_home_set = array('{urn:ietf:params:xml:ns:caldav}calendar-home-set');
        $cal_attribs = array('{DAV:}resourcetype', '{DAV:}displayname');

        require_once ($this->cal->home.'/lib/caldav-client.php');
        $caldav = new caldav_client($props["url"], $props["user"], $props["pass"]);

        $tokens = parse_url($props["url"]);
        $base_uri = $tokens['scheme']."://".$tokens['host'].($tokens['port'] ? ":".$tokens['port'] : null);
        $caldav_url = $props["url"];
        $response = $caldav->prop_find($caldav_url, array_merge($current_user_principal,$cal_attribs), 0);
        if (!$response) {
            self::debug_log("Resource \"$caldav_url\" has no collections, maybe an .ics file?");
            array_push($calendars, array(
//              'name' => $props['name'],
                'name' => preg_replace('#\.ics$#', '', end(explode('/', $tokens['path']))),
                'href' => $caldav_url,
            ));
            return $calendars;
        }
        else if (array_key_exists ('{DAV:}resourcetype', $response) &&
            $response['{DAV:}resourcetype'] instanceof Sabre\DAV\Property\ResourceType &&
            in_array('{urn:ietf:params:xml:ns:caldav}calendar',
                     $response['{DAV:}resourcetype']->getValue())) {

            $name = '';
            if (array_key_exists ('{DAV:}displayname', $response)) {
                $name = $response['{DAV:}displayname'];
            }

            array_push($calendars, array(
                'name' => $name,
                'href' => $caldav_url,
            ));
            return $calendars;
            // directly return given url as it is a calendar
        }
        // probe further for principal url and user home set
        $caldav_url = $base_uri . $response[$current_user_principal[0]];
        $response = $caldav->prop_find($caldav_url, $calendar_home_set, 0);
        if (!$response) {
            self::debug_log("Resource \"$caldav_url\" contains no calendars.");
            return $calendars;
        }
        $caldav_url = $base_uri . $response[$calendar_home_set[0]];
        $response = $caldav->prop_find($caldav_url, $cal_attribs, 1);
        foreach($response as $collection => $attribs)
        {
            $found = false;
            $name = '';
            foreach($attribs as $key => $value)
            {
                if ($key == '{DAV:}resourcetype' && is_object($value)) {
                    if ($value instanceof Sabre\DAV\Property\ResourceType) {
                        $values = $value->getValue();
                        if (in_array('{urn:ietf:params:xml:ns:caldav}calendar', $values))
                            $found = true;
                    }
                }
                else if ($key == '{DAV:}displayname') {
                    $name = $value;
                }
            }
            if ($found) {
                array_push($calendars, array(
                    'name' => $name,
                    'href' => $base_uri.$collection,
                ));
            }
        }

        return $calendars;
    }

    /**
     * Encodes directory- and filenames using rawurlencode().
     *
     * @see http://stackoverflow.com/questions/7973790/urlencode-only-the-directory-and-file-names-of-a-url
     * @param string Unencoded URL to be encoded.
     * @return Encoded URL.
     */
    private static function _encode_url($url)
    {
        // Don't encode if "%" is already used.
        if(strstr($url, "%") === false)
        {
            return preg_replace_callback('#://([^/]+)/([^?]+)#', function ($matches) {
                return '://' . $matches[1] . '/' . join('/', array_map('rawurlencode', explode('/', $matches[2])));
            }, $url);
        }
        else return $url;
    }

    /**
     * Add default (pre-installation provisioned) calendar.
     *
     * @param array $props
     *    caldav_url: Absolute URL to calendar server collection
     *    caldav_user: Username
     *    caldav_pass: Password
     *    color: Events color
     *    showAlarms:  
     * @return bool false on creation error, true otherwise
     *    
     */
    public function insert_default_calendar($props) {
        return $this->create_calendar($props);
    }

    /**
     * Callback function to produce driver-specific calendar create/edit form
     *
     * @param string Request action 'form-edit|form-new'
     * @param array  Calendar properties (e.g. id, color)
     * @param array  Edit form fields
     *
     * @return string HTML content of the form
     */
    public function calendar_form($action, $calendar, $formfields)
    {
        $cal_id = $calendar["id"];
        $props = $this->_get_caldav_props($cal_id, self::OBJ_TYPE_VCAL);

        $input_caldav_url = new html_inputfield( array(
            "name" => "caldav_url",
            "id" => "caldav_url",
            "size" => 20
        ));

        $formfields["caldav_url"] = array(
            "label" => $this->cal->gettext("caldavurl"),
            "value" => $input_caldav_url->show($props["url"]),
            "id" => "caldav_url",
        );

        $input_caldav_user = new html_inputfield( array(
            "name" => "caldav_user",
            "id" => "caldav_user",
            "size" => 20
        ));

        $formfields["caldav_user"] = array(
            "label" => $this->cal->gettext("username"),
            "value" => $input_caldav_user->show($props["user"]),
            "id" => "caldav_user",
        );

        $input_caldav_pass = new html_passwordfield( array(
            "name" => "caldav_pass",
            "id" => "caldav_pass",
            "size" => 20
        ));

        $formfields["caldav_pass"] = array(
            "label" => $this->cal->gettext("password"),
            "value" => $input_caldav_pass->show(null), // Don't send plain text password to GUI
            "id" => "caldav_pass",
        );

        return parent::calendar_form($action, $calendar, $formfields);
    }

    /**
     * Extracts caldav properties and creates calendar.
     *
     * @see database_driver::create_calendar()
     */
    public function create_calendar($prop)
    {
        $result = false;
        $props = $prop;
        $props['url'] = self::_encode_url($prop["caldav_url"]);
        $props['user'] = $prop["caldav_user"];
        $props['pass'] = $prop["caldav_pass"];
        if(!isset($props['color'])) $props['color'] = 'cc0000';
        $pwd_expanded_props = $props;
        $this->_expand_pass($pwd_expanded_props);
        $calendars = $this->_autodiscover_calendars($pwd_expanded_props);
        $cal_ids = array();

        if(sizeof($calendars) > 0)
        {
            $result = true;
            foreach ($calendars as $calendar)
            {
                // skip already existent calendars
                if (is_array($this->_get_caldav_props_by_url($calendar['href'],
                    self::OBJ_TYPE_VCAL, $this->rc->user->ID))) continue;

                $props['url'] = self::_encode_url($calendar['href']);
                $props['name'] = $calendar['name'];
                if (($obj_id = parent::create_calendar($props)) !== false) {
                    $result = $result && $this->_set_caldav_props($obj_id, self::OBJ_TYPE_VCAL, $props);
                    array_push($cal_ids, $obj_id);
                }
            }
        }

        // return if no new calendars where created
        if (empty($cal_ids)) return $result;

        // Re-read calendars to internal buffer.
        $this->_read_calendars();

        // Initial sync of newly created calendars.
        $this->_init_sync_clients($cal_ids);
        foreach($cal_ids as $cal_id){
            $this->_sync_calendar($cal_id);
        }

        return $result;
    }

    /**
     * Extracts caldav properties and updates calendar.
     *
     * @see database_driver::edit_calendar()
     */
    public function edit_calendar($prop)
    {
        if (parent::edit_calendar($prop) !== false)
        {
            // Don't change the password if not specified
            if(!$prop["caldav_pass"]) {
                $prev_prop = $this->_get_caldav_props($prop["id"], self::OBJ_TYPE_VCAL);
                if($prev_prop) $prop["caldav_pass"] = $prev_prop["pass"];
            }

            return $this->_set_caldav_props($prop["id"], self::OBJ_TYPE_VCAL, array(
                "url" => self::_encode_url($prop["caldav_url"]),
                "user" => $prop["caldav_user"],
                "pass" => $prop["caldav_pass"]
            ));
        }

        return false;
    }

    /**
     * Deletes caldav properties and the appropriate calendar.
     *
     * @see database_driver::remove_calendar()
     */
    public function remove_calendar($prop)
    {
        // Fetch caldav properties from related events.
        $event_props = $this->rc->db->query("SELECT c.obj_id as id FROM ".$this->db_events." e, ".$this->db_caldav_props." c ".
            "WHERE e.event_id = c.obj_id AND e.calendar_id=?", $prop['id']);

        if (parent::remove_calendar($prop))
        {
            while($event_props && ($arr = $this->rc->db->fetch_assoc($event_props))){
                $this->_remove_caldav_props($arr["id"], self::OBJ_TYPE_VEVENT);
            }

            $this->_remove_caldav_props($prop["id"], self::OBJ_TYPE_VCAL);
            self::debug_log("Removed calendar \"".$prop["id"]."\" with ".$event_props->rowCount()." events.");
            return true;
        }

        return false;
    }

    /**
     * Performs caldav updates on given events.
     *
     * @param array Caldav and event properties to update. See caldav_sync::get_updates().
     * @return array List of event ids.
     */
    private function _perform_updates($updates)
    {
        $event_ids = array();

        $num_created = 0;
        $num_updated = 0;

        foreach($updates as $update)
        {
            // local event -> update event
            if(isset($update["local_event"]))
            {
                // let edit_event() do all the magic
                if(parent::edit_event($update["remote_event"] + (array)$update["local_event"]))
                {
                    $event_id = $update["local_event"]["id"];
                    self::debug_log("Updated event \"$event_id\".");

                    $props = array(
                        "url" => $update["url"],
                        "tag" => $update["etag"]
                    );

                    $this->_set_caldav_props($event_id, self::OBJ_TYPE_VEVENT, $props);
                    array_push($event_ids, $event_id);
                    $num_updated ++;
                }
                else
                {
                    self::debug_log("Could not perform event update: ".print_r($update, true));
                }
            }

            // no local event -> create event
            else
            {
                $event_id = parent::new_event($update["remote_event"]);
                if($event_id)
                {
                    self::debug_log("Created event \"$event_id\".");

                    $props = array(
                        "url" => $update["url"],
                        "tag" => $update["etag"]
                    );

                    $this->_set_caldav_props($event_id, self::OBJ_TYPE_VEVENT, $props);
                    array_push($event_ids, $event_id);
                    $num_created ++;
                }
                else
                {
                    self::debug_log("Could not perform event creation: ".print_r($update, true));
                }
            }
        }

        self::debug_log("Created $num_created new events, updated $num_updated event.");
        return $event_ids;
    }

    /**
     * Return all events from the given calendar.
     *
     * @param int Calendar id.
     * @return array
     */
    private function _load_all_events($cal_id)
    {
        // This is kind of ugly but a way to get _all_ events without touching the
        // database driver.

        // Get the event with the maximum end time.
        $result = $this->rc->db->query(
            "SELECT MAX(e.end) as end FROM ".$this->db_events." e ".
            "WHERE e.calendar_id = ? ", $cal_id);

        if($result && ($arr = $this->rc->db->fetch_assoc($result))) {
            $end = new DateTime($arr["end"]);
            return parent::load_events(0, $end->getTimestamp(), null, array($cal_id));
        }
        else return array();
    }

    /**
     * Synchronizes events of given calendar.
     *
     * @param int Calendar id.
     */
    private function _sync_calendar($cal_id)
    {
        self::debug_log("Syncing calendar id \"$cal_id\".");

        $cal_sync = $this->sync_clients[$cal_id];
        $events = array();
        $caldav_props = array();

        // Ignore recurrence events and read caldav props
        foreach($this->_load_all_events($cal_id) as $event)
        {
            if($event["recurrence_id"] == 0)
            {
                array_push($events, $event);
                array_push($caldav_props,
                    $this->_get_caldav_props($event["id"], self::OBJ_TYPE_VEVENT));
            }
        }

        $updates = $cal_sync->get_updates($events, $caldav_props);
        if($updates)
        {
            list($updates, $synced_event_ids) = $updates;
            $updated_event_ids = $this->_perform_updates($updates);

            // Delete events that are not in sync or updated.
            foreach($events as $event)
            {
                if(array_search($event["id"], $updated_event_ids) === false && // No updated event
                    array_search($event["id"], $synced_event_ids) === false) // No in-sync event
                {
                    // Assume: Event not in sync and not updated, so delete!
                    parent::remove_event($event, true);
                    self::debug_log("Remove event \"".$event["id"]."\".");
                }
            }
           
            // Update calendar ctag ...
            $cal_props = $this->_get_caldav_props($cal_id, self::OBJ_TYPE_VCAL);
            $cal_props["tag"] = $cal_sync->get_ctag();
            $this->_set_caldav_props($cal_id, self::OBJ_TYPE_VCAL, $cal_props);            
        }

        self::debug_log("Successfully synced calendar id \"$cal_id\".");
    }


    /**
     * Synchronizes events and loads them.
     *
     * @see database_driver::load_events()
     */
    public function load_events($start, $end, $query = null, $cal_ids = null, $virtual = 1, $modifiedsince = null)
    {
        foreach($this->sync_clients as $cal_id => $cal_sync) {
            if(!$this->_is_synced($cal_id))
                $this->_sync_calendar($cal_id);
        }

        return parent::load_events($start, $end, $query, $cal_ids, $virtual, $modifiedsince);
    }

    /**
     * Add a single event to the database and to the caldav server.
     *
     * @param array Hash array with event properties
     * @return int Event id on success, false otherwise.
     * @see database_driver::new_event()
     */
    public function new_event($event)
    {
        $event_id = parent::new_event($event);
        $cal_id = $event["calendar"];
        if($event_id !== false)
        {
            $sync_client = $this->sync_clients[$cal_id];
            $props = $sync_client->create_event($event);

            if($props === false)
            {
                self::debug_log("Unkown error while creating caldav event, undo creating local event \"$event_id\"!");
                parent::remove_event($event);
                return false;
            }
            else
            {
                self::debug_log("Successfully pushed event \"$event_id\" to caldav server.");
                $this->_set_caldav_props($event_id, self::OBJ_TYPE_VEVENT, $props);

                // Trigger calendar sync to update ctags and etags.
                $this->_sync_calendar($cal_id);

                return $event_id;
            }
        }

        return false;
    }

    /**
     * Update the event entry with the given data and sync with caldav server.
     *
     * @param array Hash array with event properties
     * @param array Internal use only, filled with non-modified event if this is second try after a calendar sync was enforced first.
     * @see calendar_driver::edit_event()
     */
    public function edit_event($event, $old_event = null)
    {
        $sync_enforced = ($old_event != null);
        $event_id = (int)$event["id"];
        $cal_id = $event["calendar"];

        if($old_event == null)
            $old_event = parent::get_event($event);

        if(parent::edit_event($event))
        {
            // Get updates event and push to caldav.
            $event = parent::get_event(array("id" => $event_id));

            $sync_client = $this->sync_clients[$cal_id];
            $props = $this->_get_caldav_props($event_id, self::OBJ_TYPE_VEVENT);
            $success = $sync_client->update_event($event, $props);

            if($success === true)
            {
                self::debug_log("Successfully updated event \"$event_id\".");

                // Trigger calendar sync to update ctags and etags.
                $this->_sync_calendar($cal_id);

                return true;
            }
            else if($success < 0 && $sync_enforced == false)
            {
                self::debug_log("Event \"$event_id\", tag \"".$props["tag"]."\" not up to date, will update calendar first ...");
                $this->_sync_calendar($cal_id);

                return $this->edit_event($event, $old_event); // Re-try after re-sync
            }
            else
            {
                self::debug_log("Unkown error while updating caldav event, undo updating local event \"$event_id\"!");
                parent::edit_event($old_event);

                return false;
            }
        }

        return false;
    }

    /**
     * Remove a single event from the database and from caldav server.
     *
     * @param array Hash array with event properties
     * @param boolean Remove record irreversible
     *
     * @see calendar_driver::remove_event()
     */
    public function remove_event($event, $force = true)
    {
        $event_id = (int)$event["id"];
        $cal_id = (int)$event["calendar"];
        $props = $this->_get_caldav_props($event_id, self::OBJ_TYPE_VEVENT);
        $event = parent::get_event($event);

        if(parent::remove_event($event, $force))
        {
            $sync_client = $this->sync_clients[$cal_id];
            $success = $sync_client->remove_event($props);

            if($success === true)
            {
                self::debug_log("Successfully removed event \"$event_id\".");

                // Trigger calendar sync to update ctags and etags.
                $this->_sync_calendar($cal_id);

                return true;
            }
            else
            {
                self::debug_log("Unkown error while removing caldav event, undo removing local event \"$event_id\"!");
                $new_event_id = parent::new_event($event);
                $new_props = $props;
                $new_props["obj_id"] = $new_event_id;

                $this->_remove_caldav_props($event_id, self::OBJ_TYPE_VEVENT);
                $this->_set_caldav_props($event_id, self::OBJ_TYPE_VEVENT, $new_props);

                return false;
            }
        }

        return false; // Unkown error.
    }
}
