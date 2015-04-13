<?php

/**
 * CalDAV driver for the Calendar plugin
 *
 * @author Daniel Morlock <daniel.morlock@awesome-it.de>
 *
 * Copyright (C) Awesome IT GbR <info@awesome-it.de>
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

require_once (dirname(__FILE__).'/caldav_sync.php');
require_once (dirname(__FILE__).'/../../lib/encryption.php');


class caldav_driver extends calendar_driver
{
    const DB_DATE_FORMAT = 'Y-m-d H:i:s';

    // features this backend supports
    public $alarms = true;
    public $attendees = true;
    public $freebusy = false;
    public $attachments = true;
    public $alarm_types = array('DISPLAY');

    private $rc;
    private $cal;
    private $cache = array();
    private $calendars = array();
    private $calendar_ids = '';
    private $free_busy_map = array('free' => 0, 'busy' => 1, 'out-of-office' => 2, 'outofoffice' => 2, 'tentative' => 3);
    private $sensitivity_map = array('public' => 0, 'private' => 1, 'confidential' => 2);
    private $server_timezone;

    private $db_events = 'caldav_events';
    private $db_calendars = 'caldav_calendars';
    private $db_attachments = 'caldav_attachments';

    // Crypt key for CalDAV auth
    private $crypt_key;

    // Holds CalDAV sync clients
    private $sync_clients = array();

    // Min. time period to wait until CalDAV sync check.
    private $sync_period = 10; // seconds

    // Indicates debug mode for CalDAV
    static private $debug = null;

    /**
     * Helper method to log debug msg if debug mode is enabled.
     */
    static public function debug_log($msg)
    {
        if(self::$debug === true)
            rcmail::console(__CLASS__.': '.$msg);
    }

    /**
     * Helper method to log (if debug mode is enabled) and raise an user error.
     */
    private function _raise_error($msg)
    {
        self::debug_log($msg);
        $this->rc->output->show_message($msg, 'error');
    }

    /**
     * Default constructor
     */
    public function __construct($cal)
    {
        $this->cal = $cal;
        $this->rc = $cal->rc;
        $this->server_timezone = new DateTimeZone(date_default_timezone_get());

        // read database config
        $db = $this->rc->get_dbh();
        $this->db_events = $this->rc->config->get('db_table_caldav_events', $db->table_name($this->db_events));
        $this->db_calendars = $this->rc->config->get('db_table_caldav_calendars', $db->table_name($this->db_calendars));
        $this->db_attachments = $this->rc->config->get('db_table_caldav_attachments', $db->table_name($this->db_attachments));
        $this->crypt_key = $this->rc->config->get("calendar_crypt_key", "%E`c{2;<J2F^4_&._BxfQ<5Pf3qv!m{e");

        // Set debug state
        if(self::$debug === null)
            self::$debug = $this->rc->config->get('calendar_caldav_debug', False);

        $this->_read_calendars();
    }

    /**
     * Read available calendars for the current user and store them internally
     */
    protected function _read_calendars()
    {
        $hidden = array_filter(explode(',', $this->rc->config->get('hidden_caldav_calendars', '')));

        if (!empty($this->rc->user->ID)) {
            $calendar_ids = array();
            $result = $this->rc->db->query("SELECT *, calendar_id AS id
                FROM " . $this->db_calendars . "
                WHERE user_id=?
                ORDER BY name",
                $this->rc->user->ID
            );
            while ($result && ($arr = $this->rc->db->fetch_assoc($result))) {
                $arr['showalarms'] = intval($arr['showalarms']);
                $arr['active']     = !in_array($arr['id'], $hidden);
                $arr['name']       = html::quote($arr['name']);
                $arr['listname']   = html::quote($arr['name']);
                $arr['caldav_pass']   = $this->_decrypt_pass($arr['caldav_pass']);

                $cal_id = $arr['id'];

                $this->calendars[$cal_id] = $arr;
                $calendar_ids[] = $this->rc->db->quote($cal_id);

                // Initialize sync client for this calendar
                $this->sync_clients[$cal_id] = new caldav_sync($arr);
            }
            $this->calendar_ids = join(',', $calendar_ids);
        }
    }

    /**
     * Get a list of available calendars from this source
     *
     * @param bool $active   Return only active calendars
     * @param bool $personal Return only personal calendars
     *
     * @return array List of calendars
     */
    public function list_calendars($active = false, $personal = false)
    {
        // attempt to create a default calendar for this user
        if (empty($this->calendars)) {
            if ($this->create_calendar(array('name' => 'Default', 'color' => 'cc0000', 'showalarms' => true)))
                $this->_read_calendars();
        }

        $calendars = $this->calendars;

        // filter active calendars
        if ($active) {
            foreach ($calendars as $idx => $cal) {
                if (!$cal['active']) {
                    unset($calendars[$idx]);
                }
            }
        }

        // 'personal' is unsupported in this driver

        return $calendars;
    }

    /**
     * Extracts CalDAV calendar.
     *
     * @see database_driver::create_calendar()
     */
    public function create_calendar($cal)
    {
        $result = false;
        $cal['caldav_url'] = self::_encode_url($cal["caldav_url"]);
        if(!isset($cal['color'])) $cal['color'] = 'cc0000';

        $calendars = $this->_autodiscover_calendars($this->_expand_pass($cal));
        $cal_ids = array();

        if($calendars)
        {
            $result = true;
            foreach ($calendars as $calendar)
            {
                // Skip already existent calendars
                $result = $this->rc->db->query("SELECT * FROM ".$this->db_calendars." WHERE caldav_url LIKE ?", $calendar['href']);
                if($this->rc->db->affected_rows($result)) continue;

                $cal['caldav_url'] = self::_encode_url($calendar['href']);

                // Respect $props['name'] if only a single calendar was found e.g. no auto-discovery.
                if(sizeof($calendars) > 1 || !isset($cal['name'])  || $cal['name'] == "")
                    $cal['name'] = $calendar['name'];

                if (($obj_id = $this->_db_create_calendar($cal)) !== false) {
                    array_push($cal_ids, $obj_id);
                } else $result = false;
            }
        }

        // Sync newly created calendars
        if($cal_ids) {

            // Re-read calendars to internal buffer.
            $this->_read_calendars();

            // Initial sync of newly created calendars.
            foreach ($cal_ids as $cal_id) {
                $this->_sync_calendar($cal_id);
            }
        }

        return $result;
    }

    /**
     * Create a new calendar assigned to the current user
     *
     * @param array Hash array with calendar properties
     *        name: Calendar name
     *       color: The color of the calendar
     *  caldav_url: CalDAV calendar URL
     *  caldav_tag: CalDAV calendar ctag
     * caldav_user: CalDAV authentication user
     * caldav_pass: CalDAV authentication password
     *
     * @return mixed ID of the calendar on success, False on error
     */
    private function _db_create_calendar($prop)
    {
        $result = $this->rc->db->query(
            "INSERT INTO " . $this->db_calendars . "
       (user_id, name, color, showalarms, caldav_url, caldav_tag, caldav_user, caldav_pass)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            $this->rc->user->ID,
            $prop['name'],
            $prop['color'],
            $prop['showalarms']?1:0,
            $prop['caldav_url'],
            isset($props["caldav_tag"]) ? $props["caldav_tag"] : null,
            isset($props["caldav_user"]) ? $props["caldav_user"] : null,
            isset($props["caldav_pass"]) ? $this->_encrypt_pass($props["caldav_pass"]) : null
        );

        if ($result)
            return $this->rc->db->insert_id($this->db_calendars);

        return false;
    }

    /**
     * Update properties of an existing calendar
     *
     * @see calendar_driver::edit_calendar()
     */
    public function edit_calendar($cal)
    {
        $query = $this->rc->db->query("UPDATE " . $this->db_calendars . "
            SET   name=?, color=?, showalarms=?, caldav_url=?, caldav_tag=?, caldav_user=?
            WHERE calendar_id=?
            AND   user_id=?",
            $cal['name'],
            $cal['color'],
            $cal['showalarms']?1:0,
            $cal['caldav_url'],
            isset($cal["caldav_tag"]) ? $cal["caldav_tag"] : null,
            isset($cal["caldav_user"]) ? $cal["caldav_user"] : null,
            $cal['id'],
            $this->rc->user->ID
        );

        // Change password if specified
        if (isset($cal["caldav_pass"])) {
            $query = $this->rc->db->query("UPDATE " . $this->db_calendars . "
            SET   caldav_pass=?
            WHERE calendar_id=?
            AND   user_id=?",
                $this->_encrypt_pass($cal['caldav_pass']),
                $cal['id'],
                $this->rc->user->ID
            );
        }

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Set active/subscribed state of a calendar
     * Save a list of hidden calendars in user prefs
     *
     * @see calendar_driver::subscribe_calendar()
     */
    public function subscribe_calendar($prop)
    {
        $hidden = array_flip(explode(',', $this->rc->config->get('hidden_caldav_calendars', '')));

        if ($prop['active'])
            unset($hidden[$prop['id']]);
        else
            $hidden[$prop['id']] = 1;

        return $this->rc->user->save_prefs(array('hidden_caldav_calendars' => join(',', array_keys($hidden))));
    }

    /**
     * Delete the given calendar with all its contents
     *
     * @see calendar_driver::delete_calendar()
     */
    public function delete_calendar($prop)
    {
        if (!$this->calendars[$prop['id']])
            return false;

        // events and attachments will be deleted by foreign key cascade

        $query = $this->rc->db->query(
            "DELETE FROM " . $this->db_calendars . " WHERE calendar_id=?",
            $prop['id']
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Search for shared or otherwise not listed calendars the user has access
     *
     * @param string Search string
     * @param string Section/source to search
     * @return array List of calendars
     */
    public function search_calendars($query, $source)
    {
        // not implemented
        return array();
    }

    /**
     * Add a single event to the database
     *
     * @param array Hash array with event properties
     * @see calendar_driver::new_event()
     * @return bool|mixed
     */
    public function new_event($event)
    {
        if (!$this->validate($event))
            return false;

        if (!empty($this->calendars)) {
            if ($event['calendar'] && !$this->calendars[$event['calendar']])
                return false;
            if (!$event['calendar'])
                $event['calendar'] = reset(array_keys($this->calendars));

            $event = $this->_save_preprocess($event);
            $sync_client = $this->sync_clients[$event["calendar"]];

            // Only push event if caldav_tag is not set to avoid pushing it twice
            if(isset($event["caldav_tag"]) || ($event = $sync_client->create_event($event)) !== false) {
                $this->rc->db->query(sprintf(
                    "INSERT INTO " . $this->db_events . " (
                        calendar_id, created, changed, uid, %s, %s, all_day, recurrence, title, description, location,
                        categories, url, free_busy, priority, sensitivity, status, attendees, alarms, notifyat,
                        caldav_url, caldav_tag
                    )
                    VALUES (?, %s, %s, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",

                    $this->rc->db->quote_identifier('start'),
                    $this->rc->db->quote_identifier('end'),
                    $this->rc->db->now(),
                    $this->rc->db->now()),

                    $event['calendar'],
                    strval($event['uid']),
                    $event['start']->format(self::DB_DATE_FORMAT),
                    $event['end']->format(self::DB_DATE_FORMAT),
                    intval($event['all_day']),
                    $event['_recurrence'],
                    strval($event['title']),
                    strval($event['description']),
                    strval($event['location']),
                    join(',', (array)$event['categories']),
                    strval($event['url']),
                    intval($event['free_busy']),
                    intval($event['priority']),
                    intval($event['sensitivity']),
                    strval($event['status']),
                    $event['attendees'],
                    $event['alarms'],
                    $event['notifyat'],
                    $event['caldav_url'],
                    $event['caldav_tag']
                );

                $event_id = $this->rc->db->insert_id($this->db_events);

                if ($event_id) {
                    $event['id'] = $event_id;

                    // add attachments
                    if (!empty($event['attachments'])) {
                        foreach ($event['attachments'] as $attachment) {
                            $this->add_attachment($attachment, $event_id);
                            unset($attachment);
                        }
                    }

                    $this->_update_recurring($event);
                }

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
     * @see caldav_driver::_db_edit_event()
     * @return bool
     */
    public function edit_event($event, $old_event = null)
    {
        $sync_enforced = ($old_event != null);
        $event_id = (int)$event["id"];
        $cal_id = $event["calendar"];

        if($old_event == null)
            $old_event = $this->get_event($event);

        if($this->_db_edit_event($event))
        {
            // Re-load updated event and push to caldav.
            $event = $this->get_event(array("id" => $event_id));

            $sync_client = $this->sync_clients[$cal_id];
            $success = $sync_client->update_event($event);

            if($success === true)
            {
                self::debug_log("Successfully updated event \"$event_id\".");

                // Trigger calendar sync to update ctags and etags.
                $this->_sync_calendar($cal_id);

                return true;
            }
            else if($success < 0 && $sync_enforced == false)
            {
                self::debug_log("Event \"$event_id\", tag \"".$event["caldav_tag"]."\" not up to date, will update calendar first ...");
                $this->_sync_calendar($cal_id);

                return $this->edit_event($event, $old_event); // Re-try after re-sync
            }
            else
            {
                $this->_db_edit_event($old_event);
                $this->_raise_error("Could not update event: Unexpected CalDAV error.");

                return false;
            }
        }

        return false;
    }

    /**
     * Update an event entry with the given data
     *
     * @param array Hash array with event properties
     * @see calendar_driver::edit_event()
     * @return bool
     */
    private function _db_edit_event($event)
    {
        if (!empty($this->calendars)) {
            $update_master = false;
            $update_recurring = true;
            $old = $this->get_event($event);

            // increment sequence number
            if ($old['sequence'] && empty($event['sequence']))
                $event['sequence'] = max($event['sequence'], $old['sequence']+1);

            // modify a recurring event, check submitted savemode to do the right things
            if ($old['recurrence'] || $old['recurrence_id']) {
                $master = $old['recurrence_id'] ? $this->get_event(array('id' => $old['recurrence_id'])) : $old;

                // keep saved exceptions (not submitted by the client)
                if ($old['recurrence']['EXDATE'])
                    $event['recurrence']['EXDATE'] = $old['recurrence']['EXDATE'];

                switch ($event['_savemode']) {
                    case 'new':
                        $event['uid'] = $this->cal->generate_uid();
                        return $this->new_event($event);

                    case 'current':
                        // add exception to master event
                        $master['recurrence']['EXDATE'][] = $old['start'];
                        $update_master = true;

                        // just update this occurence (decouple from master)
                        $update_recurring = false;
                        $event['recurrence_id'] = 0;
                        $event['recurrence'] = array();
                        break;

                    case 'future':
                        if ($master['id'] != $event['id']) {
                            // set until-date on master event, then save this instance as new recurring event
                            $master['recurrence']['UNTIL'] = clone $event['start'];
                            $master['recurrence']['UNTIL']->sub(new DateInterval('P1D'));
                            unset($master['recurrence']['COUNT']);
                            $update_master = true;

                            // if recurrence COUNT, update value to the correct number of future occurences
                            if ($event['recurrence']['COUNT']) {
                                $fromdate = clone $event['start'];
                                $fromdate->setTimezone($this->server_timezone);
                                $sqlresult = $this->rc->db->query(sprintf(
                                    "SELECT event_id FROM " . $this->db_events . "
                   WHERE calendar_id IN (%s)
                   AND %s >= ?
                   AND recurrence_id=?",
                                    $this->calendar_ids,
                                    $this->rc->db->quote_identifier('start')
                                ),
                                    $fromdate->format(self::DB_DATE_FORMAT),
                                    $master['id']);
                                if ($count = $this->rc->db->num_rows($sqlresult))
                                    $event['recurrence']['COUNT'] = $count;
                            }

                            $update_recurring = true;
                            $event['recurrence_id'] = 0;
                            break;
                        }
                    // else: 'future' == 'all' if modifying the master event

                    default:  // 'all' is default
                        $event['id'] = $master['id'];
                        $event['recurrence_id'] = 0;

                        // use start date from master but try to be smart on time or duration changes
                        $old_start_date = $old['start']->format('Y-m-d');
                        $old_start_time = $old['allday'] ? '' : $old['start']->format('H:i');
                        $old_duration = $old['end']->format('U') - $old['start']->format('U');

                        $new_start_date = $event['start']->format('Y-m-d');
                        $new_start_time = $event['allday'] ? '' : $event['start']->format('H:i');
                        $new_duration = $event['end']->format('U') - $event['start']->format('U');

                        $diff = $old_start_date != $new_start_date || $old_start_time != $new_start_time || $old_duration != $new_duration;

                        // shifted or resized
                        if ($diff && ($old_start_date == $new_start_date || $old_duration == $new_duration)) {
                            $event['start'] = $master['start']->add($old['start']->diff($event['start']));
                            $event['end'] = clone $event['start'];
                            $event['end']->add(new DateInterval('PT'.$new_duration.'S'));
                        }
                        // dates did not change, use the ones from master
                        else if ($event['start'] == $old['start'] && $event['end'] == $old['end']) {
                            $event['start'] = $master['start'];
                            $event['end'] = $master['end'];
                        }
                        break;
                }
            }

            $success = $this->_update_event($event, $update_recurring);
            if ($success && $update_master)
                $this->_update_event($master, true);

            return $success;
        }

        return false;
    }

    /**
     * Convert save data to be used in SQL statements
     */
    private function _save_preprocess($event)
    {
        // shift dates to server's timezone (except for all-day events)
        if (!$event['allday']) {
            $event['start'] = clone $event['start'];
            $event['start']->setTimezone($this->server_timezone);
            $event['end'] = clone $event['end'];
            $event['end']->setTimezone($this->server_timezone);
        }

        // compose vcalendar-style recurrencue rule from structured data
        $rrule = $event['recurrence'] ? libcalendaring::to_rrule($event['recurrence']) : '';
        $event['_recurrence'] = rtrim($rrule, ';');
        $event['free_busy'] = intval($this->free_busy_map[strtolower($event['free_busy'])]);
        $event['sensitivity'] = intval($this->sensitivity_map[strtolower($event['sensitivity'])]);

        if ($event['free_busy'] == 'tentative') {
            $event['status'] = 'TENTATIVE';
        }

        if (isset($event['allday'])) {
            $event['all_day'] = $event['allday'] ? 1 : 0;
        }

        // compute absolute time to notify the user
        $event['notifyat'] = $this->_get_notification($event);

        if (is_array($event['valarms'])) {
            $event['alarms'] = $this->serialize_alarms($event['valarms']);
        }

        // process event attendees
        $_attendees = '';
        foreach ((array)$event['attendees'] as $attendee) {
            if (!$attendee['name'] && !$attendee['email'])
                continue;
            $_attendees .= 'NAME="'.addcslashes($attendee['name'], '"') . '"' .
                ';STATUS=' . $attendee['status'].
                ';ROLE=' . $attendee['role'] .
                ';EMAIL=' . $attendee['email'] .
                "\n";
        }
        $event['attendees'] = rtrim($_attendees);

        return $event;
    }

    /**
     * Compute absolute time to notify the user
     */
    private function _get_notification($event)
    {
        if ($event['valarms'] && $event['start'] > new DateTime()) {
            $alarm = libcalendaring::get_next_alarm($event);

            if ($alarm['time'] && in_array($alarm['action'], $this->alarm_types))
                return date('Y-m-d H:i:s', $alarm['time']);
        }

        return null;
    }

    /**
     * Save the given event record to database
     *
     * @param array Event data, already passed through self::_save_preprocess()
     * @param boolean True if recurring events instances should be updated, too
     */
    private function _update_event($event, $update_recurring = true)
    {
        $event = $this->_save_preprocess($event);
        $sql_set = array();
        $set_cols = array('start', 'end', 'all_day', 'recurrence_id', 'sequence', 'title', 'description', 'location', 'categories', 'url', 'free_busy', 'priority', 'sensitivity', 'status', 'attendees', 'alarms', 'notifyat', 'caldav_url', 'caldav_tag');
        foreach ($set_cols as $col) {
            if (is_object($event[$col]) && is_a($event[$col], 'DateTime'))
                $sql_set[] = $this->rc->db->quote_identifier($col) . '=' . $this->rc->db->quote($event[$col]->format(self::DB_DATE_FORMAT));
            else if (is_array($event[$col]))
                $sql_set[] = $this->rc->db->quote_identifier($col) . '=' . $this->rc->db->quote(join(',', $event[$col]));
            else if (array_key_exists($col, $event))
                $sql_set[] = $this->rc->db->quote_identifier($col) . '=' . $this->rc->db->quote($event[$col]);
        }

        if ($event['_recurrence'])
            $sql_set[] = $this->rc->db->quote_identifier('recurrence') . '=' . $this->rc->db->quote($event['_recurrence']);

        if ($event['_fromcalendar'] && $event['_fromcalendar'] != $event['calendar'])
            $sql_set[] = 'calendar_id=' . $this->rc->db->quote($event['calendar']);

        $query = $this->rc->db->query(sprintf(
            "UPDATE " . $this->db_events . "
                SET   changed=%s %s
                WHERE event_id=?
                AND   calendar_id IN (" . $this->calendar_ids . ")",
            $this->rc->db->now(),
            ($sql_set ? ', ' . join(', ', $sql_set) : '')
        ),
            $event['id']
        );

        $success = $this->rc->db->affected_rows($query);

        // add attachments
        if ($success && !empty($event['attachments'])) {
            foreach ($event['attachments'] as $attachment) {
                $this->add_attachment($attachment, $event['id']);
                unset($attachment);
            }
        }

        // remove attachments
        if ($success && !empty($event['deleted_attachments'])) {
            foreach ($event['deleted_attachments'] as $attachment) {
                $this->remove_attachment($attachment, $event['id']);
            }
        }

        if ($success) {
            unset($this->cache[$event['id']]);
            if ($update_recurring)
                $this->_update_recurring($event);
        }

        return $success;
    }

    /**
     * Insert "fake" entries for recurring occurences of this event
     */
    private function _update_recurring($event)
    {
        if (empty($this->calendars))
            return;

        // clear existing recurrence copies
        $this->rc->db->query(
            "DELETE FROM " . $this->db_events . "
       WHERE recurrence_id=?
       AND calendar_id IN (" . $this->calendar_ids . ")",
            $event['id']
        );

        // create new fake entries
        if ($event['recurrence']) {
            // include library class
            require_once($this->cal->home . '/lib/calendar_recurrence.php');

            $recurrence = new calendar_recurrence($this->cal, $event);

            $count = 0;
            $duration = $event['start']->diff($event['end']);
            while ($next_start = $recurrence->next_start()) {
                $next_start->setTimezone($this->server_timezone);
                $next_end = clone $next_start;
                $next_end->add($duration);
                $notify_at = $this->_get_notification(array('alarms' => $event['alarms'], 'start' => $next_start, 'end' => $next_end, 'status' => $event['status']));
                $query = $this->rc->db->query(sprintf(
                    "INSERT INTO " . $this->db_events . "
           (calendar_id, recurrence_id, created, changed, uid, %s, %s, all_day, recurrence, title, description, location, categories, url, free_busy, priority, sensitivity, status, alarms, attendees, notifyat, caldav_url, caldav_tag)
            SELECT calendar_id, ?, %s, %s, uid, ?, ?, all_day, recurrence, title, description, location, categories, url, free_busy, priority, sensitivity, status, alarms, attendees, ?, caldav_url, caldav_tag
            FROM  " . $this->db_events . " WHERE event_id=? AND calendar_id IN (" . $this->calendar_ids . ")",
                    $this->rc->db->quote_identifier('start'),
                    $this->rc->db->quote_identifier('end'),
                    $this->rc->db->now(),
                    $this->rc->db->now()
                ),
                    $event['id'],
                    $next_start->format(self::DB_DATE_FORMAT),
                    $next_end->format(self::DB_DATE_FORMAT),
                    $notify_at,
                    $event['id']
                );

                if (!$this->rc->db->affected_rows($query))
                    break;

                // stop adding events for inifinite recurrence after 20 years
                if (++$count > 999 || (!$recurrence->recurEnd && !$recurrence->recurCount && $next_start->format('Y') > date('Y') + 20))
                    break;
            }
        }
    }

    /**
     * Move a single event
     *
     * @param array Hash array with event properties
     * @see calendar_driver::move_event()
     * @return bool
     */
    public function move_event($event)
    {
        // let edit_event() do all the magic
        return $this->edit_event($event + (array)$this->get_event($event));
    }

    /**
     * Resize a single event
     *
     * @param array Hash array with event properties
     * @see calendar_driver::resize_event()
     * @return bool
     */
    public function resize_event($event)
    {
        // let edit_event() do all the magic
        return $this->edit_event($event + (array)$this->get_event($event));
    }

    /**
     * Remove a single event from the database and from the CalDAV server.
     *
     * @param array Hash array with event properties
     * @param boolean Remove record irreversible
     *
     * @see calendar_driver::remove_event()
     * @return bool
     */
    public function remove_event($event, $force = true)
    {
        $event_id = (int)$event["id"];
        $cal_id = (int)$event["calendar"];
        $event = $this->get_event($event);

        $sync_client = $this->sync_clients[$cal_id];
        $success = $sync_client->remove_event($event);

        if($success === true)
        {
            $this->_db_remove_event($event, $force);
            self::debug_log("Successfully removed event \"$event_id\".");

            // Trigger calendar sync to update ctags and etags.
            $this->_sync_calendar($cal_id);

            return true;
        }

        $this->_raise_error("Could not remove event: Unexpected CalDAV error.");
        return false;
    }

    /**
     * Remove a single event from the database
     *
     * @param array   Hash array with event properties
     * @param boolean Remove record irreversible (@TODO)
     *
     * @see calendar_driver::remove_event()
     * @return bool
     */
    private function _db_remove_event($event, $force = true)
    {
        if (!empty($this->calendars)) {
            $event += (array)$this->get_event($event);
            $master = $event;
            $update_master = false;
            $savemode = 'all';

            // read master if deleting a recurring event
            if ($event['recurrence'] || $event['recurrence_id']) {
                $master = $event['recurrence_id'] ? $this->get_event(array('id' => $event['recurrence_id'])) : $event;
                $savemode = $event['_savemode'];
            }

            switch ($savemode) {
                case 'current':
                    // add exception to master event
                    $master['recurrence']['EXDATE'][] = $event['start'];
                    $update_master = true;

                    // just delete this single occurence
                    $query = $this->rc->db->query("
                        DELETE FROM " . $this->db_events . "
                        WHERE calendar_id IN (" . $this->calendar_ids . ")
                        AND event_id=?",
                        $event['id']
                    );
                    break;

                case 'future':
                    if ($master['id'] != $event['id']) {
                        // set until-date on master event
                        $master['recurrence']['UNTIL'] = clone $event['start'];
                        $master['recurrence']['UNTIL']->sub(new DateInterval('P1D'));
                        unset($master['recurrence']['COUNT']);
                        $update_master = true;

                        // delete this and all future instances
                        $fromdate = clone $event['start'];
                        $fromdate->setTimezone($this->server_timezone);
                        $query = $this->rc->db->query("
                            DELETE FROM " . $this->db_events . "
                            WHERE calendar_id IN (" . $this->calendar_ids . ")
                            AND " . $this->rc->db->quote_identifier('start') . " >= ?
                            AND recurrence_id=?",
                            $fromdate->format(self::DB_DATE_FORMAT),
                            $master['id']
                        );
                        break;
                    }
                // else: future == all if modifying the master event

                default:  // 'all' is default
                    $query = $this->rc->db->query("
                        DELETE FROM " . $this->db_events . "
                        WHERE (event_id=? OR recurrence_id=?)
                        AND calendar_id IN (" . $this->calendar_ids . ")",
                        $master['id'],
                        $master['id']
                    );
                    break;
            }

            $success = $this->rc->db->affected_rows($query);
            if ($success && $update_master)
                $this->_update_event($master, true);

            return $success;
        }

        return false;
    }

    /**
     * Return data of a specific event
     * @param mixed  Hash array with event properties or event UID
     * @param boolean Only search in writeable calendars (ignored)
     * @param boolean Only search in active calendars
     * @param boolean Only search in personal calendars (ignored)
     * @return array Hash array with event properties
     */
    public function get_event($event, $writeable = false, $active = false, $personal = false)
    {
        $id = is_array($event) ? ($event['id'] ? $event['id'] : $event['uid']) : $event;
        $cal = is_array($event) ? $event['calendar'] : null;
        $col = is_array($event) && is_numeric($id) ? 'event_id' : 'uid';

        if ($this->cache[$id])
            return $this->cache[$id];

        if ($active) {
            $calendars = $this->calendars;
            foreach ($calendars as $idx => $cal) {
                if (!$cal['active']) {
                    unset($calendars[$idx]);
                }
            }
            $cals = join(',', $calendars);
        }
        else {
            $cals = $this->calendar_ids;
        }

        $result = $this->rc->db->query(sprintf(
            "SELECT e.*, (SELECT COUNT(attachment_id) FROM " . $this->db_attachments . "
         WHERE event_id = e.event_id OR event_id = e.recurrence_id) AS _attachments
       FROM " . $this->db_events . " AS e
       WHERE e.calendar_id IN (%s)
       AND e.$col=?",
            $cals
        ),
            $id);

        if ($result && ($event = $this->rc->db->fetch_assoc($result)) && $event['event_id']) {
            $this->cache[$id] = $this->_read_postprocess($event);
            return $this->cache[$id];
        }

        return false;
    }

    /**
     * Sync and returns event data
     *
     * @see calendar_driver::load_events()
     */
    public function load_events($start, $end, $query = null, $calendars = null, $virtual = 1, $modifiedsince = null)
    {
        if (empty($calendars))
            $calendars = array_keys($this->calendars);
        else if (!is_array($calendars))
            $calendars = explode(',', strval($calendars));

        // only allow to select from calendars of this use
        $calendar_ids = array_intersect($calendars, array_keys($this->calendars));

        // Make sure that the calendars are in sync.
        foreach ($calendar_ids as $cal_id) {
            if (!$this->_is_synced($cal_id))
                $this->_sync_calendar($cal_id);
        }

        return $this->_db_load_events($start, $end, $query, $calendars, $virtual, $modifiedsince);
    }

    /**
     * Get event data
     *
     * @see calendar_driver::load_events()
     */
    private function _db_load_events($start, $end, $query = null, $calendars = null, $virtual = 1, $modifiedsince = null)
    {
        if (empty($calendars))
            $calendars = array_keys($this->calendars);
        else if (!is_array($calendars))
            $calendars = explode(',', strval($calendars));

        // only allow to select from calendars of this use
        $calendar_ids = array_map(array($this->rc->db, 'quote'), array_intersect($calendars, array_keys($this->calendars)));

        // compose (slow) SQL query for searching
        // FIXME: improve searching using a dedicated col and normalized values
        if ($query) {
            foreach (array('title','location','description','categories','attendees') as $col)
                $sql_query[] = $this->rc->db->ilike($col, '%'.$query.'%');
            $sql_add = 'AND (' . join(' OR ', $sql_query) . ')';
        }

        if (!$virtual)
            $sql_add .= ' AND e.recurrence_id = 0';

        if ($modifiedsince)
            $sql_add .= ' AND e.changed >= ' . $this->rc->db->quote(date('Y-m-d H:i:s', $modifiedsince));

        $events = array();
        if (!empty($calendar_ids)) {
            $result = $this->rc->db->query(sprintf("
                SELECT e.*, (SELECT COUNT(attachment_id) FROM " . $this->db_attachments . "
                WHERE event_id = e.event_id OR event_id = e.recurrence_id) AS _attachments
                FROM " . $this->db_events . " e
                WHERE e.calendar_id IN (%s)
                AND e.start <= %s AND e.end >= %s
                %s",
                join(',', $calendar_ids),
                $this->rc->db->fromunixtime($end),
                $this->rc->db->fromunixtime($start),
                $sql_add
            ));

            while ($result && ($event = $this->rc->db->fetch_assoc($result))) {
                $events[] = $this->_read_postprocess($event);
            }
        }

        return $events;
    }

    /**
     * Get number of events in the given calendar
     *
     * @param  mixed   List of calendar IDs to count events (either as array or comma-separated string)
     * @param  integer Date range start (unix timestamp)
     * @param  integer Date range end (unix timestamp)
     * @return array   Hash array with counts grouped by calendar ID
     */
    public function count_events($calendars, $start, $end = null)
    {
        // not implemented
        return array();
    }

    /**
     * Convert sql record into a rcube style event object
     */
    private function _read_postprocess($event)
    {
        $free_busy_map = array_flip($this->free_busy_map);
        $sensitivity_map = array_flip($this->sensitivity_map);

        $event['id'] = $event['event_id'];
        $event['start'] = new DateTime($event['start']);
        $event['end'] = new DateTime($event['end']);
        $event['allday'] = intval($event['all_day']);
        $event['created'] = new DateTime($event['created']);
        $event['changed'] = new DateTime($event['changed']);
        $event['free_busy'] = $free_busy_map[$event['free_busy']];
        $event['sensitivity'] = $sensitivity_map[$event['sensitivity']];
        $event['calendar'] = $event['calendar_id'];
        $event['recurrence_id'] = intval($event['recurrence_id']);

        // parse recurrence rule
        if ($event['recurrence'] && preg_match_all('/([A-Z]+)=([^;]+);?/', $event['recurrence'], $m, PREG_SET_ORDER)) {
            $event['recurrence'] = array();
            foreach ($m as $rr) {
                if (is_numeric($rr[2]))
                    $rr[2] = intval($rr[2]);
                else if ($rr[1] == 'UNTIL')
                    $rr[2] = date_create($rr[2]);
                else if ($rr[1] == 'RDATE')
                    $rr[2] = array_map('date_create', explode(',', $rr[2]));
                else if ($rr[1] == 'EXDATE')
                    $rr[2] = array_map('date_create', explode(',', $rr[2]));
                $event['recurrence'][$rr[1]] = $rr[2];
            }
        }

        if ($event['_attachments'] > 0)
            $event['attachments'] = (array)$this->list_attachments($event);

        // decode serialized event attendees
        if ($event['attendees']) {
            $attendees = array();
            foreach (explode("\n", $event['attendees']) as $line) {
                $att = array();
                foreach (rcube_utils::explode_quoted_string(';', $line) as $prop) {
                    list($key, $value) = explode("=", $prop);
                    $att[strtolower($key)] = stripslashes(trim($value, '""'));
                }
                $attendees[] = $att;
            }
            $event['attendees'] = $attendees;
        }
        else {
            $event['attendees'] = array();
        }

        // decode serialized alarms
        if ($event['alarms']) {
            $event['valarms'] = $this->unserialize_alarms($event['alarms']);
        }

        unset($event['event_id'], $event['calendar_id'], $event['notifyat'], $event['all_day'], $event['_attachments']);
        return $event;
    }

    /**
     * Get a list of pending alarms to be displayed to the user
     *
     * @see calendar_driver::pending_alarms()
     */
    public function pending_alarms($time, $calendars = null)
    {
        if (empty($calendars))
            $calendars = array_keys($this->calendars);
        else if (is_string($calendars))
            $calendars = explode(',', $calendars);

        // only allow to select from calendars with activated alarms
        $calendar_ids = array();
        foreach ($calendars as $cid) {
            if ($this->calendars[$cid] && $this->calendars[$cid]['showalarms'])
                $calendar_ids[] = $cid;
        }
        $calendar_ids = array_map(array($this->rc->db, 'quote'), $calendar_ids);

        $alarms = array();
        if (!empty($calendar_ids)) {
            $result = $this->rc->db->query(sprintf(
                "SELECT * FROM " . $this->db_events . "
         WHERE calendar_id IN (%s)
         AND notifyat <= %s AND %s > %s",
                join(',', $calendar_ids),
                $this->rc->db->fromunixtime($time),
                $this->rc->db->quote_identifier('end'),
                $this->rc->db->fromunixtime($time)
            ));

            while ($result && ($event = $this->rc->db->fetch_assoc($result)))
                $alarms[] = $this->_read_postprocess($event);
        }

        return $alarms;
    }

    /**
     * Feedback after showing/sending an alarm notification
     *
     * @see calendar_driver::dismiss_alarm()
     */
    public function dismiss_alarm($event_id, $snooze = 0)
    {
        // set new notifyat time or unset if not snoozed
        $notify_at = $snooze > 0 ? date(self::DB_DATE_FORMAT, time() + $snooze) : null;

        $query = $this->rc->db->query(sprintf(
            "UPDATE " . $this->db_events . "
       SET   changed=%s, notifyat=?
       WHERE event_id=?
       AND calendar_id IN (" . $this->calendar_ids . ")",
            $this->rc->db->now()),
            $notify_at,
            $event_id
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Save an attachment related to the given event
     */
    private function add_attachment($attachment, $event_id)
    {
        $data = $attachment['data'] ? $attachment['data'] : file_get_contents($attachment['path']);

        $query = $this->rc->db->query(
            "INSERT INTO " . $this->db_attachments .
            " (event_id, filename, mimetype, size, data)" .
            " VALUES (?, ?, ?, ?, ?)",
            $event_id,
            $attachment['name'],
            $attachment['mimetype'],
            strlen($data),
            base64_encode($data)
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Remove a specific attachment from the given event
     */
    private function remove_attachment($attachment_id, $event_id)
    {
        $query = $this->rc->db->query(
            "DELETE FROM " . $this->db_attachments .
            " WHERE attachment_id = ?" .
            " AND event_id IN (SELECT event_id FROM " . $this->db_events .
            " WHERE event_id = ?"  .
            " AND calendar_id IN (" . $this->calendar_ids . "))",
            $attachment_id,
            $event_id
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * List attachments of specified event
     */
    public function list_attachments($event)
    {
        $attachments = array();

        if (!empty($this->calendar_ids)) {
            $result = $this->rc->db->query(
                "SELECT attachment_id AS id, filename AS name, mimetype, size " .
                " FROM " . $this->db_attachments .
                " WHERE event_id IN (SELECT event_id FROM " . $this->db_events .
                " WHERE event_id=?"  .
                " AND calendar_id IN (" . $this->calendar_ids . "))".
                " ORDER BY filename",
                $event['recurrence_id'] ? $event['recurrence_id'] : $event['event_id']
            );

            while ($result && ($arr = $this->rc->db->fetch_assoc($result))) {
                $attachments[] = $arr;
            }
        }

        return $attachments;
    }

    /**
     * Get attachment properties
     */
    public function get_attachment($id, $event)
    {
        if (!empty($this->calendar_ids)) {
            $result = $this->rc->db->query(
                "SELECT attachment_id AS id, filename AS name, mimetype, size " .
                " FROM " . $this->db_attachments .
                " WHERE attachment_id=?".
                " AND event_id=?",
                $id,
                $event['recurrence_id'] ? $event['recurrence_id'] : $event['id']
            );

            if ($result && ($arr = $this->rc->db->fetch_assoc($result))) {
                return $arr;
            }
        }

        return null;
    }

    /**
     * Get attachment body
     */
    public function get_attachment_body($id, $event)
    {
        if (!empty($this->calendar_ids)) {
            $result = $this->rc->db->query(
                "SELECT data " .
                " FROM " . $this->db_attachments .
                " WHERE attachment_id=?".
                " AND event_id=?",
                $id,
                $event['id']
            );

            if ($result && ($arr = $this->rc->db->fetch_assoc($result))) {
                return base64_decode($arr['data']);
            }
        }

        return null;
    }

    /**
     * Remove the given category
     */
    public function remove_category($name)
    {
        $query = $this->rc->db->query(
            "UPDATE " . $this->db_events . "
       SET   categories=''
       WHERE categories=?
       AND   calendar_id IN (" . $this->calendar_ids . ")",
            $name
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Update/replace a category
     */
    public function replace_category($oldname, $name, $color)
    {
        $query = $this->rc->db->query(
            "UPDATE " . $this->db_events . "
       SET   categories=?
       WHERE categories=?
       AND   calendar_id IN (" . $this->calendar_ids . ")",
            $name,
            $oldname
        );

        return $this->rc->db->affected_rows($query);
    }

    /**
     * Helper method to serialize the list of alarms into a string
     */
    private function serialize_alarms($valarms)
    {
        foreach ((array)$valarms as $i => $alarm) {
            if ($alarm['trigger'] instanceof DateTime) {
                $valarms[$i]['trigger'] = '@' . $alarm['trigger']->format('c');
            }
        }

        return $valarms ? json_encode($valarms) : null;
    }

    /**
     * Helper method to decode a serialized list of alarms
     */
    private function unserialize_alarms($alarms)
    {
        // decode json serialized alarms
        if ($alarms && $alarms[0] == '[') {
            $valarms = json_decode($alarms, true);
            foreach ($valarms as $i => $alarm) {
                if ($alarm['trigger'][0] == '@') {
                    try {
                        $valarms[$i]['trigger'] = new DateTime(substr($alarm['trigger'], 1));
                    }
                    catch (Exception $e) {
                        unset($valarms[$i]);
                    }
                }
            }
        }
        // convert legacy alarms data
        else if (strlen($alarms)) {
            list($trigger, $action) = explode(':', $alarms, 2);
            if ($trigger = libcalendaring::parse_alaram_value($trigger)) {
                $valarms = array(array('action' => $action, 'trigger' => $trigger[3] ?: $trigger[0]));
            }
        }

        return $valarms;
    }

    /**
     * Handler for user_delete plugin hook
     */
    public function user_delete($args)
    {
        $db = $this->rc->db;
        $user = $args['user'];
        $event_ids = array();

        $events = $db->query(
            "SELECT event_id FROM " . $this->db_events . " AS ev" .
            " LEFT JOIN " . $this->db_calendars . " cal ON (ev.calendar_id = cal.calendar_id)".
            " WHERE user_id=?",
            $user->ID);

        while ($row = $db->fetch_assoc($events)) {
            $event_ids[] = $row['event_id'];
        }

        if (!empty($event_ids)) {
            foreach (array($this->db_attachments, $this->db_events) as $table) {
                $db->query(sprintf("DELETE FROM $table WHERE event_id IN (%s)", join(',', $event_ids)));
            }
        }

        foreach (array($this->db_calendars, 'itipinvitations') as $table) {
            $db->query("DELETE FROM $table WHERE user_id=?", $user->ID);
        }
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
        // Make sure we have current attributes
        $calendar = $this->calendars[$calendar["id"]];

        $input_caldav_url = new html_inputfield( array(
            "name" => "caldav_url",
            "id" => "caldav_url",
            "size" => 20
        ));

        $formfields["caldav_url"] = array(
            "label" => $this->cal->gettext("caldavurl"),
            "value" => $input_caldav_url->show($calendar["caldav_url"]),
            "id" => "caldav_url",
        );

        $input_caldav_user = new html_inputfield( array(
            "name" => "caldav_user",
            "id" => "caldav_user",
            "size" => 20
        ));

        $formfields["caldav_user"] = array(
            "label" => $this->cal->gettext("username"),
            "value" => $input_caldav_user->show($calendar["caldav_user"]),
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
     * Expand all "%p" occurrences in 'caldav_pass' element of calendar object
     * properties array with RC (imap) password.
     * Other elements are left untouched.
     *
     * @param array List of properties
     * @return array List of properties, with expanded 'caldav_pass' attribute
     *
     */
    private function _expand_pass($props)
    {
        if (isset($props['caldav_pass']))
            $props['caldav_pass'] = str_replace('%p', $this->rc->get_user_password(), $props['caldav_pass']);

        return $props;
    }

    /**
     * Auto discover calenders available to the user on the caldav server
     * @param array $props
     *    caldav_url: Absolute URL to CalDAV server
     *   caldav_user: Username
     *   caldav_pass: Password
     * @return False on error or an array with the following calendar props:
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
        $caldav = new caldav_client($props["url"], $props["caldav_user"], $props["caldav_pass"]);

        $tokens = parse_url($props["url"]);
        $base_uri = $tokens['scheme']."://".$tokens['host'].($tokens['port'] ? ":".$tokens['port'] : null);
        $caldav_url = $props["url"];
        $response = $caldav->prop_find($caldav_url, array_merge($current_user_principal,$cal_attribs), 0);
        if (!$response) {
            $this->_raise_error("Resource \"$caldav_url\" has no collections");
            return false;
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
            $this->_raise_error("Resource \"$caldav_url\" contains no calendars.");
            return false;
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
     * Synchronizes events of given calendar.
     *
     * @param int Calendar ID to sync
     */
    private function _sync_calendar($cal_id)
    {
        self::debug_log("Syncing calendar id \"$cal_id\".");

        $cal_sync = $this->sync_clients[$cal_id];
        $events = array();

        // Ignore recurrence events and read caldav props
        foreach($this->_load_all_events($cal_id) as $event) {
            if($event["recurrence_id"] == 0) {
                array_push($events, $event);
            }
        }

        $updates = $cal_sync->get_updates($events);
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
                    $this->_db_remove_event($event, true);
                    self::debug_log("Remove event \"".$event["id"]."\".");
                }
            }

            // Update calendar ctag ...
            $calendar = $this->calendars[$cal_id];
            $calendar["caldav_tag"] = $cal_sync->get_ctag();
            $this->edit_calendar($calendar);
        }

        self::debug_log("Successfully synced calendar id \"$cal_id\".");
    }

    /**
     * Return all events from the given calendar.
     *
     * @param int Calendar id.
     * @return array
     */
    private function _load_all_events($cal_id)
    {
        // FIXME: This is kind of ugly but a way to get _all_ events without touching the database driver.

        // Get the event with the maximum end time.
        $result = $this->rc->db->query(
            "SELECT MAX(e.end) as end FROM ".$this->db_events." e ".
            "WHERE e.calendar_id = ? ", $cal_id);

        if($result && ($arr = $this->rc->db->fetch_assoc($result))) {
            $end = new DateTime($arr["end"]);

            // Don't use load_events() which is doing another sync while this method might be already invoked in an sync.
            return $this->_db_load_events(0, $end->getTimestamp(), null, array($cal_id));
        }
        else return array();
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
                // Overwrite local event attributes with new event, url + etag.
                $event = array_merge((array)$update["local_event"], $update["remote_event"], array(
                    "caldav_url" => $update["url"],
                    "caldav_tag" => $update["etag"]));

                // let edit_event() do all the magic
                if($this->_db_edit_event($event))
                {
                    $event_id = $event["id"];
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
                $event = array_merge($update["remote_event"], array(
                    "caldav_url" => $update["url"],
                    "caldav_tag" => $update["etag"]));

                $event_id = $this->new_event($event);
                if($event_id)
                {
                    self::debug_log("Created event \"$event_id\".");
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
            "UPDATE ".$this->db_calendars." ".
            "SET caldav_last_change = NOW() WHERE calendar_id = ? AND ".
            $this->_unix_timestamp('caldav_last_change') ." + ? <= ".$this->_unix_timestamp('NOW()'),
            $cal_id, $this->sync_period);

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
     * Returns db-specific timestamp queries for epoch format
     *
     * @param str column name or valid timestamp (e.g. NOW())
     * @return str db-specific timestamp query for epoch format
     */
    private function _unix_timestamp($field)
    {
        switch ($this->rc->db->db_provider) {
            case 'postgres':
                return "EXTRACT (EPOCH FROM $field)";
            default:
                return "UNIX_TIMESTAMP($field)";
        }
    }

    private function _decrypt_pass($pass) {
        $p = base64_decode($pass);
        $e = new Encryption(MCRYPT_BlOWFISH, MCRYPT_MODE_CBC);
        return $e->decrypt($p, $this->crypt_key);
    }

    private function _encrypt_pass($pass) {
        $e = new Encryption(MCRYPT_BlOWFISH, MCRYPT_MODE_CBC);
        $p = $e->encrypt($pass, $this->crypt_key);
        return base64_encode($p);
    }
}
