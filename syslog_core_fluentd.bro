# Scott Campbell scampbell@lbl.gov
#
# syslog input framework v. 0.1
# 4/30/2016  Scott Campbell
#
# Policy to read data from a fluentd processed syslog stream.
#
# policy snippet looks like:
#
#	<source>
#	  @type tail
#	  path /data/messages
#	  pos_file /tmp/syslog_read.pos
#	  format syslog
#	  keep_time_key true
#	  tag syslog.data
#	  refresh_interval .1
#	  read_lines_limit 10000
#	</source>
#	<filter syslog.data>
#	  @type grep
#	  regexp1 ident sshd|nim-login|httpd|BROEVENT|newt|gatekeeper
#	</filter>
#

@load frameworks/communication/listen
@load base/frameworks/input
@load host_core

@load syslog_policy/syslog_httpd_fluentd
@load syslog_policy/syslog_secAPI_fluentd
@load syslog_policy/syslog_globus_fluentd

module SYSLOG_PARSE;

export {

	# for SYSLOG_PARSE logging stream
	redef enum Log::ID += { LOG };
	redef enum Log::ID += { LOG2 };

        redef enum Notice::Type += {
                SYSLOG_INPUT_LowTransactionRate,
                SYSLOG_INPUT_HighTransactionRate,
		SYSLOG_INPUT_DataReset,
		};

	global data_file = "/" &redef;

	global kv_splitter: pattern = /[\ \t]+/;
	global space_split: pattern = /[\ ]+/;
	global tab_split: pattern = /[\t]/;
	global one_space: string = " ";

	global sshd_pattern: pattern =/sshd/;
	global nim_pattern: pattern =/nim-login/;
	global bro_api_pattern: pattern =/newt|BROEVENT/;
	global httpd_pattern: pattern = /httpd/;
	global gatekeeper_pattern: pattern = /gatekeeper/;
	global myproxy_pattern: pattern = /myproxy-server/;

	global year = "1970" &redef;	# this will be set at start time
	global tzone = "PST" &redef;	# this will be set at start time
	const year_refresh_interval = 1 min;

	# for passing line data from the file reader to the event handler
	type lineVals: record {
		d: string;
		};

	# table of functions mapped by the line type
	const dispatcher: table[string] of function(_data: string): count &redef;

	# for gatekeeper we need a data structure to hold state as info is built up
	type gatekeeperRec: record {
		start: time &log &default = double_to_time(0.000000);
		dt: double &log &default = 0.000000;
		# resp_h is the syslog source
		orig_h: string &log &default = "127.127.127.127";
		log_source_ip: string &log &default = "127.127.127.127";
		# user related info
		g_user: string &log &default = "NULL";
		l_user: string &log &default = "NULL";
		l_uid: count &log &default = 999999;
		l_gid: count &log &default = 999999;
		#
		service: string &log &default = "NULL";
		success: string &log &default = "NULL";
		#
		error_msg: string &log &default = "NULL";
		};

	#  indexed by [resp_h,pid] => string
	global gc_table: table[string] of gatekeeperRec;

	global stop_sem = 0 &redef;

        # track the transaction rate - notice on transition between low and high water rates
        # this is count per input_test_interval
        const input_count_test = T &redef;
        const input_low_water:count = 10 &redef;
        const input_high_water:count = 10000 &redef;
        const input_test_interval:interval = 60 sec &redef;
        # track input rate ( events/input_test_interval)
        global input_count: count = 1 &redef;
        global input_count_prev: count = 1 &redef;
        global input_count_delta: count = 0 &redef;
        #  0=pre-init, 1=ok, 2=in low error
        global input_count_state: count = 0 &redef;
	const DATANODE = F &redef;

	global build_connid: function(orig_h:addr, orig_p:port , log_source_ip:addr, resp_p:port) : conn_id;
	global time_convert: function(data: string) : time;

	} # end export

function build_connid(orig_h:addr, orig_p:port , log_source_ip:addr, resp_p:port) : conn_id
	{
	local t_conn_id: conn_id;

	t_conn_id$orig_h = orig_h;
	t_conn_id$orig_p = orig_p;
	t_conn_id$resp_h = log_source_ip;
	t_conn_id$resp_p = resp_p;

	return t_conn_id;
	}
# Here we handle the nasty nasty buisness of dealing with syslog time.
# Since the syslog *file* normally contains "Month  Day Time" but not year, we
#  will not have the year as well as any sub second data.  With no other info, we
#  grope around a bit and hope that the year in the file is the same as the year
#  for current time...
#
function time_convert(data: string) : time
	{
	# The string converter seems to be slightly OS dependant.
	# Linux:
	local parse_string: string = "%Y %B %d %T";
	# FreeBSD:
	#local parse_string: string = "%Z %Y %b %d %H:%M:%S";
	local date_mod = "NULL";

	# first convert the string to a known quantity
	# like parse_string, we can get away with not having the
	#   time zone in the equsn.
	# Linux:
	date_mod = fmt("%s %s", year,data);
	# FreeBSD
	#date_mod = fmt("%s %s %s", tzone,year,data);

	# second, make sure that any extra spaces in the date string are expunged...
	local date_mod_p = gsub(date_mod, kv_splitter, one_space);

	local ret_val = strptime(parse_string, date_mod_p);

	return ret_val;
	}

# Take data of the form key:value and return the value portion
function get_data(data: string) : string
        {
		local ret_val: string_vec;
		local delim: pattern = /:/;

		ret_val = split_string1(data, delim);

		return ret_val[1];
        }

function accepted_f(data: string) : count
	{
	# time:Apr 22 11:00:23	host:128.55.160.223	ident:sshd	pid:5437	message:Accepted keyboard-interactive/pam for eeloe from 131.243.223.234 port 61519 ssh2
	local parts = split_string(data, tab_split);
	local msg_parts = split_string( get_data(parts[4]), space_split );
	local time_parts = split_string( get_data(parts[0]), space_split );

	local pid = get_data(parts[3]);
	local log_source_ip = get_data(parts[1]);

	local auth_type = msg_parts[1];
	local auth_id = msg_parts[3];
	local orig_h = msg_parts[5];
	# convert into bro port type
	local orig_p = fmt("%s/tcp", msg_parts[7]);

	local month = time_parts[0];
	local day   = time_parts[1];
	local t  = time_parts[2];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));

	#print fmt("KEY ACCEPT: %s %s %s %s %s %s", auth_id, key,log_source_ip, pid, orig_h, orig_p);

	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "ACCEPTED", auth_type, "DATA");
	return 0;
	}

function postponed_f(data: string) : count
	{
	# time:Apr 22 11:34:07	host:128.55.160.14	ident:sshd	pid:15962	message:Postponed keyboard-interactive for lgerhard from 128.55.162.250 port 36782 ssh2 [preauth]
	local parts = split_string(data, tab_split);
	local msg_parts = split_string( get_data(parts[4]), space_split );
	local time_parts = split_string( get_data(parts[0]), space_split );

	local pid = get_data(parts[3]);
	local log_source_ip = get_data(parts[1]);

	local auth_type = msg_parts[1];
	local auth_id = msg_parts[3];
	local orig_h = msg_parts[5];
	# convert into bro port type
	local orig_p = fmt("%s/tcp", msg_parts[7]);

	local month = time_parts[0];
	local day   = time_parts[1];
	local t  = time_parts[2];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));

	#print fmt("KEY POST: %s %s %s %s %s %s ", auth_id, key,log_source_ip, pid, orig_h, orig_p);

	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "POSTPONED", auth_type, "DATA");
	return 0;
	}

function failed_f(data: string) : count
	{
	# Failed messages tend to be somewhat more complex and varried
	#
	# host:128.55.161.143	ident:sshd	pid:2513	message:|Failed password for root from 222.186.21.120 port 2195| ssh2
	# host:128.55.163.173	ident:sshd	pid:1314	message:Failed password for invalid user tomcat from 138.0.148.24 port 58313 ssh2
	#
	# some entries have data after the "ssh2" entry, use this as a index point

	local s_splitter: pattern = / ssh2/;

	local parts = split_string(data, tab_split);

	local ssh2_msg = split_string( get_data(parts[4]), s_splitter);
	local msg_parts = split_string( ssh2_msg[0], space_split );
	local time_parts = split_string( get_data(parts[0]), space_split );
	# note that the split will remove ssh2 from the string ..
	local parts_len = | msg_parts |;

	local pid = get_data(parts[3]);
	local log_source_ip = get_data(parts[1]);

	local auth_id = msg_parts[parts_len - 5];
	local orig_h = msg_parts[parts_len - 3];
	local orig_p = fmt("%s/tcp",msg_parts[parts_len - 1]);
	local auth_type = msg_parts[1];

	local month = time_parts[0];
	local day   = time_parts[1];
	local t  = time_parts[2];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));

	#print fmt("KEY FAIL: %s %s %s %s %s %s ", auth_id,key,log_source_ip, pid, orig_h, orig_p);

	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "FAILED", auth_type, "DATA");
	return 0;
	}

# General form:
#  time:Apr 22 11:09:45	host:128.55.210.29	ident:nim-login	pid:9376	message:user:annau#011remote-ip:24.7.107.195#011msg:login
# message data looks like:
# 	user:gghosh#011remote-ip:165.124.144.179#011msg:login
#   user:federicat#011remote-ip:192.33.101.100#011msg:failed-login,invalid username format (possible break-in attempt)
#
#

function nim_login_f(data: string) : count
	{
	local invalid_u: pattern = /.*invalid username format.*/;
	local invalid_p: pattern = /.*invalid password format.*/;
	local nim_delim: pattern = /\#011/;
	local comma_split: pattern = /,/;

	local action = "NULL";
	local output_data = "";

	local parts = split_string(data, tab_split);
	local time_parts = split_string( get_data(parts[0]), space_split );

	local pid = get_data(parts[3]);
	local log_source_ip = get_data(parts[1]);

	local month = time_parts[0];
	local day   = time_parts[1];
	local t  = time_parts[2];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	# The message data in this case holds the whole set of nim encoded data
	# so snip it out
	local msg_data = get_data(parts[4]);
	local nim_msg_parse = split_string( msg_data, nim_delim);

	local auth_id = get_data( nim_msg_parse[0] );
	local orig_h = get_data( nim_msg_parse[1] );
	local nim_msg_txt = get_data( nim_msg_parse[2] );

	# just some random thing ...
	local orig_p = "38476/tcp";

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("443/tcp"));

	# unpack the message part
	local nim_result = split_string( nim_msg_txt, comma_split);

	if ( strcmp( nim_result[0], "login" ) == 0 ) {
		action = "ACCEPTED";
		}
	else if ( strcmp( nim_result[0], "failed-login") == 0 ) {
		action = "FAILED";
		}

	# this will only match in the situation where there is additional info in the msg_data blocks
	if ( |nim_result| > 1 ) {
		output_data = "";

		if ( invalid_u == nim_result[1] )
			output_data = fmt("%s%s", output_data, "INVALID_USER_FORMAT");

		if ( invalid_p == nim_result[1] )
			output_data = fmt("%s %s", output_data, "INVALID_PASWD_FORMAT");

		}

	#print fmt("NIM_AUTH   %s %s PASSWD %s %s", auth_id, log_source_ip, action, output_data);
	event USER_CORE::auth_transaction(ts, "NULL", cid , auth_id, log_source_ip, "SYSLOG_NIM", "AUTHENTICATION", action, "PASSWORD", output_data);

	return 0;
	}

redef dispatcher += {
	["ACCEPTED"] = accepted_f,
	["POSTPONED"] = postponed_f,
	["FAILED"] = failed_f,
	["NIM_LOGIN"] = nim_login_f,
	["BROEVENT"] = SYSLOG_SECAPI::secapi_f,
	["GATEKEEPER"] = SYSLOG_GLOBUS::gatekeeper_f,
	["MYPROXY-SERVER"] = SYSLOG_GLOBUS::myproxy_f,
	["HTTPD"] = SYSLOG_HTTPD::httpd_f,
	};

event set_year()
	{
	local t = current_time();
	local t_year = strftime("%Y",t);
	local t_zone = strftime("%Z",t);

	SYSLOG_PARSE::year = t_year;
	SYSLOG_PARSE::tzone = t_zone;

	schedule year_refresh_interval { set_year() };
	}


event syslogLine(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
	# Each line is fed to this event where it is digested and sent to the dispatcher
	#  for appropriate processing
	#
	#  Sep 21 00:13:45 128.55.58.73 sshd[21332]: Accepted publickey for ewiedner from 128.55.58.77 port 54641 ssh2
	#  Sep 20 12:42:51 128.55.22.194 httpd[21838]: nersc.gov 128.55.22.8 - - [20/Sep/2013:12:42:51 -0700] "GET /lbstatus HTTP/1.0" 301 238 "-" "-"
	#
	++input_count;

	local parts = split_string(LV$d, tab_split);
	local event_name = "NULL";
	local event_action = "NULL";

	event_name = get_data(parts[2]);		# ident fields

	if ( sshd_pattern == event_name ) {
		# must parse out the action - i.e. accept/fail/postponed
		# action will be the first word in the message field.
		local message_data = get_data(parts[4]);
		event_action = to_upper( split_string(message_data, space_split)[0] );

		if ( event_action in dispatcher)
			dispatcher[event_action](LV$d);
		}

	else if ( nim_pattern == event_name )  {
			event_action = "NIM_LOGIN";
			dispatcher[event_action](LV$d);
		}

	else if ( bro_api_pattern == event_name )  {
			event_action = "BROEVENT";
			dispatcher[event_action](LV$d);
		}

	else if ( gatekeeper_pattern == event_name ) {
			event_action = "GATEKEEPER";
			dispatcher[event_action](LV$d);
		}

	else if ( myproxy_pattern == event_name ) {
			event_action = "MYPROXY-SERVER";
			dispatcher[event_action](LV$d);
		}

	else if ( httpd_pattern == event_name ) {
			event_action = "HTTPD";
			dispatcher[event_action](LV$d);
		}
	}

event stop_reader()
        {
        if ( stop_sem == 0 ) {
		#print fmt("%s          stop-reader", gethostname());
                Input::remove("syslog");
                stop_sem = 1;

		NOTICE([$note=SYSLOG_INPUT_DataReset,$msg=fmt("stopping reader")]);

                }
        }

event start_reader()
        {
        if ( stop_sem == 1 ) {
		#print fmt("%s          start-reader", gethostname());
		local config_strings: table[string] of string = {
			["offset"] = "-1",
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="syslog", $fields=lineVals, $ev=syslogLine]);

                stop_sem = 0;

		NOTICE([$note=SYSLOG_INPUT_DataReset,$msg=fmt("starting reader")]);

                }
        }

event sys_transaction_rate()
	{
        # Values for input_count_state:
        #  0=pre-init, 1=ok, 2=in error
        # We make the assumption here that the low_water < high_water
        # Use a global for input_count_delta so that the value is consistent across
        #   anybody looking at it.
        input_count_delta = input_count - input_count_prev;

        #print fmt("%s SYSLOG Log delta: %s", network_time(),input_count_delta);

        # rate is too low - send a notice the first time
        if (input_count_delta <= input_low_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=SYSLOG_INPUT_LowTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }

                # Now reset the reader
                schedule 1 sec { stop_reader() };
                schedule 10 sec { start_reader() };
                }
        # rate is too high - send a notice the first time
        if (input_count_delta >= input_high_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=SYSLOG_INPUT_HighTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }
                }

        # rate is ok
        if ( (input_count_delta > input_low_water) && (input_count_delta < input_high_water) ) {
                input_count_state = 1;
                }

        # rotate values
        input_count_prev = input_count;

        # reschedule this all over again ...
        schedule input_test_interval { sys_transaction_rate() };
	}

function init_datastream(): count
	{

	# give this a try - do not spin up the input framework in the event
	#   that the file is DNE
	#

	if ( DATANODE ) {

		print fmt("%s SYSLOG data file %s located", gethostname(), data_file);

		local config_strings: table[string] of string = {
			["offset"] = "-1",
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="syslog", $fields=lineVals, $ev=syslogLine]);


		# start rate monitoring for event stream
		schedule input_test_interval { sys_transaction_rate() };
		}

	Log::create_stream(SYSLOG_PARSE::LOG, [$columns=gatekeeperRec]);
	local filter_c: Log::Filter = [$name="default", $path="syslog_core"];
	Log::add_filter(LOG, filter_c);

	return 0;
	}

event bro_init()
	{
	init_datastream();
	event set_year();
	}
