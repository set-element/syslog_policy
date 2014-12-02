# Scott Campbell scampbell@lbl.gov
#
# syslog input framework v. 0.1
# 9/30/2013  Scott Campbell
#
# Policy to read in a "typical" syslog file and extract from it the 
#  sshd/auth related info.  Note that this is different from the native
#  syslog analyzer in that it is expected that not all data will be 
#  available ( ex the time/date field) etc.
#

@load frameworks/communication/listen
@load base/frameworks/input
@load host_core

@load SyslogReader/syslog_httpd
@load SyslogReader/syslog_secAPI

module SYSLOG_PARSE;

export {

	# for SYSLOG_PARSE logging stream
	redef enum Log::ID += { LOG };
	redef enum Log::ID += { LOG2 };

        redef enum Notice::Type += {
                SYSLOG_INPUT_LowTransactionRate,
                SYSLOG_INPUT_HighTransactionRate,
		};

	global data_file = "/" &redef;
	
	global kv_splitter: pattern = /[\ \t]+/;
	global one_space: string = " ";
	const pid_pattern: pattern = /\[[0-9]{1,6}\]/;

	global sshd_pattern: pattern =/sshd\[[0-9]{1,8}\]./;
	global nim_pattern: pattern =/nim-login\[[0-9]{1,8}\]./;
	global bro_api_pattern: pattern =/newt|BROEVENT/;
	global httpd_pattern: pattern = /httpd\[[0-9]{1,8}\]./;
	const  gatekeeper_pattern: pattern = /.*gatekeeper\[[0-9]{1,8}\]./;

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

function accepted_f(data: string) : count
	{
	# Aug 20 16:35:01 128.55.46.32 sshd[14920]: Accepted publickey for root from 10.32.46.16 port 38512 ssh2
	local parts = split(data, kv_splitter);

	local pid = parts[5];
	local log_source_ip = parts[4];
	local auth_type = parts[7];
	local auth_id = parts[9];
	local orig_h = parts[11];
	# convert into bro port type
	local orig_p = fmt("%s/tcp", parts[13]);

	local month = parts[1];
	local day   = parts[2];
	local t  = parts[3];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));
print fmt("KEY ACCEPT: %s %s %s %s %s %s", auth_id, key,log_source_ip, pid, orig_h, orig_p);

	#print fmt("ACCEPT %s[%s] @ %s:%s -> %s", auth_id, auth_type, orig_h, orig_p, log_source_ip);

	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "ACCEPTED", auth_type, "DATA");
	return 0;
	}

function postponed_f(data: string) : count
	{
	# Sep 24 00:20:02 128.55.46.20 sshd[18584]: Postponed publickey for abc from 128.55.71.22 port 48329 ssh2
	local parts = split(data, kv_splitter);

	local pid = parts[5];
	local log_source_ip = parts[4];
	local auth_type = parts[7];
	local auth_id = parts[9];
	local orig_h = parts[11];
	# convert into bro port type
	local orig_p = fmt("%s/tcp", parts[13]);

	local month = parts[1];
	local day   = parts[2];
	local t  = parts[3];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));
print fmt("KEY POST: %s %s %s %s %s %s ", auth_id, key,log_source_ip, pid, orig_h, orig_p);
	#print fmt("POSTPONED %s[%s] @ %s:%s -> %s", auth_id, auth_type, orig_h, orig_p, log_source_ip);
	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "POSTPONED", auth_type, "DATA");
	return 0;
	}

function failed_f(data: string) : count
	{
	# Failed messages tend to be somewhat more complex and varried
	#  than the rest
	local f_splitter: pattern = / Failed /;

	local parts = split(data, kv_splitter);
	local parts_len = | parts |;

	local pid = parts[5];
	local log_source_ip = parts[4];
	local auth_id = parts[parts_len - 5];
	local orig_h = parts[parts_len - 3];
	local orig_p = fmt("%s/tcp",parts[parts_len - 1]);

	# Finally, for the one value in the middle, we have to do
	#  some nasty parsing ...
	local tmp_set = split(data, f_splitter);
	local tmp2_set = split(tmp_set[2], kv_splitter);

	local auth_type = tmp2_set[1];

	local month = parts[1];
	local day   = parts[2];
	local t  = parts[3];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("22/tcp"));
	local key = fmt("%s", sha1_hash(log_source_ip, pid, orig_h, orig_p));
print fmt("KEY FAIL: %s %s %s %s %s %s ", auth_id,key,log_source_ip, pid, orig_h, orig_p);

	#print fmt("FAIL   %s[%s] @ %s:%s -> %s", auth_id, auth_type, orig_h, orig_p, log_source_ip);
	event USER_CORE::auth_transaction(ts, key, cid , auth_id, log_source_ip, "SYSLOG_SSH", "AUTHENTICATION", "FAILED", auth_type, "DATA");
	return 0;
	}

# General form:
#     Aug 27 00:00:31 128.55.80.161 nim-login[30867]: user:dfgtyuio	remote-ip:67.160.111.222	msg:login
# msg data looks like:
#  43 failed-login
#   5 failed-login,invalid password format (possible break-in attempt)
#   2 failed-login,invalid username format (possible break-in attempt)
#   2 failed-login,invalid username format (possible break-in attempt),invalid password format (possible break-in attempt)
# 122 login
#

function nim_login_f(raw_data: string) : count
	{
	#print fmt("%s", raw_data);
	local parts = split(raw_data, kv_splitter);
	local sc_splitter: pattern = /:/;
	local comma_p: pattern = /,/;
	local invalid_u: pattern = /.*invalid username format.*/;
	local invalid_p: pattern = /.*invalid password format.*/;
	local action = "NULL";
	local data = "DATA";

	local log_source_ip = parts[4];

	# take the second element for the user	
	local auth_id = split(parts[6], sc_splitter)[2];
	local orig_h = split(parts[7], sc_splitter)[2];
	# just some random thing ...
	local orig_p = "38476/tcp";

	local month = parts[1];
	local day   = parts[2];
	local t  = parts[3];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local cid: conn_id = build_connid( to_addr(orig_h), to_port(orig_p), to_addr(log_source_ip), to_port("443/tcp"));

	# unpack the message part
	# first snipp off the ':'
	local msg = split(parts[8], sc_splitter)[2];
	# then generate a set split on ','
	local msg_data = split(msg, comma_p);

	if ( strcmp( msg_data[1], "login" ) == 0 ) {
		action = "ACCEPTED";
		}
	else if ( strcmp( msg_data[1], "failed-login") == 0 ) {
		action = "FAILED";
		}

	# this will only match in the situation where there is additional info in the msg_data blocks
	if ( |parts| > 10 ) {
		data = "";

		if ( invalid_u == raw_data )
			data = fmt("%s%s", data, "INVALID_USER_FORMAT");	

		if ( invalid_p == raw_data )
			data = fmt("%s %s", data, "INVALID_PASWD_FORMAT");	
	
		}

	#print fmt("NIM_AUTH   %s %s PASSWD %s %s", auth_id, log_source_ip, action, data);
	event USER_CORE::auth_transaction(ts, "NULL", cid , auth_id, log_source_ip, "SYSLOG_NIM", "AUTHENTICATION", action, "PASSWORD", data);

	return 0;
	}
# Oct  5 19:32:15 128.55.81.150 BROEVENT USER_DATA 1381026735.000000 client newt shuber "<bound method QueueResourceAdapter.method_proxy of <newt.queue.v ...
#
function nersc_sec_api_f(data: string) : count
	{
	print fmt("SEC API: %s", data);
	local be_pattern: pattern = /" BROEVENT "/;	


	return 0;
	}

function gatekeeper_f(data: string) : count
	{
	# this one is a little different in that the record generation is stateful because of the 
	#   nulti-line nature of the raw data
	# We can break this put into it's own file in time
	#
	local gc_p1: pattern = /.* Got connection.*/;			# Init the data struct
	local gc_p2: pattern = /.* Requested service:.*/;		# ok
	local gc_p3: pattern = /.* Authorized as local user:.*/;	# ok
	local gc_p4: pattern = /.* Authorized as local uid:.*/;		# ok
	local gc_p5: pattern = /.*   and local gid:.*/; 		# Normal exit point
	local gc_p6: pattern = /.* Authenticated globus user.*/;	# id globus user
	local gc_p7: pattern = /.*failed authorization.*/;

	local parts = split(data, kv_splitter);

	local log_source_ip = parts[4];
	#local auth_type = parts[7];
	#local auth_id = parts[9];
	#local orig_h = parts[11];
	#local orig_p = parts[13];

	local month = parts[1];
	local day   = parts[2];
	local t  = parts[3];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	local pid = split_all( data, pid_pattern )[2] ;
	local key = fmt("%s%s", pid, log_source_ip);

	local t_gcr: gatekeeperRec;
	local record_mod = 0;
	local flush_value = 0;


	# lookup state structure
	if ( key !in gc_table ) {
		# new struct
		t_gcr$start = ts;
		t_gcr$log_source_ip = log_source_ip;
		}
	else
		t_gcr = gc_table[key];

	# Now begin processing the input data
	if ( gc_p1 == data ) {		# /.* Got connection .*/
		# form: ... Got connection A.B.C.D ...
		# extract the connecting IP

		local tmp_pat: pattern = /"Got connection "/;
		local t_p = split_all(data, tmp_pat)[3]; 	 # snip off IP and trailing
		local t_ip = split(t_p, kv_splitter)[1]; # remove trailing

		t_gcr$orig_h = t_ip;
		record_mod = 1;
		}
	else if ( gc_p2 == data ) {	# /.* Requested service:.*/
		t_gcr$service = parts[ |parts| -1  ];

		record_mod = 1;
		}
	else if ( gc_p3 == data ) {	# /.* Authorized as local user:.*/
		t_gcr$l_user = parts[ |parts| ];

		record_mod = 1;
		}
	else if ( gc_p4 == data ) {	# /.* Authorized as local uid:.*/
		t_gcr$l_uid = to_count(parts[ |parts| ]);

		record_mod = 1;
		}
	else if ( gc_p5 == data ) {	# /.*   and local gid:.*/
		t_gcr$l_gid = to_count(parts[ |parts| ]);
		t_gcr$success = "ACCEPTED";

		record_mod = 1;
		flush_value = 1;
		}
	else if ( gc_p6 == data ) {	# /.* Authenticated globus user:.*/
		# since the record can contain multiple spaces, we snip on the RE
		local tmp_pat2: pattern = /" Authenticated globus user: "/;
		local t_id = split_all(data, tmp_pat2)[3];	

		t_gcr$g_user = t_id;

		record_mod = 1;
		}
	else if ( gc_p7 == data ) {	# ERROR 
		# this might be a bit messy as the assumption is that all 
		#  error messages (of this form) are well behaved...
		# for the time being we can split on the general handler 	

		local tmp_pat3: pattern = /"globus_gss_assist: "/;
		t_gcr$error_msg = split_all(data, tmp_pat3)[3];
		t_gcr$success = "FAILED";

		record_mod = 1;
		flush_value = 1;
		}
	else {
		# unknown line - skip for now
		}


	if ( record_mod == 1 )
		gc_table[key] = t_gcr;

	if ( flush_value == 1 ) {
		# write to spesific globus log
		Log::write(LOG, t_gcr);

		# then figure something out to give to the central authwatch
		#
		local cid: conn_id = build_connid( to_addr(t_gcr$orig_h), to_port("0/tcp"), to_addr(t_gcr$log_source_ip), to_port("0/tcp"));
		event USER_CORE::auth_transaction(t_gcr$start, "NULL", cid , t_gcr$l_user, t_gcr$log_source_ip, "GATEKEEPER", "AUTHENTICATION", t_gcr$success, "GLOBUS", t_gcr$g_user);

		}

	return 0;
	}


redef dispatcher += {
	["ACCEPTED"] = accepted_f,
	["POSTPONED"] = postponed_f,
	["FAILED"] = failed_f,
	["NIM_LOGIN"] = nim_login_f,
	["BROEVENT"] = SYSLOG_SECAPI::secapi_f,
	["GATEKEEPER"] = gatekeeper_f,
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


event line(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
	# Each line is fed to this event where it is digested and sent to the dispatcher 
	#  for appropriate processing
	# 
	#  Sep 21 00:13:45 128.55.58.73 sshd[21332]: Accepted publickey for ewiedner from 128.55.58.77 port 54641 ssh2
	#  Sep 20 12:42:51 128.55.22.194 httpd[21838]: nersc.gov 128.55.22.8 - - [20/Sep/2013:12:42:51 -0700] "GET /lbstatus HTTP/1.0" 301 238 "-" "-"
	#
	++input_count;

	local parts = split(LV$d, kv_splitter);
	local event_name = "NULL";
	local event_action = "NULL";

	if ( |parts| < 6 )
		return;

	event_name = parts[5];
	event_action = to_upper(parts[6]);

	if ( sshd_pattern == event_name ) {
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
                }
        }

event start_reader()
        {
        if ( stop_sem == 1 ) {
		#print fmt("%s          start-reader", gethostname());
                Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::TSTREAM, $name="syslog", $fields=lineVals, $ev=line]);
                stop_sem = 0;
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
        print fmt("%s SYSLOG Log delta: %s", network_time(),input_count_delta);

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
	if ( DATANODE && (file_size(data_file) != -1.0) ) {
		Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::TSTREAM, $name="syslog", $fields=lineVals, $ev=line]);

		# start rate monitoring for event stream
		schedule input_test_interval { sys_transaction_rate() };
		}

	Log::create_stream(SYSLOG_PARSE::LOG, [$columns=gatekeeperRec]);
	return 0;
	}

event bro_init()
	{
	event set_year();
	init_datastream();
	}



