# Globus Syslog analyzer
# Analyzer for gatekeeper and my-proxy system logs
#

module SYSLOG_GLOBUS;

export {

	# for SYSLOG_GLOBUS logging stream
	redef enum Log::ID += { LOG };
	redef enum Log::ID += { LOG2 };

	global kv_splitter: pattern = /[\ \t]+/;
	global space_split: pattern = /[\ ]+/;
	global tab_split: pattern = /[\t]/;
	global one_space: string = " ";

	# for gatekeeper we need a data structure to hold state as info is built up
	type gatekeeperRec: record {
		start: time &log &default = double_to_time(0.000000);
		dt: double &log &default = 0.000000;
		# orig_h is the syslog source
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

	type myproxyRec: record {
		start: time &log &default = double_to_time(0.000000);
		dt: double &log &default = 0.000000;
		#
		orig_h: string &log &default = "127.127.127.127"; # requestor address
		log_source_ip: string &log &default = "127.127.127.127";
		max_cert_lifetime: count &log &default=0;
		request: string &log &default="NULL";
		username: string &log &default="NULL";
		#
		cert_request_hash: string &log &default="NULL";
		cert_request_lifetime: count &log &default=0;
		cert_issue_lifetime: count &log &default=0;
		cert_issue_DN: string &log &default="NULL";
		#
		auth: string &log &default="NULL";
		auth_err_msg: string &log &default="NULL";
		}

	#  indexed by [resp_h,pid] => string
	global gc_table: table[string] of gatekeeperRec;

	#  indexed by [resp_h,pid] => string
	global mp_table: table[string] of myproxyRec;

	global myproxy_f: function(data: string) : count;
	global globus_f: function(data: string) : count;

	} # end export

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

function myproxy_f( data: string) : count
	{
		# --------------------------------------------------------- #
		local mp_p0: pattern = /^myproxy-server.*/;					# init
		local mp_p1: pattern = /^max certificate lifetime.*/;		# cert max lifetime
		local mp_p2: pattern = /^Connection from.*/;				# external host
		local mp_p3: pattern = /^Received.*/;						# request < > for user < >
		# --------------------------------------------------------- #
		local mp_p4: pattern = /^PAM authentication succeeded.*/;	# auth = T
		local mp_p5: pattern = /^Got a cert request for user.*/;	# uid, hash, lifetime
		local mp_p6: pattern = /^Issued certificate for user.*/;	# DN for cert
		# --------------------------------------------------------- #
		local mp_p7: pattern = /^Exiting:.*/;						# error message
		# --------------------------------------------------------- #
		local parts = split_string(data, tab_split);
		local time_parts = split_string( get_data(parts[0]), space_split );

		local pid = get_data(parts[3]);
		local log_source_ip = get_data(parts[1]);

		local month = time_parts[0];
		local day   = time_parts[1];
		local t  = time_parts[2];
		local timestamp = fmt("%s %s %s", month, day, t);
		local ts = time_convert(timestamp);

		local key = fmt("%s%s", pid, log_source_ip);

		local t_mpr: myproxyRec;
		local record_mod = 0;
		local flush_value = 0;

		# lookup state structure
		if ( key !in mp_table ) {
			# new struct
			t_mpr$start = ts;
			t_mpr$log_source_ip = log_source_ip;
			}
		else
			t_mpr = mp_table[key];

		# Now begin processing the input data
		local msg_data = get_data(parts[4]);
		local msg_data_parts = split_string(msg_data, space_split);

		if ( mp_p0 == msg_data ) {	# /^myproxy-server.*/
			# sample: myproxy-server v6.1 ....
			# just use to init the data struct
			record_mod = 1;
			}
		else if ( mp_p1 == msg_data ) {	# /^max certificate lifetime.*/;
			# max certificate lifetime: 997200 seconds
			t_mpr$max_cert_lifetime = to_count(msg_data_parts[3]);
			record_mod = 1;
			}
		else if ( mp_p2 == msg_data ) {	# /^Connection from.*/
			# Connection from 174.129.226.69
			t_mpr$orig_h = msg_data_parts[2];
			record_mod = 1;
			}
		else if ( mp_p3 == msg_data ) {	# /^Received.*/;
			# Received GET request for username userabc
			t_mpr$request = msg_data_parts[1];
			t_mpr$username = msg_data_parts[5];
			record_mod = 1;
			}
		else if ( mp_p4 == msg_data ) {	# /^PAM authentication succeeded.*/;
			# PAM authentication succeeded for userabc
			t_mpr$auth = "T";
			record_mod = 1;
			}
		else if ( mp_p5 == msg_data ) {	# /^Got a cert request for user.*/
			# Got a cert request for user "userabc", with pubkey hash "0x103ad383", and lifetime "86400"
			# parse one more time on " character
			local msg_data_q5 = split_string(msg_data, /\"/);

			t_mpr$cert_request_hash = msg_data_q5[3];
			t_mpr$cert_request_lifetime = msg_data_q5[5];
			record_mod = 1;
			}
		else if ( mp_p6 == msg_data ) {	# /^Issued certificate for user.*/
			# Issued certificate for user "danielsf", with DN "/DC=gov/DC=nersc/OU=People/CN=Scott Daniel 58711", lifetime "86400", and serial number "0x9B:F3"
			# parse one more time on " character
			local msg_data_q6 = split_string(msg_data, /\"/);

			t_mpr$cert_issue_lifetime = msg_data_q6[5]
			t_mpr$cert_issue_DN = msg_data_q6[3];
			record_mod = 1;
			flush_value = 1;
			}
		else if ( mp_p7 == msg_data ) {	# /^Exiting:.*/
			# Exiting: Mapping call-out returned error Expired unknown username: emorin
			# invalid password
			t_mpr$auth = "F";
			local error = "":

			if ( |msg_data_parts| > 2 ) {
				error = "ERR_UNKNOWN_USR";
				}
			else {
				error = "ERR_INVALID_PASS";
				}

			t$mpr$auth_err_msg = error;

			record_mod = 1;
			flush_value = 1;
			}

		if ( record_mod == 1 )
			mp_table[key] = t_mpr;

		if ( flush_value == 1 ) 	{
			# write to spesific globus log
			Log::write(LOG2, t_mpr);
			# get rid of the table value
			delete mp_table[key];

			# then figure something out to give to the central authwatch
			#
			local cid: conn_id = build_connid( to_addr(t_gcr$orig_h), to_port("0/tcp"), to_addr(t_gcr$log_source_ip), to_port("0/tcp"));
			event USER_CORE::auth_transaction(t_mpr$start, "NULL", cid , t_mpr$username, t_mpr$log_source_ip, "GATEKEEPER", "AUTHENTICATION", t_gcr$success, "GLOBUS", t_gcr$g_user);

			}

	}

function gatekeeper_f(data: string) : count
	{
		# this one is a little different in that the record generation is stateful because of the
		#   nulti-line nature of the raw data
		# We can break this put into it's own file in time
		#
		local gc_p1: pattern = /.* Got connection.*/;				# Init the data struct
		local gc_p2: pattern = /.* Requested service:.*/;			# ok
		local gc_p3: pattern = /.* Authorized as local user:.*/;	# ok
		local gc_p4: pattern = /.* Authorized as local uid:.*/;		# ok
		local gc_p5: pattern = /.*   and local gid:.*/; 			# Normal exit point
		local gc_p6: pattern = /.* Authenticated globus user.*/;	# id globus user
		local gc_p7: pattern = /.*failed authorization.*/;

		local parts = split_string(data, tab_split);
		local time_parts = split_string( get_data(parts[0]), space_split );

		local pid = get_data(parts[3]);
		local log_source_ip = get_data(parts[1]);

		local month = time_parts[0];
		local day   = time_parts[1];
		local t  = time_parts[2];
		local timestamp = fmt("%s %s %s", month, day, t);
		local ts = time_convert(timestamp);

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
		local msg_data = get_data(parts[4]);

		if ( gc_p1 == msg_data ) {		# /.* Got connection .*/
			# form: ... Got connection A.B.C.D ...
			# extract the connecting IP

			local tmp_pat: pattern = /"Got connection "/;
			local t_p = split_string_all(msg_data, tmp_pat)[2]; 	 # snip off IP and trailing
			local t_ip = split_string(t_p, kv_splitter)[0]; # remove trailing

			t_gcr$orig_h = t_ip;
			record_mod = 1;
			}
		else if ( gc_p2 == msg_data ) {	# /.* Requested service:.*/
			t_gcr$service = parts[ |parts| - 2  ];

			record_mod = 1;
			}
		else if ( gc_p3 == msg_data ) {	# /.* Authorized as local user:.*/
			t_gcr$l_user = parts[ |parts| - 1 ];

			record_mod = 1;
			}
		else if ( gc_p4 == msg_data ) {	# /.* Authorized as local uid:.*/
			t_gcr$l_uid = to_count(parts[ |parts| - 1 ]);

			record_mod = 1;
			}
		else if ( gc_p5 == msg_data ) {	# /.*   and local gid:.*/
			t_gcr$l_gid = to_count(parts[ |parts| - 1 ]);
			t_gcr$success = "ACCEPTED";

			record_mod = 1;
			flush_value = 1;
			}
		else if ( gc_p6 == msg_data ) {	# /.* Authenticated globus user:.*/
			# since the record can contain multiple spaces, we snip on the RE
			local tmp_pat2: pattern = /" Authenticated globus user: "/;
			local t_id = split_string_all(msg_data, tmp_pat2)[2];

			t_gcr$g_user = t_id;

			record_mod = 1;
			}
		else if ( gc_p7 == msg_data ) {	# ERROR
			# this might be a bit messy as the assumption is that all
			#  error messages (of this form) are well behaved...
			# for the time being we can split on the general handler

			local tmp_pat3: pattern = /"globus_gss_assist: "/;
			t_gcr$error_msg = split_string_all(data, tmp_pat3)[2];
			t_gcr$success = "FAILED";

			record_mod = 1;
			flush_value = 1;
			}
		else {
			# unknown line - skip for now
			}


		if ( record_mod == 1 )
			gc_table[key] = t_gcr;

		if ( flush_value == 1 ) 	{
			# write to spesific globus log
			Log::write(LOG, t_gcr);
			delete gc_table[key];

			# then figure something out to give to the central authwatch
			#
			local cid: conn_id = build_connid( to_addr(t_gcr$orig_h), to_port("0/tcp"), to_addr(t_gcr$log_source_ip), to_port("0/tcp"));
			event USER_CORE::auth_transaction(t_gcr$start, "NULL", cid , t_gcr$l_user, t_gcr$log_source_ip, "GATEKEEPER", "AUTHENTICATION", t_gcr$success, "GLOBUS", t_gcr$g_user);

			}

	return 0;
	}

event bro_init()
	{
	Log::create_stream(SYSLOG_GLOBUS::LOG, [$columns=gatekeeperRec]);
	local filter_c: Log::Filter = [$name="default", $path="gatekeeper"];
	Log::add_filter(LOG, filter_c);

	Log::create_stream(SYSLOG_GLOBUS::LOG2, [$columns=gatekeeperRec]);
	local filter_c2: Log::Filter = [$name="default", $path="myproxy"];
	Log::add_filter(LOG2, filter_c2);

	}
