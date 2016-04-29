#
#

@load syslog_policy/syslog_core_fluentd
@load syslog_policy/syslog_consts

module SYSLOG_SECAPI;

export {

	redef enum Log::ID += { LOG };

        global kv_splitter: pattern = /[\ \t]+/;
	global space_split: pattern = /[\ ]+/;
	global tab_split: pattern = /[\t]/;
        global one_space: string = " ";

	const year = 2016;

	# Nov 26 00:00:12 128.55.81.150 
	# BROEVENT USER_DATA 1416988812.000000 client newt joalbert "<bound method NimAdapter.get of <newt.account.views.NimAdapter object at 0x7fb4b1074750>>", "()", "{'path': u'/user/jdeslip/persons'}"
	#  Since the data provided could be almost anything, start with a string for logging, then convert per function type.
	#
        type SAPI_REQ: record {
		# default syslog parameters
                ts: time &log;
                logip: string &log &default= "NULL";
		# SecAPI spesific bits
		ftype: string &log &default="NULL";
		api_ts: string &log;
		service: string &log &default="NULL";
		uid: string &log &default="NULL";
		
		direction:string &log &default="NULL";
		ret_code:string &log &default="NULL";
		data1:string &log &default="NULL";
		data2:string &log &default="NULL";
		data3:string &log &default="NULL";
		
		event_h:string &log &default="NULL";
		event_p1:string &log &default="NULL";
		event_p2:string &log &default="NULL";
		};	

	global secapi_f: function(data: string) : count;

	# table of functions mapped by the line type
	const dispatcher: table[string] of function(_data: string): count &redef;

	} # end export

function time_convert(data: string) : time
        {
        # the string converter seems to be slightly os dependant.
        # linux:
        local parse_string: string = "%Y %B %d %T";
        # freebsd:
        #local parse_string: string = "%Z %Y %b %d %H:%M:%S";
        local date_mod = "NULL";

        # first convert the string to a known quantity
        # like parse_string, we can get away with not having the
        #   time zone in the equsn.
        # linux:
        date_mod = fmt("%s %s", year,data);
        # freebsd
        #date_mod = fmt("%s %s %s", tzone,year,data);

        # second, make sure that any extra spaces in the date string are expunged...
        local date_mod_p = gsub(date_mod, kv_splitter, one_space);

        local ret_val = strptime(parse_string, date_mod_p);

        return ret_val;
        }

function get_data(data: string) : string
        {
		local ret_val: string_vec;
		local delim: pattern = /:/;

		ret_val = split_string1(data, delim);

		return ret_val[1];
        }


function user_auth_f(data: string): count
	{
	# user_auth(time, service, uid, result, method, message)
	# Apr 29 11:10:31 128.55.210.141 BROEVENT USER_AUTH 1461953431.000000 newt rthomas 1 0 NOMESSAGE
	# Fill in time info
	local t_SAPI_REQ: SAPI_REQ;

	local data_parts = split_string(data, tab_split);
	local msg_data = get_data(data_parts[3]);
	local msg_parts = split_string(msg_data, space_split);
	local time_parts = split_string( get_data(data_parts[0]), space_split );

        local month = time_parts[0];
        local day   = time_parts[1];
        local t  = time_parts[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);
	print fmt("UD timestamp: %s conv: %s", timestamp, ts);

        local log_source_ip = get_data(data_parts[1]);

	local eventTime = msg_parts[1];
	local eventService = msg_parts[2];
	local eventUid = msg_parts[3];
	local eventResult = sapi_auth_res[to_count( msg_parts[4])];
	local eventMethod = sapi_auth_res[to_count( msg_parts[5])];
	local eventMessage =  msg_parts[6];

	t_SAPI_REQ$ts = ts;
	t_SAPI_REQ$logip = log_source_ip;
	t_SAPI_REQ$ftype =  msg_parts[0];
	t_SAPI_REQ$api_ts = eventTime;
	t_SAPI_REQ$service = eventService;
	t_SAPI_REQ$uid = eventUid;
	t_SAPI_REQ$ret_code = eventResult;
	t_SAPI_REQ$data1 = eventMethod;
	t_SAPI_REQ$data2 = eventMessage;

	print fmt("OUT: %s", t_SAPI_REQ);
	Log::write(LOG, t_SAPI_REQ);
	return 0;
	}

function user_data_f(data: string): count
	{
	# user_data(time, direction, service, uid, data)
	# time:Apr 29 12:34:15	host:128.55.210.141	ident:BROEVENT	message:USER_DATA 1461958455.000000 client newt tjiani "<bound 7c90>>", "()", "{'path': u'/user/persons'}"
	local t_SAPI_REQ: SAPI_REQ;
	local data_parts = split_string(data, tab_split);
	local msg_data = get_data(data_parts[3]);
	local msg_parts = split_string(msg_data, space_split);
	local time_parts = split_string( get_data(data_parts[0]), space_split );

        local month = time_parts[0];
        local day   = time_parts[1];
        local t  = time_parts[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);
	print fmt("UD timestamp: %s conv: %s", timestamp, ts);

        local log_source_ip = get_data(data_parts[1]);

	local eventTime = msg_parts[1];
	local eventDirection = msg_parts[2];
	local eventService = msg_parts[3];
        local eventUid = msg_parts[4];
	local data_q = split_string(msg_data, /\"/);
	local eventData = fmt("%s %s %s", data_q[1], data_q[3], data_q[5]);

        t_SAPI_REQ$ts = ts;
        t_SAPI_REQ$logip = log_source_ip;
        t_SAPI_REQ$ftype = msg_parts[0];
        t_SAPI_REQ$api_ts = eventTime;
        t_SAPI_REQ$service = eventService;
        t_SAPI_REQ$uid = eventUid;
        t_SAPI_REQ$direction = eventDirection;
        t_SAPI_REQ$data1 = eventData;

	print fmt("OUT: %s", t_SAPI_REQ);
	Log::write(LOG, t_SAPI_REQ);
	return 0;
	}

function user_exec_f(data: string): count
	{

	local parts_space = split_string(data, kv_splitter);
	# Fill in time info
        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[3];
	return 0;
	}

function port_forward_f(data: string): count
	{

	local parts_space = split_string(data, kv_splitter);
	# Fill in time info
        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[3];
	return 0;
	}

function connection_event_f(data: string): count
	{

	local parts_space = split_string(data, kv_splitter);
	# Fill in time info
        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[3];
	return 0;
	}

function job_submission_f(data: string): count
	{

	local parts_space = split_string(data, kv_splitter);
	# Fill in time info
        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[3];
	return 0;
	}

function service_register_f(data: string): count
	{

	local parts_space = split_string(data, kv_splitter);
	# Fill in time info
        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[3];
	return 0;
	}

redef dispatcher += {
        ["USER_AUTH"] = user_auth_f,
        ["USER_DATA"] = user_data_f,
        ["USER_EXEC"] = user_exec_f,
        ["PORT_FORWARD"] = port_forward_f,
        ["CONNECTION_EVENT"] = connection_event_f,
        ["JOB_SUBMISSION"] = job_submission_f,
        ["SERVICE_REGISTER"] = service_register_f,
        };

# Interface/routing function to hand off the SEC_API call based on the ftype value
function secapi_f(data: string) : count
        {
	# time: XXX host:128.55.210.141	ident:BROEVENT	message:USER_DATA 1461939274.000000 client newt mcurcic "<bound method NimAdapter.get of ... , "()", "{'path': u'/user/aspencer/persons'}"
        local t_SAPI_REQ: SAPI_REQ;

        # split on space
	local data_parts = split_string(data, tab_split);
	local msg_data = get_data(data_parts[3]);
	local msg_parts = split_string( msg_data, space_split);
	local fname = to_upper(msg_parts[0]);

	if ( fname in dispatcher )
		dispatcher[fname](data);

        return 0;
        }

event bro_init()
{
	Log::create_stream(SYSLOG_SECAPI::LOG, [$columns=SAPI_REQ]);
	local filter_c: Log::Filter = [$name="default", $path="syslog_secapi"];
	Log::add_filter(LOG, filter_c);
}
