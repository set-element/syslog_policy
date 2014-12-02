#
#

@load SyslogReader/syslog_core.bro
@load SyslogReader/syslog_consts

module SYSLOG_SECAPI;

export {

	redef enum Log::ID += { LOG };

        global kv_splitter: pattern = /[\ \t]+/;
        global one_space: string = " ";
        const pid_pattern: pattern = /\[[0-9]{1,6}\]/;
	const year = 2014;

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
		
		event_h:string &log &default="null";
		event_p1:string &log &default="null";
		event_p2:string &log &default="null";
		};	

	global secapi_f: function(data: string) : count;

	# table of functions mapped by the line type
	const dispatcher: table[string] of function(_data: string): count &redef;

	} # end export

function time_convert(data: string) : time
        {
        # the string converter seems to be slightly os dependant.
        # linux:
        local parse_string: string = "%y %b %d %t";
        # freebsd:
        #local parse_string: string = "%z %y %b %d %h:%m:%s";
        local date_mod = "null";

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

function user_auth_f(data: string): count
	{
	# user_auth(time, service, uid, result, method, message)
	# Nov 26 04:45:38 128.55.81.150 <EF><BB><BF>BROEVENT USER_AUTH 1417005938.000000 newt angela 1 0 NOMESSAGE
	# Fill in time info
	local t_SAPI_REQ: SAPI_REQ;
	local parts_space = split(data, kv_splitter);

        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
	local eventTime = parts_space[7];
	local eventService = parts_space[8];
	local eventUid = parts_space[9];
	local eventResult = sapi_auth_res[to_count(parts_space[10])];
	local eventMethod = sapi_auth_meth[to_count(parts_space[11])];
	local eventMessage = parts_space[12];

	t_SAPI_REQ$ts = ts;
	t_SAPI_REQ$ftype = parts_space[6];
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
	# Nov 26 00:00:12 128.55.81.150 
	# BROEVENT USER_DATA 1416988812.000000 client newt joalbert "<bound method NimAdapter.get of <newt.account.views.NimAdapter object at 0x7fb4b1074750>>", "()", "{'path': u'/user/yundi/persons'}"
	local t_SAPI_REQ: SAPI_REQ;
	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];

	local eventTime = parts_space[7];
	local eventDirection = parts_space[8];
	local eventService = parts_space[9];
        local eventUid = parts_space[10];
	local data_q = split(data, /\"/);
	local eventData = fmt("%s %s %s", data_q[2], data_q[4], data_q[6]);

        t_SAPI_REQ$ts = ts;
        t_SAPI_REQ$ftype = parts_space[6];
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

	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
	return 0;
	}

function port_forward_f(data: string): count
	{

	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
	return 0;
	}

function connection_event_f(data: string): count
	{

	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
	return 0;
	}

function job_submission_f(data: string): count
	{

	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
	return 0;
	}

function service_register_f(data: string): count
	{

	local parts_space = split(data, kv_splitter);
	# Fill in time info
        local month = parts_space[1];
        local day   = parts_space[2];
        local t  = parts_space[3];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        local log_source_ip = parts_space[4];
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
        local t_SAPI_REQ: SAPI_REQ;

        # split on space
        print fmt("in secapi_f: %s", data);
        local parts_space = split(data, kv_splitter);
	local fname = to_upper(parts_space[6]);
	print fmt("parsed val: %s", fname);
	dispatcher[fname](data);

        return 0;
        }

event bro_init()
{
	Log::create_stream(SYSLOG_SECAPI::LOG, [$columns=SAPI_REQ]);
}
