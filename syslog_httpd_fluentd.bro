#
#

@load syslog_policy/syslog_core_fluentd
@load policy/protocols/http/detect-sqli

module SYSLOG_HTTPD;

export {

	redef enum Log::ID += { LOG };

        global kv_splitter: pattern = /[\ \t]+/;
        global tab_splitter: pattern = /[\t]+|\\x09/;
        global space_splitter: pattern = /[\ ]+/;
        global one_space: string = " ";
	const year = 2016;

        type HTTP_REQ: record {
                ts: time &log;
                logip: string &log &default= "NULL";
                #cip: addr &log &default = 127.0.0.0;
                cip: string &log &default = "NULL";
                ident: string &log &default = "NULL";
                uid: string &log &default = "NULL";
                domain: string &log &default="NULL";
                method: string &log &default = "NULL";
                request: string &log &default = "NULL";
                referrer: string &log &default = "NULL";
                stat_code: count &log &default = 0;
		flags: string &log &default = "NULL";
                data: string &log &default = "-";
                };

	global httpd_f: function(data: string) : count;

	} # end export

function get_data(data: string) : string
        {
		local ret_val: string_vec;
		local delim: pattern = /:/;

		ret_val = split_string1(data, delim);

		return ret_val[1];
        }

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

function http_test_sqli(request: string) : string
	{
	local ret_val = "NULL";

	# this is taken full cloth from the sqli injection detect 
	# convert request to unescaped form
	local u_request = unescape_URI(request);

	if ( HTTP::match_sql_injection_uri in u_request )
                {
		ret_val = "SQLI_HTTP";	
		}

	return ret_val;
	}

function httpd_log_f(data: string) : count
        {
        # time:Apr 23 00:00:03	
	# host:128.55.193.38	
	# ident:httpd	
	# pid:63592	
	# message:www.nersc.gov 128.55.6.33 - - [23/Apr/2016:11:46:59 -0700] "GET /science/hpc-...ark-jarrell/ 
	# 	HTTP/1.0" 404 22554 "-" "gsa-crawler (Enterprise; M2-A3SPM2JL6LWAA; server-team@nersc.gov)"
        # 
        # IP , ident, userid of auth requestor, time finished processing request, "REQUEST", stat code , response size, "referrer", "client"

        local t_HTTP_REQ: HTTP_REQ;

	# split data up in a variety of ways
	local parts_tab = split_string( data, tab_splitter);
	local time_parts = split_string( get_data(parts_tab[0]), space_splitter );

	local msg_raw = get_data( parts_tab[4] );
	local msg_space = split_string( msg_raw, space_splitter);
        local msg_quote = split_string( msg_raw, /\"/);

	# do a little sanity checking here cause if these are not right, the data 
	#  will not be worth looking at
	if ( |parts_tab| < 5 )
		return 1;

	if ( |msg_quote| < 5 )
		return 1;

	# sometimes there are more fields than others,  which is kinda frustrating
	#  here the domain name is only there when it feels like.  This is the
	#  duct tape that binds ...
        local domain_name = "NO_DOMAIN";
	local offset = 0;
	local t_offtest = split_string1( msg_raw, /\[/)[0];
	local offset_test = | split_string( t_offtest, space_splitter) |;

	if ( offset_test == 5 ) {
		offset = 1;
		domain_name = msg_space[0];
 		}

        local log_source_ip = get_data( parts_tab[1] );
        local client_ip = msg_space[0+offset];
        local ident = msg_space[1+offset];
        local uid = msg_space[2+offset];

        local request = split_string1(msg_quote[1], space_splitter)[1];
        local referrer = msg_quote[3];
        local client = msg_quote[5];

        local sub_query = split_string(strip(msg_quote[2]), space_splitter);
        local stat_code = sub_query[0];
        local resp_size = sub_query[1];

        local sub_query2 = split_string( msg_quote[1], kv_splitter);
        local method = sub_query2[0];

	local month = time_parts[0];
	local day   = time_parts[1];
	local t  = time_parts[2];
	local timestamp = fmt("%s %s %s", month, day, t);
	local ts = time_convert(timestamp);

	# This kinda sucks
	if ( strcmp(ident,"\x2d") == 0 )
		ident = "NULL";

	if ( strcmp(uid,"\x2d") == 0 )
		uid = "NULL";

	if ( strcmp(referrer,"\x2d") == 0 )
		referrer = "NULL";

        t_HTTP_REQ$ts = ts;
        t_HTTP_REQ$logip = log_source_ip;
        t_HTTP_REQ$domain = domain_name;
        t_HTTP_REQ$cip = client_ip;
        #t_HTTP_REQ$cip = to_addr(client_ip);
        t_HTTP_REQ$ident = ident;
        t_HTTP_REQ$uid = uid;
        t_HTTP_REQ$method = method;
        t_HTTP_REQ$request = request;
        t_HTTP_REQ$referrer = referrer;
        t_HTTP_REQ$stat_code = to_count(stat_code);
        t_HTTP_REQ$data = resp_size;
	t_HTTP_REQ$flags = http_test_sqli(request);
	# print fmt("DS: %s", t_HTTP_REQ);
        Log::write(LOG, t_HTTP_REQ);

        return 0;
        }

function httpd_error_f(data: string): count
	{
	# need to work on this
	# Nov 29 19:59:41 128.55.71.63 httpd[7101]: [error] ap_proxy_connect_backend disabling worker for (localhost)

	return 0;
	}

function httpd_f(data: string) : count
	{
	local error_log: pattern = /.*\[error\].*/;
        local parts_space = split_string(data, tab_splitter);
	local msg_parse = split_string( parts_space[4], space_splitter );
if ( |parts_space| < 4 )
	print fmt("error state for function httpd_f: %s", data);
	# route log vs error
	if ( error_log == msg_parse[0] ) {
		httpd_error_f(data);
		}
	else {
		httpd_log_f(data);
		}

	return 0;
	}

event bro_init()
{
	Log::create_stream(SYSLOG_HTTPD::LOG, [$columns=HTTP_REQ]);
	local filter_c: Log::Filter = [$name="default", $path="syslog_httpd"];
	Log::add_filter(LOG, filter_c);
}
