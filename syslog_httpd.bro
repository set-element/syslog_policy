#
#

@load syslog_policy/syslog_core_fluentd

module SYSLOG_HTTPD;

export {

	redef enum Log::ID += { LOG };

        global kv_splitter: pattern = /[\ \t]+/;
        global one_space: string = " ";
        const pid_pattern: pattern = /\[[0-9]{1,6}\]/;
	const year = 2014;

        type HTTP_REQ: record {
                ts: time &log;
                logip: string &log &default= "NULL";
                domain: string &log &default="NULL";
                cip: addr &log &default = 127.0.0.0;
                ident: string &log &default = "NULL";
                uid: string &log &default = "NULL";
                method: string &log &default = "NULL";
                request: string &log &default = "NULL";
                referrer: string &log &default = "NULL";
                stat_code: count &log &default = 0;
                data: string &log &default = "-";
                };

	global httpd_f: function(data: string) : count;

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


function httpd_log_f(data: string) : count
        {
        # Nov 11 19:09:49 128.55.22.195 httpd[25994]: www.nersc.gov 72.33.232.45 - - [11/Nov/2014:19:09:49 -0800]
        # "GET /sapphire/javascript/Validator.js?m=1305666528 HTTP/1.1" 304 - "https://www.nersc.gov/users/live-status/"
        # "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:33.0) Gecko/20100101 Firefox/33.0"
        # IP , ident, userid of auth requestor, time finished processing request, "REQUEST", stat code , response size, "referrer", "client"
        local t_HTTP_REQ: HTTP_REQ;

        # split on space
        local parts_space = split_string(data, kv_splitter);
        # split on "
        local parts_quote = split_string(data, /\"/);

        local log_source_ip = parts_space[3];
        local domain_name = parts_space[5];
        local client_ip = parts_space[6];
        local ident = parts_space[7];
        local uid = parts_space[8];

        local request = parts_quote[1];
        local referrer = parts_quote[3];
        local client = parts_quote[5];

        local sq = split_string(strip(parts_quote[2]), kv_splitter);
        local stat_code = sq[0];
        local resp_size = sq[1];

        local sq2 = split_string( parts_quote[1], kv_splitter);
        local method = sq2[0];

        local month = parts_space[0];
        local day   = parts_space[1];
        local t  = parts_space[2];
        local timestamp = fmt("%s %s %s", month, day, t);
        local ts = time_convert(timestamp);

        t_HTTP_REQ$ts = ts;
        t_HTTP_REQ$logip = log_source_ip;
        t_HTTP_REQ$domain = domain_name;
        t_HTTP_REQ$cip = to_addr(client_ip);
        t_HTTP_REQ$ident = ident;
        t_HTTP_REQ$uid = uid;
        t_HTTP_REQ$method = method;
        t_HTTP_REQ$request = request;
        t_HTTP_REQ$referrer = referrer;
        t_HTTP_REQ$stat_code = to_count(stat_code);
        t_HTTP_REQ$data = resp_size;
	# print fmt("DS: %s", t_HTTP_REQ);
        Log::write(LOG, t_HTTP_REQ);

        return 0;
        }

function httpd_error_f(data: string): count
	{
	# Nov 29 19:59:41 128.55.71.63 httpd[7101]: [error] ap_proxy_connect_backend disabling worker for (localhost)

	return 0;
	}

function httpd_f(data: string) : count
	{
	local error_log: pattern = /.*\[error\].*/;
        local parts_space = split_string(data, kv_splitter);

	# route log vs error
	if ( error_log == parts_space[5] ) {
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
