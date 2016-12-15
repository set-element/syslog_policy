@load syslog_policy/syslog_core_fluentd
module SYSLOG_SUDO;

export {

	redef enum Log::ID += { LOG };

	global kv_splitter: pattern = /[\ \t]+/;
	global tab_splitter: pattern = /[\t]+|\\x09/;
	global space_splitter: pattern = /[\ ]+/;
	global one_space: string = " ";
	const year = 2016;

	# for matching service field
	global su_match: pattern = /^su$/;
	global sudo_match: pattern = /^sudo$/;

	type S_REC: record {
		ts: time &log;					#
		logip: string &log &default = "NULL";		#

		from_id: string &log &default = "NULL";		#
		to_id: string &log &default = "NULL";		#
		tty: string &log &default = "NULL";		# optional
		command: string &log &default = "NULL";		# if just su for shell, make = "shell"
		pwd: string &log &default = "NULL";		# optional sudo field
		success: string &log &default = "NULL";		# did the command work?
		session_state: count &default = 0;	# session start/end from pam_unix
		flavor: string &log &default = "NULL";
		};

	# the index for this table is [host, from_id, tty]
	global s_rec_state: table[string] of S_REC;

	# global processing function
	global su_sudo_f: function(data: string) : count;

	global cap_pam: pattern = /.*PAM.*/;
	global pam_func: pattern = /.*pam_.*/;
	global pam_unix: pattern = /.*pam_unix.*/;
	global pam_sss: pattern = /.*pam_sss.*/;
	global auth_succ: pattern = /.*authentication\ success.*/;
	global auth_fail: pattern = /.*authentication\ failure.*/;
	global su_fail: pattern = /.*FAILED.*/;
	global tty_pattern: pattern = /^tty=.*/;
	global to_id_pattern: pattern =  /^user=.*/;
	global from_id_pattern: pattern =  /^user=.*/;
	global pwd_pattern: pattern = /^pwd=.*/;
	global command_pattern: pattern = /^command=.*/;
	global not_pattern: pattern = /^NOT$/;

	global session_drain_wait: interval = 1 sec;
	} # end export

# clean up the identity string cause it is a mess ...
function clean_id(s: string) : string
	{
	#print fmt("IDC: in: %s", s);
	local p1: pattern = /\(/;
	local p2: pattern = /\)/;

	local sp1 = sub(s,p1,"");
	local sp2 = sub(sp1,p2,"");

	# convert uid=0 -> root
	if ( sp2 == "uid=0" )
		sp2 = "root";
	

	#print fmt("IDC: out: %s", sp2);
	return sp2;
	}


# Take data of the form key:value and return the value portion
function get_data(data: string) : string
        {
                local ret_val: string_vec;
                local delim: pattern = /:/;

                ret_val = split_string1(data, delim);

                return ret_val[1];
        }

function time_convert(data: string) : time
        {
	# get handed the nasty "time: ..." string and make it happy
	#
	local time_split = split_string( get_data(data), space_splitter);
	local month = time_split[0];
	local day   = time_split[1];
	local t  = time_split[2];
	local timestamp = fmt("%s %s %s", month, day, t);

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
        date_mod = fmt("%s %s", year,timestamp);
        # FreeBSD
        #date_mod = fmt("%s %s %s", tzone,year,timestamp);

        # second, make sure that any extra spaces in the date string are expunged...
        local date_mod_p = gsub(date_mod, kv_splitter, one_space);

        local ret_val = strptime(parse_string, date_mod_p);

        return ret_val;
        }

function get_index(logip: string, id: string, tty: string) : string
	{
	# return index string composed of canonical [host, from_id, tty]
	local ret_val = "ERROR";

	# logip and id are fairly well defined and can be comsumed as provided
	# tty is a little messy since it can come in the form of TTY=pts/4, tty=/dev/pts/4 or tty=STRING
	local ttydata1 = split_string(tty, /=/);
	local ttyret = "";

	if ( |ttydata1| > 1 ) {
		local ttydata2 = split_string(ttydata1[1], /\//);

		if ( |ttydata2| == 2 ) 	
			ttyret = fmt("%s%s", ttydata2[0], ttydata2[1]);

		if ( |ttydata2| == 3 ) 	
			ttyret = fmt("%s%s", ttydata2[1], ttydata2[2]);

		}

	ret_val = fmt("%s%s%s", logip, id, ttyret);

	return ret_val;
	}

# If index dne, provide blank struct else the current state
#
function lookup_record(index: string) : S_REC
	{
	local t_S: S_REC;

	if ( index in s_rec_state )
		t_S = s_rec_state[index];
 
	return t_S;
	}

event remove_record(index: string)
	{
	if ( index in s_rec_state ) {
		Log::write(LOG, s_rec_state[index]);
		delete s_rec_state[index];
		}
	}

# Sync the current record with any historical data and the
#  current record 
#
function sync_record(index: string, rec: S_REC) : count
	{
	local ret_val = 0;
	local t_S: S_REC;

	# Since you can not iterate over a struct we will do this
	#  the messy way ...
	if ( index in s_rec_state ) {

		# Need to poke about a bit.  Index values must be
		#  unchanged and assume that change from non-default
		#  is bad.
		#print fmt("RECORD LOOKUP SUCCESSFUL: %s", index);
		t_S = s_rec_state[index];
	
		# copy new values if old t_S value == NULL and
		#  new value also != NULL	
		if ( (rec$to_id == "NULL") && (t_S$to_id != "NULL") )
			rec$to_id = t_S$to_id;

		if ( (rec$tty == "NULL") && (t_S$tty != "NULL") )
			rec$tty = rec$tty;

		if ( (rec$command == "NULL") && (t_S$command != "NULL") )
			rec$command =  t_S$command;

		if ( (rec$pwd == "NULL") && (t_S$pwd != "NULL") )
			rec$pwd = t_S$pwd;
		
		if ( (rec$success == "NULL") && (t_S$success != "NULL") )
			rec$success = t_S$success;
			
		if ( (rec$session_state == 0) && (t_S$session_state != 0 ) )
			rec$session_state = t_S$session_state;

		# log and clear
		if ( rec$session_state == 1 ) {
			Log::write(LOG, rec);
			delete s_rec_state[index];	
			}
		else {
			# save data
		#print fmt("RECORD LOOKUP FAIL: %s", index);
			s_rec_state[index] = rec;
			# set timer for deleting
			schedule session_drain_wait { remove_record(index) };
			}
		}
	else {
		# this is a new rec so just drop in what we have
		s_rec_state[index] = rec;
		#Log::write(LOG, rec);
		schedule session_drain_wait { remove_record(index) };

		ret_val = 1;
		}

	return ret_val;
	}


function process_pam_sudo(data: string)
	{
	#
	# Aug 24 14:11:14 128.55.160.224 sudo: pam_unix(sudo_special:auth): 
	#	authentication failure; logname=beecroft uid=26009 euid=0 tty=/dev/pts/0 ruser=beecroft rhost=  user=beecroft
	#    -> note message always contains *failure* if an auth decision
	# For the three basic types of pam_ messages that we are interested in, they share a common structure.
	# As well, the logname/ruser/user are all the "from_id" user
	# [time:Sep 25 14:44:49, host:128.55.160.201, ident:su, message:pam_unix(su-l:session): session closed for user starxrd]
	# pam_unix(sudo_special:auth)
	# pam_unix(sudo:auth)
	# pam_sss(sudo_special:auth)
	#         local index = get_index(log_ip, from_id, tty); 

	local data_tab = split_string(data, tab_splitter); 
	local message_split = split_string( get_data(data_tab[3]), space_splitter);

	local p_type = message_split[0];
	local success = "NULL";
	local tty = "NULL";
	local from_id = "NULL";

        if ( (pam_unix == p_type) || (pam_sss == p_type) ) {

		if ( auth_succ == data ) {
			success = "T";
			}
		else if ( auth_fail == data ) {
			success = "F";
			}
	
		# ; logname=beecroft uid=26009 euid=0 tty=/dev/pts/0 ruser=beecroft rhost=  user=beecroft	
print fmt("PROCESS PAM SUDO: %s", data);
		local data_seg = split_string(data, /\x09/);
		local user_data = split_string( data_seg[1], space_splitter);

		for ( i in user_data ) {

			if ( tty_pattern == to_lower(user_data[i]) )
				tty = split_string( user_data[i], /=/ )[1]; 	
			
			if ( from_id_pattern == to_lower(user_data[i]) )
				from_id = split_string( user_data[i], /=/ )[1];
			}
		# get_index(logip: string, id: string, tty: string)
		local index = get_index(get_data(data_tab[1]), clean_id(from_id), tty);
		local t_S = lookup_record(index);

		t_S$success = success;
		t_S$tty = tty;
		t_S$from_id = clean_id(from_id);
		t_S$ts = time_convert(data_tab[0]);
		t_S$logip = get_data(data_tab[1]);
		t_S$flavor = "SUDO1";

		# set to sync and log since vanilla
		t_S$session_state = 1;
		#print fmt("%s", t_S);
		sync_record(index, t_S);

		} # end of pam_unix/pam_sss test

	}


function process_vanilla_sudo(data: string)
	{
	# A "vanilla" sudo log can either be standalone or come after a pam_ call.  In each case
	#  flush the record as soon as the delay goes off.
	#
	# data looks like:
	# time:Sep 25 08:08:02\x09host:128.55.160.208\x09ident:sudo\x09message:nrpe : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/lpp/mmfs/bin/mmdiag --waiters
	# time:Sep 27 14:24:50\x09host:128.55.210.17\x09ident:sudo\x09message:t : user NOT in sudoers ; TTY=pts/31 ; PWD=/data/home/t ; USER=root ; COMMAND=/usr/bi

	local data_tab = split_string(data, tab_splitter); 
	local message_split = split_string( get_data(data_tab[3]), space_splitter);

	local t_S: S_REC;
	t_S$ts = time_convert(data_tab[0]);
	t_S$logip = get_data(data_tab[1]);
	t_S$from_id = clean_id(message_split[0]);
	t_S$success = "T";

	for ( i in message_split ) {

		if ( tty_pattern == to_lower(message_split[i]) )
			t_S$tty = split_string( message_split[i], /=/ )[1];

		if ( to_id_pattern == to_lower(message_split[i]) )
			t_S$to_id = clean_id(split_string( message_split[i], /=/ )[1]);

		if ( pwd_pattern == to_lower(message_split[i]) )
			t_S$pwd = split_string( message_split[i], /=/ )[1];

		if ( command_pattern == to_lower(message_split[i]) )
			t_S$command = split_string( message_split[i], /=/ )[1];

		if ( not_pattern == message_split[i] )
			t_S$success = "F";
		}

	t_S$flavor = "SUDO2";
	# set to sync and log since vanilla
	t_S$session_state = 1;

	local index = get_index(t_S$logip,t_S$from_id, t_S$tty);
	#print fmt("%s", t_S);	
	sync_record(index, t_S);

	}

function sudo_log_f(data: string)
	{
	#  start by parsing the form and handing off to the more specialized codes
	#  general form: MM DD HH:MM:SS sudo: (.X.) with X being either the from_id or a pam_ 
	#     or a PAM [info] which we will be skipping

	local data_space = split_string(data, tab_splitter); 

	local test_string = get_data(data_space[3]);
	
	if ( cap_pam == test_string ) {
		return;
		}
	else if ( pam_func == test_string ) {
		#print fmt("pam_func match,call process_pam_sudo");
		process_pam_sudo(data);
		}
	else {
		#print fmt("pam_func fallthrough process_vanilla_sudo");
		process_vanilla_sudo(data);
		}

	}

function su_pam_log_f(data: string)
	{
	# pam_unix(su-l:session): session opened for user qsuge by (uid=0)
	# pam_unix(su-l:session): session closed for user qsuge
	# pam_unix(su-l:session): session opened for user postgres by (uid=0)
	# pam_unix(su-l:session): session closed for user postgres

	local data_tab = split_string(data, tab_splitter); 
	local message_split = split_string( get_data(data_tab[3]), space_splitter);
	local t_S: S_REC;

	# closing records do not have enough information to get to the 
	#  historical record, so just don't log.
	# session_state = 0  will give enough time for the next step to be recorded
	#  and will time out into logging.
	#
	if ( message_split[2] == "closed" )
		return;

	t_S$ts = time_convert(data_tab[0]);
       	t_S$to_id = clean_id(message_split[5]);
       	t_S$flavor = "SU_SESSION";
       	t_S$success = "T";
	t_S$logip = get_data(data_tab[1]);

	t_S$session_state = 0;
	t_S$from_id = clean_id(message_split[7]);
	
	#print fmt("%s", t_S);	
	local index = get_index(t_S$logip,t_S$from_id,t_S$tty);
	sync_record(index, t_S);
	#Log::write(LOG, t_S);	
	}


function su_van_log_f(data: string)
	{
	# Aug  8 12:25:14 128.55.64.27 su: csnavely to root on /dev/pts/18pontoni on pts/0
	#        ""                        (to postgres) root on none
	# Aug 27 13:01:29 128.55.195.11 su: FAILED SU (to root) apontoni on pts/0
	# 
	local data_tab = split_string(data, tab_splitter); 
	local message_split = split_string( get_data(data_tab[3]), space_splitter);
	local t_S: S_REC;

	t_S$ts = time_convert(data_tab[0]);
	t_S$logip = get_data(data_tab[1]);
	t_S$session_state = 1;
	
	# vanilla 'su'
	if ( su_fail == data ) {
		# Aug 27 13:01:29 128.55.195.11 su: FAILED SU (to root) apontoni on pts/0
		
		t_S$success = "F";
		t_S$from_id = clean_id(message_split[4]);
		t_S$to_id = clean_id(message_split[3]);
		t_S$flavor = "SU1";	
		t_S$tty = to_lower(message_split[6]);
		}
	else {
		# there are (at least) two different forms of log message here, both examples above	
		if ( |message_split| < 6 ) {
			t_S$from_id = clean_id(message_split[2]);
			t_S$to_id = clean_id(message_split[1]);
			t_S$tty = to_lower(message_split[4]);
			}
		else {
			t_S$from_id = clean_id(message_split[0]);
			t_S$to_id = clean_id(message_split[2]);
			t_S$tty = message_split[6];
			}

			t_S$flavor = "SU2";	
			t_S$success = "T";

		} #  end success == F/T

	local index = get_index(t_S$logip,t_S$from_id, t_S$tty);
	sync_record(index, t_S);
	#print fmt("%s", t_S);	
	}


# Interface function that is called by external policy
#  for handing off data
#
function su_sudo_f(data: string) : count
	{
	local ret_val: count = 0;
	local parts_tab = split_string(data, tab_splitter);

	#print fmt("start match for %s", data);
	local t_u = get_data(parts_tab[2]);

	if ( su_match == t_u ) {
		if ( pam_func == data ) {
			#print fmt("match su_pam_log_f: %s |  %s", parts_tab[2], parts_tab[3]);
			su_pam_log_f(data);	
			}
		else {
			#print fmt("match su_vam_log_f: %s |  %s", parts_tab[2], parts_tab[3]);
			su_van_log_f(data);
			} 
		
		}

	if ( sudo_match == t_u ) {
		#print fmt("match sudo_log_f: %s |  %s", parts_tab[2],parts_tab[3]);
		sudo_log_f(data);
		}
	#print fmt("end match for %s", data);
	#print fmt("-------------------------------------------");

	return ret_val;
	} # end su_sudo_f()



event bro_init()
{
	Log::create_stream(SYSLOG_SUDO::LOG, [$columns=S_REC]);
	local filter_c: Log::Filter = [$name="default", $path="syslog_sudo"];
}
