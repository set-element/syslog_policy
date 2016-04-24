SyslogReader
============

Use Input Framework to read syslogs and import into user and system structs 

This policy file uses the input framework to digest raw syslog data read from a
text file and converts it into a series of events.

Overall the authentication related events are fed to the general user event handler 
which tracks aggrigate activity across multiplle sources.

The code has been written to facilitate it being implemented on a worker node which 
reports back to the manager who is responsible for tracking aggrigate behaviors.

To your main config file add:

	@load syslog_policy
	redef SYSLOG_PARSE::data_file = "/home/bro/logs/RAW/DATA_0";

And for the /etc/node.cfg file:

	[syslog]
	type=worker
	host=sigma-n
	aux_scripts="syslog_policy/init_node"

