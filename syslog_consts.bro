
const sapi_auth_res = {
	[0] = "AUTH_FAIL",
	[1] = "AUTH_SUCCESS",
	[2] = "AUTH_OTHER",
	} &default = function(n: count): string { return fmt("unknown-sapi-res-type-%d", n); };

const sapi_auth_meth = {
	[0] = "PASSWORD",
	[1] = "PUBKEY",
	[2] = "PAM",
	[3] = "LDAP",
	[4] = "HOSTBASED",
	[5] = "X509",
	[6] = "KERBEROS",
	[7] = "OTHER",
	} &default = function(n: count): string { return fmt("unknown-sapi-auth-type-%d", n); };
