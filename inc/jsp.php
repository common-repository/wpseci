<?

/**
 *
 * @package WPSECi (Wordpress security injection)
 * @author Jeff Starr [Block Bad Queries (BBQ)](http://perishablepress.com/block-bad-queries/)
 * @added filters Rynaldo Stoltz
 * 
 */

	$request_uri_array  = apply_filters( 'request_uri_items',  array( 'eval\(', 'UNION\+SELECT', '\(null\)', 'base64_', '\/localhost', '\/pingserver', '\/config\.', '\/wwwroot', '\/makefile', 'crossdomain\.', 'proc\/self\/environ', 'etc\/passwd', '\/https\/', '\/http\/', '\/ftp\/', '\/cgi\/', '\.cgi', '\.exe', '\.sql', '\.ini', '\.dll', '\.asp', '\.jsp', '\/\.bash', '\/\.git', '\/\.svn', '\/\.tar', ' ', '\<', '\>', '\/\=', '\.\.\.', '\+\+\+', '\:\/\/', '\/&&' ) );
	$query_string_array = apply_filters( 'query_string_items', array( '\.\.\/', '127\.0\.0\.1', 'localhost', 'loopback', '\%0A', '\%0D', '\%22', '\%27', '\%00', '\%2e\%2e', 'union', 'input_file', 'execute', 'mosconfig', 'path\=\.', 'mod\=\.' ) );
	$user_agent_array   = apply_filters( 'user_agent_items',   array( 'acunetix', 'binlar', 'casper', 'clshttp', 'cmswor', 'diavol', 'dotbot', 'finder', 'flicky', 'grab', 'havij', 'httrack', 'jakarta', 'miner', 'nikto', 'nutch', 'planet', 'purebot', 'pycurl', 'skygrid', 'sucker', 'sqlmap', 'turnit', 'vikspi', 'wget', 'winhttp', 'zmeu' ) );

	if (

	preg_match( '/' . implode( '|', $request_uri_array )  . '/i', $_SERVER['REQUEST_URI'] ) || 
	preg_match( '/' . implode( '|', $query_string_array ) . '/i', $_SERVER['QUERY_STRING'] ) || 
	preg_match( '/' . implode( '|', $user_agent_array )   . '/i', $_SERVER['HTTP_USER_AGENT'] )

	) {

	header('HTTP/1.1 403 Forbidden');
	header('Status: 403 Forbidden');
	header('Connection: Close');
	exit;

	}

?>