<?php
/*
Plugin Name: WPSECi (Wordpress security injection)
Plugin URI: http://www.securiilock.com/wpsecii
Description: Wordpress Security protection against SQLi, XSS, CST, RFi, LFi, Base64, and malicious URL requests. 
Author: RS Publishing
Version: 13394
Author URI: http://www.securiilock.com
*/

require_once( WP_PLUGIN_DIR . '/wpseci/inc/jsp.php' );

$wpseci = new wpseci();

register_activation_hook( WP_PLUGIN_DIR . '/wpseci/wpseci.php', array($wpseci, 'activate') );
register_deactivation_hook( WP_PLUGIN_DIR . '/wpseci/wpseci.php', array($wpseci, 'deactivate') );


function gnf_rem() { return ''; }

if (function_exists('add_filter')) {

 $types = array('html', 'xhtml', 'atom', 'rss2', /*'rdf',*/ 'comment', 'export',);
 foreach ($types as $type)
 add_filter('get_the_generator_'.$type, 'gnf_rem');

}

remove_action('wp_head', 'wlwmanifest_link');
remove_action('wp_head', 'rsd_link');
remove_action('wp_head', 'start_post_rel_link');
remove_action('wp_head', 'index_rel_link');
remove_action('wp_head', 'adjacent_posts_rel_link');

function upd_plu() {

if ( ! current_user_can( 'manage_options' ) ) {

 	remove_action( 'load-update-core.php', 'wp_update_plugins' );
	add_filter( 'pre_site_transient_update_plugins', create_function( '$a', "return null;" ) );
	wp_clear_scheduled_hook( 'wp_update_plugins' );

		}
	}

function upd_temp() {

if ( ! current_user_can( 'manage_options' ) ) {
			
	remove_action( 'load-update-core.php', 'wp_update_themes' );
	add_filter( 'pre_site_transient_update_themes', create_function( '$a', "return null;" ) );
	wp_clear_scheduled_hook( 'wp_update_themes' );

		}
	}

add_action('admin_menu','naghide_wpup');

function naghide_wpup() {

remove_action( 'admin_notices', 'update_nag', 3 );

}

add_filter('login_errors',create_function(NULL, "return 'Sorry Mario ! Peaches is in another castle !';"));

?>