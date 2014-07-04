<?php
/*
Plugin Name: Safe Cookies
Plugin URI: https://github.com/subhransusekhar/safe-cookies
Description: Tries to create a more secure cookie with random vatiable to avoid reuse of cookies
Version: 1.0
Author: Subhransu Sekhar
Author URI: http://subhransusekhar.com/
*/
if ( !function_exists('wp_generate_auth_cookie') ) :
function wp_generate_auth_cookie($user_id, $expiration, $scheme = 'auth') {
		$user = get_userdata($user_id);
		$key = '_rand_auth_key';
		$single = true;
		$user_key = get_user_meta( $user_id, $key, $single );
		if(empty($user_key)) {
		  $user_key = generateRandomString();
		  add_user_meta( $user_id, $key, $user_key);
		}
		$pass_frag = substr($user->user_pass, 8, 4);
		$key = wp_hash($user->user_login . $pass_frag . '|' . $expiration . '|' . $user_key, $scheme);
		$hash = hash_hmac('md5', $user->user_login . '|' . $expiration, $key);
	
		$cookie = $user_key . '|' . $expiration . '|' . $hash;
	
		return apply_filters('auth_cookie', $cookie, $user_id, $expiration, $scheme);
	}
endif;

if ( !function_exists('wp_validate_auth_cookie') ) :
function wp_validate_auth_cookie($cookie = '', $scheme = 'auth') {
		if ( empty($cookie) ) {
			switch ($scheme){
				case 'auth':
					$cookie_name = AUTH_COOKIE;
					break;
				case 'secure_auth':
					$cookie_name = SECURE_AUTH_COOKIE;
					break;
				case "logged_in":
					$cookie_name = LOGGED_IN_COOKIE;
					break;
				default:
					if ( is_ssl() ) {
						$cookie_name = SECURE_AUTH_COOKIE;
						$scheme = 'secure_auth';
					} else {
						$cookie_name = AUTH_COOKIE;
						$scheme = 'auth';
					}
		    }
	
			if ( empty($_COOKIE[$cookie_name]) )
				return false;
			$cookie = $_COOKIE[$cookie_name];
		}
	
		$cookie_elements = explode('|', $cookie);
		if ( count($cookie_elements) != 3 )
			return false;
	
		list($user_key, $expiration, $hmac) = $cookie_elements;
	
		$expired = $expiration;
	
		// Allow a grace period for POST and AJAX requests
		if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] )
			$expired += 3600;
	
		// Quick check to see if an honest cookie has expired
		if ( $expired < time() ) {
			do_action('auth_cookie_expired', $cookie_elements);
			return false;
		}
		$user_id = get_user_id_by_key($user_key);
		$user = get_userdata($user_id);
		if ( ! $user ) {
			do_action('auth_cookie_bad_username', $cookie_elements);
			return false;
		}
	
		$pass_frag = substr($user->user_pass, 8, 4);

		
		$key = wp_hash($user->user_login . $pass_frag . '|' . $expiration . '|' . $user_key, $scheme);
		$hash = hash_hmac('md5', $user->user_login . '|' . $expiration, $key);
	
		if ( $hmac != $hash ) {
			do_action('auth_cookie_bad_hash', $cookie_elements);
			return false;
		}
	
		if ( $expiration < time() ) // AJAX/POST grace period set above
			$GLOBALS['login_grace_period'] = 1;
	
		do_action('auth_cookie_valid', $cookie_elements, $user);
	
		return $user->ID;
	}
endif;


function safe_cookie_logout() {
  $user_ID = get_current_user_id();
  delete_user_meta($user_ID, '_rand_auth_key');
  wp_clear_auth_cookie();
}
add_action('wp_logout', 'safe_cookie_logout');

function generateRandomString($length = 10) {
  $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $randomString = '';
  for ($i = 0; $i < $length; $i++) {
    $randomString .= $characters[rand(0, strlen($characters) - 1)];
  }
  return $randomString;
}
function get_user_id_by_key($key) {
	global $wpdb;
	$data = $wpdb->get_row($wpdb->prepare("SELECT * FROM $wpdb->usermeta WHERE meta_key = '_rand_auth_key' AND meta_value = %s", $key));
	return $data->user_id;
}