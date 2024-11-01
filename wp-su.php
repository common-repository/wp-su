<?php
/*
Plugin Name: WP Su
Plugin URI: http://dd32.id.au/wordpress-plugins/wp-su/
Description: Proof of Concept plugin which offers <strong>Su</strong>peruser functionality to WordPress. Users of the selected roles are presented with a Bare-basics interface, with the option to move into 'Su' mode by proving the Super User password.
Author: Dion Hulse
Version: 1.0
Author URI: http://dd32.id.au/
*/

new Plugin_WP_Su();
class Plugin_WP_Su {
	
	var $su_req_caps = array();
	var $su_roles = array();
	var $user_is_su = false;
	var $su_allowed = false;

	var $cookie_handler = null;

	function Plugin_WP_Su() {
		$this->cookie_handler = new Plugin_Wp_su_Auth_Cookie_Handler(&$this);
		add_action('init', array(&$this, 'init'));
		add_action('admin_init', array(&$this, 'admin_init'));
		add_action('admin_menu', array(&$this, 'admin_menu'));
		add_filter('user_has_cap', array(&$this, 'limit_user_has_cap'), 5, 3);
		register_activation_hook(__FILE__, array(&$this, 'activate'));
	}
	function init() {
		$opts = get_option('wp_su-options', array('caps' => array(), 'roles' => array('administrator')) );
		$this->su_roles = isset($opts['roles']) ? $opts['roles'] : array();
		$this->su_req_caps = isset($opts['caps']) ? $opts['caps'] : array();

		$this->user_is_su = $this->cookie_handler->wp_validate_su_auth_cookie();

		$user = wp_get_current_user();

		if ( is_array($user->roles) )
			foreach ( $user->roles as $role )
				if ( in_array($role, $this->su_roles) )
					$this->su_allowed = true;

		load_plugin_textdomain('su', null, dirname(plugin_basename(__FILE__)) . '/langs/');

		add_action('admin_page_access_denied', array(&$this, 'admin_access_denied') );
		
	}
	function admin_init() {
		
		wp_enqueue_style('su', plugins_url( dirname(plugin_basename(__FILE__)) . '/wp-su.css'), array(), '1');
		add_filter('admin_body_class', array(&$this, 'admin_body_class'));
		
		register_setting( 'su_options', 'wp_su-options' );
		
		add_filter('sanitize_option_wp_su-options', array(&$this, 'sanitize_option') );

		// 3.0+ add_action('admin_user_info_links', array(&$this, 'admin_header_su'));
		add_action('admin_head', array(&$this, 'admin_header_su_js'), 100);


//		if ( $this->su_allowed && isset($_POST['su_pwd']) )
//			$this->maybe_post_login('quiet');
	}
	function admin_menu() {

		//Logout
		add_action('load-su-settings_page_su_loginout', array(&$this, 'maybe_post_logout'), 5);
		add_action('load-su-settings_page_su_loginout', array(&$this, 'maybe_load_su_iframe'), 5);

		//Login
		add_action('load-su-settings_page_su_loginout', array(&$this, 'maybe_post_login'), 5);
		add_action('load-su-settings_page_su_loginout', array(&$this, 'maybe_load_su_iframe'), 5);

		if ( $this->su_allowed ) {
			
			add_thickbox();
			
			add_utility_page( __('Su Settings', 'su'), __('Su Settings', 'su'), 'administrator', 'su', array(&$this, 'admin_page') );
			
			add_submenu_page( 'Su', __('Su Settings', 'su'), __('Su Settings', 'su'), 'administrator', 'su', array(&$this, 'admin_page'));
	
			if ( $this->su_allowed ) {
				if ( ! $this->user_is_su )
					add_submenu_page('su', __('Su Log In', 'su'), __('Su Log In', 'su'), 'read', 'su_loginout', array(&$this, 'admin_su_login'));
				else
					add_submenu_page('su', __('Su Log Out', 'su'), __('Su Log Out', 'su'), 'read', 'su_loginout', array(&$this, 'maybe_post_logout'));
			}
		}

	}
	
	function admin_access_denied($str) {
		if ( $this->su_allowed ) {
			
			if ( !$this->user_is_su && isset($_GET['page']) && in_array($_GET['page'], array('su_login', 'su') ) ) {
				$this->maybe_post_login();
				wp_safe_redirect( admin_url('admin.php?page=su_loginout') );
				die();
			}
			
			wp_deregister_script('thickbox');
			wp_deregister_style('thickbox');
			wp_enqueue_style('su', plugins_url( dirname(plugin_basename(__FILE__)) . '/wp-su.css'), array(), '1');
			iframe_header();
			$this->admin_su_login(false, __('Sorry, But the requested page required privledges which you do not have.</p><p><a href="index.php">Back to Dashboard?</a>', 'su'));
			iframe_footer();
			die();
		} else {
			wp_die($str);
		}
	}
	
	function activate() {
		//On activation, set the defaults, if its been done before, we'll retain caps/roles, but reset password
		$user = wp_get_current_user();
		if ( get_option('wp_sudo-options') ) {
			update_option('wp_su-options', get_option('wp_sudo-options'));
			delete_option('wp_sudo-options');
		}
		$current = get_option('wp_su-options');
		$new = array('caps' => array(), 'roles' => array('administrator'), 'password' => $user->user_pass);
		if ( is_array($current) ) {
			$new['caps'] = $current['caps'];
			$new['roles'] = $current['roles'];
		}
		update_option('wp_su-options', $new );
	}
	
	function sanitize_option($new) {
		if ( empty($new['password']) || ( empty($new['password']['new1']) && empty($new['password']['new2'])) ) {
			$new['password'] = $this->get_hashed_password();
		} elseif ( is_array($new['password']) ) {
			if ( !wp_check_password($new['password']['original'], $this->get_hashed_password()) ) {
				 $new['password'] = $this->get_hashed_password();
				 update_option('wp_su-password', __('Original Password not specified.', 'su'));
			} elseif ( $new['password']['new1'] != $new['password']['new2'] ) {
				 $new['password'] = $this->get_hashed_password();
				 update_option('wp_su-password', __('New Passwords do not match.', 'su'));
			} else {
				// Ok, Seems the password is ok..
				// Lets hash it.
				$new['password'] = wp_hash_password($new['password']['new1']);
				update_option('wp_su-password', __('Password updated.', 'su'));
			}
		}
		return $new;
	}


	function admin_body_class($classes) {
		if ( $this->user_is_su )
			$classes .= ' su';
		else
			$classes .= ' not-su';
		return $classes;
	}

	function admin_header_su_js() {
		if ( ! $this->su_allowed )
			return;
			
		if ( $this->user_is_su )
			$link = '<a href="' . admin_url('admin.php?page=su_loginout&user_info=true') . '" class="su_link">' . __('Log Out of Su', 'su') . '</a> | ';
		else
			$link = '<a href="' . admin_url('admin.php?page=su_loginout&user_info=true&TB_iframe=true&width=400&height=500') . '" class="su_link thickbox">' . __('Su', 'su') . '</a> | ';
		echo "
<script type='text/javascript'>
	jQuery(document).load( function() {
		jQuery('#user_info p:first a:last').before('{$link}');
		tb_init('a.thickbox, area.thickbox, input.thickbox');
	});
</script>";
	}

	/* This is for WP 3.0+ function admin_header_su($links) {
		if ( $this->su_allowed ) {
			if ( $this->user_is_su )
				$links[7] = ' | <a href="' . admin_url('profile.php?page=su_logout&user_info=true') . '" class="su_link">' . __('Log Out of Su', 'su') . '</a>';
			else
				$links[7] = ' | <a href="' . admin_url('profile.php?page=su_login&user_info=true&TB_iframe=true&width=400&height=500') . '" class="su_link thickbox">' . __('Su', 'su') . '</a>';
		}
		return $links;
	}*/

	function limit_user_has_cap($allcaps, $caps, $args) {
		foreach ( (array)$this->su_req_caps as $cap ) {
			if (  ! $this->user_is_su && isset($allcaps[$cap]) )
				unset($allcaps[$cap]);
			//elseif ( $this->user_is_su && ! isset($allcaps[$cap]) )
			//	$allcaps[$cap] = true; //This branch allows less-than-admin roles to have full admin while running in su, If su is allowed for their role, and they know the password.
		}
		return $allcaps;
	}
	
	function maybe_post_logout() {
		if ( ! $this->user_is_su )
			return;
		$this->cookie_handler->logout();
		wp_safe_redirect( admin_url('') );
		die();
	}
	
	function maybe_post_login($type = 'auto') {
		if ( isset($_POST['su_pwd']) ) {
			$pass = stripslashes($_POST['su_pwd']);
			$timeout = !empty($_POST['su_timeout']) ? absint($_POST['su_timeout']) : 1; //default to 1 min.
			if ( $timeout != get_user_option('su_timeout') ) {
				$user = wp_get_current_user();
				update_user_option($user->id, 'su_timeout', $timeout);
			}
			$result = $this->cookie_handler->login($pass, $timeout);
			if ( $result && !is_wp_error($result) ) {
				if ( $type = 'auto' ) {
					$type = !empty($_POST['redirect_to']) ? 'redirect' : 'jsreloadparent';
				}
				switch ( $type ) {
					case 'redirect':
						wp_safe_redirect( stripslashes($_POST['redirect_to']) );
						die();
						break;
					case 'jsreloadparent':
						echo '<script type="text/javascript">window.parent.location.reload();</script>';
						die();
						break;
					case 'quiet':
						return;
						break;
				}
			} else {
				$this->login_error = $result;
			}
		}
	}
	
	function maybe_load_su_iframe() {
		$in_iframe = !isset($_GET['TB_iframe']) && isset($_GET['user_info']);
		if ( $in_iframe ) {
			//Deregister JS's:
			wp_deregister_script('thickbox');
			wp_deregister_style('thickbox');
			iframe_header();
			$this->admin_su_login(true);
			iframe_footer();
			die();
		}
	}
	
	function admin_su_login( $iframe = false, $message = '' ) {
		?><div class="wrap">
			<div id="su_login">
				<div id="login">
					<h1><a href="#" style="background: url(images/logo-login.gif) no-repeat top center;"><?php _e('WordPress') ?></a></h1>
					<?php
						if ( !empty($this->login_error) ) {
							echo '<div class="error"><p>' . $this->login_error->get_error_message() . '</p></div>';
							echo '<div class="message"><p>' . __('If you have forgotten your password, Please uninstall this plugin via FTP and re-install it, Your Su password will be reset to the installers password.', 'su') . '</p></div>';
						}
						if ( !empty($message) )
							echo '<div class="message"><p>' . $message . '</p></div>';
					?>
				</div>
				<form name="loginform" id="loginform" action="admin.php?page=su_loginout" method="post" autocomplete="off">
					<p class="superusertext">
						<?php _e('Please enter your Su Password to continue.', 'su') ?>
					</p>
					<p>
						<label><?php _e('Password', 'su') ?><br />
						<input type="password" name="su_pwd" id="super_user_pass" class="input" value="" size="20" tabindex="20" /></label>
					</p>
					<p>
						<label><?php _e('Login Timeout', 'su') ?><br />
						<select name="su_timeout">
						<?php
							$last_timeout = get_user_option('su_timeout');
							foreach ( array(1, 5, 15, 30, 60) as $timeout )
								echo '<option value="' . $timeout . '" ' . $this->_checked($timeout, $last_timeout, 'selected') . '>'
									. sprintf(_n('%s Minute', '%s Minutes', $timeout, 'su'), $timeout) . '</option>';
						?>
						</select>
						</label>
					</p>
					<p class="submit">
						<input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php _e('Log Into Su', 'su') ?>" tabindex="100" />
						<?php if ( ! $iframe ) { ?>
						<input type="hidden" name="redirect_to" value="<?php echo wp_get_referer() ?>" />
						<?php } ?>
					</p>
				</form>
			</div>
		</div>
		<?php
	}
	
	function get_hashed_password() {
		$opts = get_option('wp_su-options', array('password' => false) );
		return $opts['password'];
	}

	function admin_page() {
		global $wp_roles;
		
		if ( get_option('wp_su-password') ) {
			echo '<div class="updated"><p>' . get_option('wp_su-password') . '</p></div>';
			delete_option('wp_su-password');	
		}
		
		echo '<div class="wrap">';
		screen_icon('tools');
		echo '<h2>' . __('Wp-Su Settings', 'su') . '</h2>';
		echo '<p>' . __('WP-Su is a powerful plugin which allows you to secure your WordPress installation easier by limiting what your administrative account can access in its normal state.', 'su') . '</p>';
		echo '<p>' . __('<strong>Please note:</strong> This initial version is a <strong>Proof Of Concept</strong> plugin, It has not undergone deep security review. Do not rely upon this plugin for front-line security. Infact, Dont even run it on a Production site with multiple users until its been tested properly.', 'su') . '</p>';
		
		echo '<h3>' . __('Roles Su is available under', 'su') . '</h3>';
		echo '<form method="post" action="' . admin_url('options.php') . '">';
		settings_fields('su_options');

		echo '<table> <tr><td>';
		foreach ( (array)$wp_roles->roles as $role => $data ) {
			if ( get_option('default_role') === $role ) //Lets not offer su to default users.. :)
				continue;
			echo '<label for="su-roles-' . $role . '"><input type="checkbox" name="wp_su-options[roles][]" id="su-roles-' . $role . '" value="' . $role . '" ' . $this->_checked($role, $this->su_roles) . ' />' . $data['name'] . '</label>&nbsp;';
		}
		echo '</td></tr></table>';
		echo '<h3>' . __('Capabilities which are protected by Su', 'su') . '</h3>';
		echo '<p>' . __('Any capabilities which are ticked below, will only be available to users if they are running in a su-enabled account. This is regardless of if your Role is an Administrator or similar.', 'su') . '</p>';

		$allcaps = $this->_get_allcaps();
		$items_per_column = ceil(count($allcaps) / 4);
		echo '<table id="su-cap-table"> <tr><td>';
		foreach ( $allcaps as $item => $cap ) {
			if ( 0 === $item % $items_per_column ) //This is a bug.
				echo '</td><td>';
			echo '<label for="su-caps-' . $cap . '"><input type="checkbox" name="wp_su-options[caps][]" id="su-caps-' . $cap . '" value="' . $cap . '" ' . $this->_checked($cap, $this->su_req_caps) . ' />' . $cap . '</label><br />';
		}
		echo '</td></tr></table>';
		echo '<p class="hide-if-no-js"><input type="button" id="su-recomended-caps" value="' . esc_attr(__('Check suggested settings', 'su')) . '"></p>';
?>
<script type="text/javascript">
jQuery('#su-recomended-caps').click( function() {
												var vals = ['administrator', 'switch_themes', 'edit_themes', 'activate_plugins', 'edit_plugins', 'edit_users', 'edit_files', 'manage_options', 'import', 'level_10', 'level_9', 'level_8', 'delete_users', 'create_users', 'unfiltered_upload', 'update_plugins', 'delete_plugins', 'install_plugins', 'update_themes', 'install_themes'];
												//jQuery("#su-cap-table input").val( vals );
												for ( var i in vals ) {
													jQuery('#su-caps-' + vals[i] ).attr('checked', 'checked');
												}
												});
</script>
<?php
		//echo '<p>' . __('<strong>Please Note:</strong> the <em>level_*</em> capabilities are not listed due to them being phased out of WordPress since <strong>version 2.0</strong>. In the event that they are used by a plugin, the equivilent <em>capability</em> will be checked for.', 'su') . '</p>';
		
		echo '<h3>' . __('Change Password', 'su') . '</h3>';
		echo '<p>' . __('Please Enter your current password, Along with your new password twice. Please note: This only affects your SU password, Not your user accounts password, they may be set independantly of eachother.', 'su') . '</p>';
		echo '<p>';
		echo '<label for="su-pass-original">' . __('Current Password', 'su') . '</label><input type="password" name="wp_su-options[password][original]" id="su-pass-original" /><br />';
		echo '<label for="su-pass-new1">' . __('New Password', 'su') . '</label><input type="password" name="wp_su-options[password][new1]" id="su-pass-new1" /><br />';
		echo '<label for="su-pass-new2">' . __('Retype New Password', 'su') . '</label><input type="password" name="wp_su-options[password][new2]" id="su-pass-new2" />';
		echo '</p>';
		
		echo '<p><input type="submit" name="submit" value="' . __('Save Settings', 'su') . '" /></p>';
		
		echo '</div>';
	}
	function _get_allcaps() {
		global $wp_roles;
		//Gather a list of all the current capabilities.
		//Whilst not really a cap, We'll add this as a cap for the UI.
		$allcaps = array('administrator');

		foreach ( (array)$wp_roles->roles as $role => $data )
			$allcaps = array_merge( $allcaps, (array)array_keys($data['capabilities']) );

		//Filter out the stupid caps
		//$hidden_caps = array('read', 'level_10', 'level_9', 'level_8', 'level_7', 'level_6', 'level_5', 'level_4', 'level_3', 'level_2', 'level_1', 'level_0');
		//$allcaps = array_diff($allcaps, $hidden_caps);

		$allcaps = array_unique($allcaps);

		return $allcaps;
	}
	function _checked($item, $items, $type = 'checked') {
		if ( is_array($items) )
			return in_array($item, $items) ? "$type='$type'" : '';
		else
			return $item == $items ? "$type='$type'" : '';
	}
}

class Plugin_Wp_su_Auth_Cookie_Handler {
	var $parent = false;
	function Plugin_Wp_su_Auth_Cookie_Handler($parent) {
		$this->parent = $parent;
		define( 'su_AUTH_COOKIE', 'su_' . AUTH_COOKIE);
	}
	// $length: time in minuges to stay logged in.
	function login($password, $length = 5) {
		if ( wp_check_password( $password, $this->parent->get_hashed_password() ) ) {
			$user = wp_get_current_user();
			$this->wp_set_su_auth_cookie($user->ID, $length);
			return true;
		} else {
			return new WP_Error('invalid_password', __('Invalid Password', 'su'));
		}
	}
	function logout() {
		$user = wp_get_current_user();
		return $this->wp_set_su_auth_cookie($user->ID, -600); //Expire it.
	}
	
	function wp_validate_su_auth_cookie($cookie = '', $scheme = 'su_auth') {
		if ( ! $cookie_elements = $this->wp_parse_su_auth_cookie($cookie, $scheme) )
			return false;
	
		extract($cookie_elements, EXTR_OVERWRITE);
	
		// Quick check to see if an honest cookie has expired
		if ( $expiration < time() )
			return false;
	
		$user = get_userdatabylogin($username);
		if ( ! $user )
			return false;
	
		$pass_frag = substr($this->parent->get_hashed_password(), 8, 4);
	
		$key = wp_hash($username . $pass_frag . '|' . $expiration, $scheme);
		$hash = hash_hmac('md5', $username . '|' . $expiration, $key);
	
		if ( $hmac != $hash )
			return false;
	
		return $user->ID;
	}

	function wp_parse_su_auth_cookie($cookie = '', $scheme = 'su_auth') {
		if ( empty($cookie) ) {
			if ( 'su_auth' !== $scheme ) 
				return false;

			$cookie_name = su_AUTH_COOKIE;
	
			if ( empty($_COOKIE[$cookie_name]) )
				return false;
			$cookie = $_COOKIE[$cookie_name];
		}
	
		$cookie_elements = explode('|', $cookie);
		if ( count($cookie_elements) != 3 )
			return false;
	
		list($username, $expiration, $hmac) = $cookie_elements;
	
		return compact('username', 'expiration', 'hmac', 'scheme');
	}

	function wp_set_su_auth_cookie($user_id, $length, $secure = '') {
		$expiration = time() + ($length * 60);
	
		if ( '' === $secure )
			$secure = is_ssl() ? true : false;
	
		$auth_cookie_name = su_AUTH_COOKIE;
		$scheme = 'su_auth';
	
		$auth_cookie = $this->wp_generate_su_auth_cookie($user_id, $expiration, $scheme);
	
		// Set httponly if the php version is >= 5.2.0
		if ( version_compare(phpversion(), '5.2.0', 'ge') ) {
			setcookie($auth_cookie_name, $auth_cookie, $expiration, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true);
		} else {
			$cookie_domain = COOKIE_DOMAIN;
			if ( !empty($cookie_domain) )
				$cookie_domain .= '; HttpOnly';
			setcookie($auth_cookie_name, $auth_cookie, $expiration, ADMIN_COOKIE_PATH, $cookie_domain, $secure);
		}
	}
	function wp_generate_su_auth_cookie($user_id, $expiration, $scheme = 'su_auth') {
		$user = get_userdata($user_id);
	
		$pass_frag = substr($this->parent->get_hashed_password(), 8, 4);
	
		$key = wp_hash($user->user_login . $pass_frag . '|' . $expiration, $scheme);
		$hash = hash_hmac('md5', $user->user_login . '|' . $expiration, $key);
	
		return $user->user_login . '|' . $expiration . '|' . $hash;
	}
}