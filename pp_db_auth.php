<?php
/*
  Plugin Name: External Database Authentication Reloaded
  Plugin URI: http://www.7mediaws.org/extend/plugins/external-db-auth-reloaded/
  Description: Used to externally authenticate WP users with an existing user DB.
  Version: 1.2.0
  Author: Joshua Parker
  Author URI: http://www.desiringfreedom.com/
  Original Author: Charlene Barina
  Original Author URI: http://www.ploofle.com

  Copyright 2007  Charlene Barina  (email : cbarina@u.washington.edu)

  This program is free software; you can redistribute it and/or modify
  it  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');
require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'user.php');
require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'pluggable.php');
require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'class-phpass.php');

function pp_db_auth_activate()
{
    add_option('pp_db_type', "MySQL", "External database type");
    add_option('pp_db_mdb2_path', "", "Path to MDB2 (if non-standard)");
    add_option('pp_host', "", "External database hostname");
    add_option('pp_db_port', "", "Database port (if non-standard)");
    add_option('pp_db', "", "External database name");
    add_option('pp_db_user', "", "External database username");
    add_option('pp_db_pw', "", "External database password");
    add_option('pp_db_table', "", "External database table for authentication");
    add_option('pp_db_namefield', "", "External database field for username");
    add_option('pp_db_pwfield', "", "External database field for password");
    add_option('pp_db_first_name', "");
    add_option('pp_db_last_name', "");
    add_option('pp_db_user_url', "");
    add_option('pp_db_user_email', "");
    add_option('pp_db_description', "");
    add_option('pp_db_aim', "");
    add_option('pp_db_yim', "");
    add_option('pp_db_jabber', "");
    add_option('pp_db_enc', "", "Type of encoding for external db (default SHA1? or MD5?)");
    add_option('pp_db_other_enc', "");
    add_option('pp_db_error_msg', "", "Custom login message");
    add_option('pp_db_role_bool', '');
    add_option('pp_db_role', '');
    add_option('pp_db_role_value', '');
    add_option('pp_db_site_url', '');
}

function pp_db_auth_init()
{
    register_setting('pp_db_auth', 'pp_db_type');
    register_setting('pp_db_auth', 'pp_db_mdb2_path');
    register_setting('pp_db_auth', 'pp_host');
    register_setting('pp_db_auth', 'pp_db_port');
    register_setting('pp_db_auth', 'pp_db');
    register_setting('pp_db_auth', 'pp_db_user');
    register_setting('pp_db_auth', 'pp_db_pw');
    register_setting('pp_db_auth', 'pp_db_table');
    register_setting('pp_db_auth', 'pp_db_namefield');
    register_setting('pp_db_auth', 'pp_db_pwfield');
    register_setting('pp_db_auth', 'pp_db_first_name');
    register_setting('pp_db_auth', 'pp_db_last_name');
    register_setting('pp_db_auth', 'pp_db_user_url');
    register_setting('pp_db_auth', 'pp_db_user_email');
    register_setting('pp_db_auth', 'pp_db_description');
    register_setting('pp_db_auth', 'pp_db_aim');
    register_setting('pp_db_auth', 'pp_db_yim');
    register_setting('pp_db_auth', 'pp_db_jabber');
    register_setting('pp_db_auth', 'pp_db_enc');
    register_setting('pp_db_auth', 'pp_db_other_enc');
    register_setting('pp_db_auth', 'pp_db_error_msg');
    register_setting('pp_db_auth', 'pp_db_role');
    register_setting('pp_db_auth', 'pp_db_role_bool');
    register_setting('pp_db_auth', 'pp_db_role_value');
    register_setting('pp_db_auth', 'pp_db_site_url');
}

//page for config menu
function pp_db_auth_add_menu()
{
    add_options_page("External DB settings", "External DB settings", 'manage_options', __FILE__, "pp_db_auth_display_options");
}

//actual configuration screen
function pp_db_auth_display_options()
{
    $db_types[] = "MySQL";
    $db_types[] = "MSSQL";
    $db_types[] = "PgSQL";

    ?>
    <div class="wrap">
        <h2><?php _e('External Database Authentication Settings'); ?></h2>        
        <form method="post" action="options.php">
    <?php settings_fields('pp_db_auth'); ?>
            <h3><?php _e('External Database Settings'); ?></h3>
            <strong><?php _e('Make sure your WP admin account exists in the external db prior to saving these settings.'); ?></strong>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><?php _e('Database type'); ?></th>
                    <td><select name="pp_db_type" >
                            <?php
                            foreach ($db_types as $key => $value) { //print out radio buttons
                                if ($value == get_option('pp_db_type'))
                                    echo '<option value="' . $value . '" selected="selected">' . $value . '<br/>';
                                else
                                    echo '<option value="' . $value . '">' . $value . '<br/>';;
                            }

                            ?>
                        </select> 
                    </td>
                    <td>
                        <span class="description"><strong style="color:red;"><?php _e('required'); ?></strong>; <?php _e('If not MySQL, requires'); ?> <a href="http://pear.php.net/package/MDB2/" target="new"><?php _e('PEAR MDB2 package'); ?></a> <?php _e('and relevant database driver package installation.'); ?></span>
                    </td>
                </tr>        
                <tr valign="top">
                    <th scope="row"><label><?php _e('Path to MDB2.php'); ?></label></th>
                    <td><input type="text" name="pp_db_mdb2_path" value="<?php echo get_option('pp_db_mdb2_path'); ?>" /> </td>
                    <td><span class="description"><?php _e('Only when using non-MySQL database and in case this isn\'t in some sort of include path in your PHP configuration.  No trailing slash! e.g., /home/username/php'); ?></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Host'); ?></label></th>
                    <td><input type="text" name="pp_host" value="<?php echo get_option('pp_host'); ?>" /> </td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong>; <?php _e('(often localhost)'); ?></span> </td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Port'); ?></label></th>
                    <td><input type="text" name="pp_db_port" value="<?php echo get_option('pp_db_port'); ?>" /> </td>
                    <td><span class="description"><?php _e('Only set this if you have a non-standard port for connecting.'); ?></span></td>
                </tr>        
                <tr valign="top">
                    <th scope="row"><label><?php _e('Name'); ?></label></th>
                    <td><input type="text" name="pp_db" value="<?php echo get_option('pp_db'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Username'); ?></label></th>
                    <td><input type="text" name="pp_db_user" value="<?php echo get_option('pp_db_user'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong>; <?php _e('(recommend select privileges only)'); ?></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Password'); ?></label></th>
                    <td><input type="password" name="pp_db_pw" value="<?php echo get_option('pp_db_pw'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('User table'); ?></label></th>
                    <td><input type="text" name="pp_db_table" value="<?php echo get_option('pp_db_table'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span></td>
                </tr>
            </table>

            <h3><?php _e('External Database Source Fields'); ?></h3>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><label><?php _e('Username'); ?></label></th>
                    <td><input type="text" name="pp_db_namefield" value="<?php echo get_option('pp_db_namefield'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Password'); ?></label></th>
                    <td><input type="text" name="pp_db_pwfield" value="<?php echo get_option('pp_db_pwfield'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span><td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php _e('Password encryption method'); ?></th>
                    <td><select name="pp_db_enc">
                            <?php
                            switch (get_option('pp_db_enc')) {
                                case "SHA1" :
                                    echo '<option selected="selected">SHA1</option><option>MD5</option><option>HASH</option><option>PHPass</option><option>Other</option>';
                                    break;
                                case "MD5" :
                                    echo '<option>SHA1</option><option selected="selected">MD5</option><option>HASH</option><option>PHPass</option><option>Other</option>';
                                    break;
                                case "HASH" :
                                    echo '<option>SHA1</option><option>MD5</option><option selected="selected">HASH</option><option>PHPass</option><option>Other</option>';
                                    break;
                                case "PHPass" :
                                    echo '<option>SHA1</option><option>MD5</option><option>HASH</option><option selected="selected">PHPass</option><option>Other</option>';
                                    break;
                                case "Other" :
                                    echo '<option>SHA1</option><option>MD5</option><option>HASH</option><option>PHPass</option><option selected="selected">Other</option>';
                                    break;
                                default :
                                    echo '<option>SHA1</option><option>MD5</option><option selected="selected">HASH</option><option>PHPass</option><option>Other</option>';
                                    break;
                            }

                            ?>
                        </select></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong>; <?php _e('using "Other" requires you to enter PHP code below!)'); ?></td>            
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Hash code'); ?></label></th>
                    <td><input type="text" name="pp_db_other_enc" size="50" value="<?php echo get_option('pp_db_other_enc'); ?>" /></td>
                    <td><span class="description"><?php _e('Only will run if "Other" is selected and needs to be PHP code. Variable you need to set is $password2, and you have access to (original) $username and $password.'); ?></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Role check'); ?></label></th>
                    <td><input type="text" name="pp_db_role" value="<?php echo get_option('pp_db_role'); ?>" />
                        <br />
                        <select name="pp_db_role_bool">
                            <?php
                            switch (get_option('pp_db_role_bool')) {
                                case "is" :
                                    echo '<option selected="selected">is</option><option>greater than</option><option>less than</option>';
                                    break;
                                case "greater than" :
                                    echo '<option>is</option><option selected="selected">greater than</option><option>less than</option>';
                                    break;
                                case "less than" :
                                    echo '<option>is</option><option>greater than</option><option selected="selected">less than</option>';
                                    break;
                                default :
                                    echo '<option selected="selected">is</option><option>greater than</option><option>less than</option>';
                                    break;
                            }

                            ?>
                        </select><br />
                        <input type="text" name="pp_db_role_value" value="<?php echo get_option('pp_db_role_value'); ?>" /></td>
                    <td><span class="description"><?php _e('Use this if you have certain user role ids in your external database to further restrict allowed logins.  If unused, leave fields blank.'); ?></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('First name'); ?></label></th>
                    <td><input type="text" name="pp_db_first_name" value="<?php echo get_option('pp_db_first_name'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Last name'); ?></label></th>
                    <td><input type="text" name="pp_db_last_name" value="<?php echo get_option('pp_db_last_name'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Homepage'); ?></label></th>
                    <td><input type="text" name="pp_db_user_url" value="<?php echo get_option('pp_db_user_url'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Email'); ?></label></th>
                    <td><input type="text" name="pp_db_user_email" value="<?php echo get_option('pp_db_user_email'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('Bio/description'); ?></label></th>
                    <td><input type="text" name="pp_db_description" value="<?php echo get_option('pp_db_description'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('AIM screen name'); ?></label></th>
                    <td><input type="text" name="pp_db_aim" value="<?php echo get_option('pp_db_aim'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('YIM screen name'); ?></label></th>
                    <td><input type="text" name="pp_db_yim" value="<?php echo get_option('pp_db_yim'); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><label><?php _e('JABBER screen name'); ?></label></th>
                    <td><input type="text" name="pp_db_jabber" value="<?php echo get_option('pp_db_jabber'); ?>" /></td>
                </tr>
            </table>
            <h3><?php _e('Other'); ?></h3>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><label><?php _e('External Site URL'); ?></label></th>
                    <td><input type="text" name="pp_db_site_url" value="<?php echo get_option('pp_db_site_url'); ?>" /></td>
                    <td><span class="description"><strong style="color:red;"><?php _e('required'); ?></strong></span></td>
                </tr>
                <tr valign="top">
                    <th scope="row"><?php _e('Custom login message'); ?></th>
                    <td><textarea name="pp_db_error_msg" cols=40 rows=4><?php echo htmlspecialchars(get_option('pp_db_error_msg')); ?></textarea></td>
                    <td><span class="description"><?php _e('Shows up in login box, e.g., to tell them where to get an account. You can use HTML in this text.'); ?></td>
                </tr>        
            </table>

            <p class="submit">
                <input type="submit" name="Submit" value="Save changes" />
            </p>
        </form>
    </div>
    <?php
}

//sort-of wrapper for all DB interactions
function db_functions($driver, $process, $resource, $query)
{
    $host = get_option('pp_host');
    $user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    
    if ($driver == "MySQL") { //use built-in PHP mysqli connection
        switch ($process) {
            case "connect" :
                $port = get_option('pp_db_port');
                if (!empty($port))
                    $port = ":" . get_option('pp_db_port');
                $resource = mysqli_connect($host, $user, $pass, $db) or die("Error " . mysqli_error($resource));
                return $resource;
                break;
            case "query":
                $result = $resource->query($query) or die("Error " . mysqli_error($resource));
                return $result;
                break;
            case "numrows":
                return mysqli_num_rows($resource);
                break;
            case "fetch":
                return mysqli_fetch_assoc($resource);
                break;
            case "close":
                mysqli_close($resource);
                break;
        }
    }
    else {  //Use MDB2   
        $mdbpath = get_option('pp_db_mdb2_path') . "/MDB2.php";
        require_once($mdbpath);
        switch ($process) {
            case "connect" :
                $port = get_option('pp_db_port');
                if (!empty($port))
                    $port = ":" . get_option('pp_db_port');
                $url = strtolower($driver) . "://" . get_option('pp_db_user') . ":" . get_option('pp_db_pw') . "@" . get_option('pp_host') . $port . "/" . get_option('pp_db');
                $resource = & MDB2::connect($url);
                if (PEAR::isError($resource))
                    die("Error while connecting : " . $resource->getMessage());
                return $resource;
                break;
            case "query":
                $result = $resource->query($query);
                if (PEAR::isError($result))
                    die('Failed to issue query, error message : ' . $result->getMessage());
                return $result;
                break;
            case "numrows":
                return $resource->numRows();
                break;
            case "fetch":
                return $resource->fetchRow(MDB2_FETCHMODE_ASSOC);
                break;
            case "close":
                $resource->disconnect();
                break;
        }
    }
}

function pp_hash_password($password)
{
    // By default, use the portable hash from phpass
    $pp_hasher = new PasswordHash(8, FALSE);

    return $pp_hasher->HashPassword($password);
}

function pp_check_password($password, $hash, $user_id = '')
{

    // If the hash is still md5...
    if (strlen($hash) <= 32) {
        $check = ( $hash == md5($password) );
        if ($check && $user_id) {
            // Rehash using new hash.
            pp_set_password($password, $user_id);
            $hash = pp_hash_password($password);
        }

        return apply_filters('check_password', $check, $password, $hash, $user_id);
    }

    // If the stored hash is longer than an MD5, presume the
    // new style phpass portable hash.
    $pp_hasher = new PasswordHash(8, FALSE);

    $check = $pp_hasher->CheckPassword($password, $hash);

    return apply_filters('check_password', $check, $password, $hash, $user_id);
}


//	Function that returns the assoc array of field values for row where username matches $username.
//
//	@$username	Username of the row to fecth in the database.
//	@Returns	Key=>Value array for selected row, 0 (zero) if no entry matched $username, or False on error.

function pp_db_user_info( $username = '' ) {
	
	if( empty($username) ) return false;
	
	$host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $db_table = get_option('pp_db_table');
    $uname = get_option('pp_db_namefield');
    
    $db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
    $res = mysqli_query($db_link, "SELECT * FROM `" . $db_table . "` WHERE $uname = '" . $username . "'");
    if( $res === false ) return false;
    if( mysqli_num_rows($res) == 0 ) return 0;
    $row = mysqli_fetch_assoc($res);
    if( $row === false ) return false;
    return count($row);
    
}


//	Function that checks if $username exists in user table.
//	Returns associative array of rows matching username,  empty array if none was found,
//	or False on error.
function pp_db_check_username($username = '') {
	
	if( empty($username) ) return false;
	
	$host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $db_table = get_option('pp_db_table');
    $uname = get_option('pp_db_namefield');
    
    $db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
    $res = mysqli_query($db_link, "SELECT * FROM `" . $db_table . "` WHERE $uname = '" . $username . "'");
    $entries = array();
    while($row = mysqli_fetch_assoc($res)) {
    	if( $row == false ) return false;
    	$entries[] = $row;
    }
    return $entries;
    
}

// Function that checks if $email exists in user table.
// Returns row count where email field's value corresponds to $email argument.
function pp_db_check_email($email = '') {
	
	if( empty($email) ) return false;
	
	$host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $db_table = get_option('pp_db_table');
    $umail = get_option('pp_db_user_email');
    
    $db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
    $res = mysqli_query($db_link, "SELECT * FROM `" . $db_table . "` WHERE $umail = '" . $email . "'");
    $entries = array();
    while($row = mysqli_fetch_assoc($res)) {
    	if( $row == false ) return false;
    	$entries[] = $row;
    }
    return $entries;
    
}

function pp_db_edit_user_profile( $user ) {
	?>
		<table class="form-table">
			<tr>
				<th><label><?php _e('Répertoire d\'authentification','pp_db');?></label></th>
				<td>
					<?php
						echo '<input type="text" name="directory_service" id="directory_service" value="'.esc_html(get_user_meta($user->ID,'directory_service',true)).'" class="regular-text code" disabled/>';
					?>
					<p class="description">
						<?php _e('Service d\'authentification pour ce compte (e.g. "sim.umontreal.ca" ou "labo23.med.umontreal.ca").','pp_db'); ?>
					</p>
				</td>
			</tr>
		</table>
	<?php 
}

//	Function that creates user in external database upon registration if no error occured.
//
//	It is primordial that this hook runs after all other hooks for this action across plugins.
//
//	Action(s): registration_errors
function pp_db_registration_errors( $errors = NULL, $username = '', $email = '' ) {
	
	if( !is_object($errors) ) $errors = new WP_Error();
	if( empty($username) ) $errors->add('pp_db_empty_username', __('Username must be provided.'));
	if( empty($email) ) $errors->add('pp_db_empty_email', __('Email address must be provided.'));
	
	//$errors->add('pp_db_user_1', __('POST:<br/>'.serialize($_POST).'<br/>'));
	//$errors->add('pp_db_user_2', __('User:<br/>'.serialize($old_user).'<br/>'));
	
	//	Check for existing username/password.
	$exists = pp_db_check_username($username);
	if( $exists === false ) {
		$errors->add('pp_db_database_error', __('Error while accessing database.'));
	}
	elseif( is_array($exists) && count($exists) > 0 ) {
		$errors->add('pp_db_username_exists', __('This username is already taken.'));
	}
	
	$exists = pp_db_check_email($email);
	if( $exists === false ) {
		$errors->add('pp_db_database_error', __('Error while accessing database.'));
	}
	elseif( is_array($exists) && count($exists) > 0 ) {
		$errors->add('pp_db_email_exists', __('This email address is already taken.'));
	}
	
	//	Errors indicate another plugin has an account with either same username or email.
	//	Exit.
	$err_code = $errors->get_error_code();
	if( !empty($err_code) ) return $errors;
	
	// Actual user creation in external db. Wordpress handles the WP database.
	//	TODO:	Generate random password.
	//pp_db_register_user( $errors, $username, $email );
	$user = new WP_User(0, $username);
	$user->user_login=$username;
	$user->user_pass=$_POST['user_pass'];
	$user->user_email=$email;
	// Actual user creation in external db. Wordpress handles the WP database.
	//	TODO:	Generate random password.
	if( pp_db_create_user( $errors, $user ) == true ) {
		update_user_meta($user->ID, 'directory_service', get_option('pp_host') );
	}
	
	return $errors;
	
}

//	Function that creates user in external database upon creation in admin panel if no error occured.
//	This function actually launches the 'registration_errors' filter for which a hook is
//	implemented in this plugin. It is in that function that user creation actually occurs.
//
//	It is primordial that this hook runs after all other hooks for this action across plugins.
//
//	External database field updates (as opposed to creation) are handled by those actions:
//		personnal_options_update
//		edit_user_profile_update
//
//	Action(s): user_profile_update_errors
function pp_db_user_profile_update_errors( $errors, $update, $user ) {
	
	$err_code = $errors->get_error_code();
	if( !empty($err_code) ) return;
	
	//	Get current user account values (throw error if none found during a user update
	//	since it should exist).
	$old_user = get_userdata($user->ID);
	if( $update == true && $old_user === false ) {
		$errors->add('pp_db_user_update_error', __('Could not find user in Wordpress database.'));
	}
	
	//$errors->add('pp_db_user_1', __('User:<br/>'.serialize($user).'<br/>'));
	//$errors->add('pp_db_user_2', __('User:<br/>'.serialize($old_user).'<br/>'));
	
	//	Make sure user login is in the values.
	if( !isset($user->user_login) || empty($user->user_login) ) {
		$user->user_login = $old_user->user_login;
	}
	
	//	Check if we are updating an account's email address.
	$update_email = false;
	if( !empty($user->user_email) && $update && $user->user_email != $old_user->user_email ) {
		$update_email = true;
	}
	
	$field_username = get_option('pp_db_namefield');
	$field_email = get_option('pp_db_user_email');
	
	//	Check for existing username/email.
	$match = false;
	$entries = pp_db_check_username($user->user_login);
	if( $entries === false ) {
		$errors->add('pp_db_database_error', __('Error while accessing database.'));
	}
	elseif( is_array($entries) && count($entries) > 0 ) {
		if( $entries[0][$field_email] == $user->user_email || ( $update_email == true && $entries[0][$field_email] == $old_user->user_email ) ) {
			$match = true;
		}
		else {
			$errors->add('pp_db_username_nomatch', __('Username already exist in external database, but provided email does not match account information.'));
		}
	}
	if( $match == false ) {
		$entries = pp_db_check_email($user->user_email);
		if( $entries === false ) {
			$errors->add('pp_db_database_error', __('Error while accessing database.'));
		}
		elseif( is_array($entries) && count($entries) > 0 ) {
			$errors->add('pp_db_email_nomatch', __('Email already exist in external database, but provided username does not match account information.'));
		}
	}
	
	//	Exit if an error occured.
	$err_code = $errors->get_error_code();
	if( !empty($err_code) ) return;
	
	//	Could not find existing account match in external db.
	if( $match == false ) {
		
		//	Wordpress is updating a record that is not handled by this plugin.
		//	Exit.
		if( $update == true ) return;
		
		
		//	Creating a new user.
		//	Check if user should be created in external db, or if it already exists in 
		//	a database handled by another plugin. Normally, the 'registration_errors' filter
		//	in a plugin *should* check for existing username/email.
		//$err = new WP_Error();
		remove_filter( 'registration_errors', 'pp_db_registration_errors', 99999 );
		apply_filters( 'registration_errors', $errors, $user->user_login, $user->user_email );
		add_filter('registration_errors', 'pp_db_registration_errors', 99999, 3);
		
		//	Errors indicate another plugin has an account with either same username or email (but not both).
		//	Exit.
		//$err_code = $err->get_error_code();
		$err_code = $errors->get_error_code();
		if( !empty($err_code) ) return $errors;
		
		// Actual user creation in external db. Wordpress handles the WP database.
		//	TODO:	Generate random password.
		if( pp_db_create_user( $errors, $user, $match ) == true ) {
			update_user_meta($user->ID, 'directory_service', get_option('pp_host') );
		}
		else {
			$errors->add('pp_db_database_error', __('External account creation error.'));
		}
		
		
		
	}
	else {	// $match == true
		
		//	Account matched in external db. Wheter WP is attempting to update user info
		//	or creating a new record in its internal database, we have to update external
		//	database.
		if( pp_db_create_user( $errors, $user, $match ) == true ) {
			update_user_meta($user->ID, 'directory_service', get_option('pp_host') );
		}
		
	}
	
}

//	Function that creates/updates a user record in external database.
//	TODO:	Handle validating password before update.
//	Returns true on success, false on error.
function pp_db_create_user( &$errors = NULL, $user = NULL, $update = NULL ) {
	
	if( !is_object($user) ) return false;
	if( !is_object($errors) ) $errors = new WP_Error();
	
	//	Retreive old user values.
	//	Should be required only if $update==false,
	//	but I don't feel like checking right now ;)
	if( isset($user->ID) && !empty($user->ID) ) {
		$old_user = get_userdata($user->ID);
	}
	
	//	Set user login if not set.
	if( !isset($user->user_login) || empty($user->user_login) ) {
		if( !is_object($old_user) || empty($old_user->user_login) ) {
			$errors->add('pp_db_create_user_error', __('Username must be provided.'));
			return false;
		}
		$user->user_login = $old_user->user_login;
	}
	
	$host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $db_table = get_option('pp_db_table');
    $field_username = get_option('pp_db_namefield');
    $field_password = get_option('pp_db_pwfield');
    $field_email = get_option('pp_db_user_email');
    $field_firstname = get_option('pp_db_first_name');
    $field_lastname = get_option('pp_db_last_name');
    
    $fields = array();
    if( $update == false ) $fields[$field_username] = $user->user_login;
    if( $update == false ) {
    	if( !empty($user->user_pass) ) {
    		$fields[$field_password] = md5($user->user_pass);
    	}
    	else {
    		$fields[$field_password] = md5(generate_password());
    	}
    }
    $fields[$field_email] = $user->user_email;
    $fields[$field_firstname] = $user->first_name;
    $fields[$field_lastname] = $user->last_name;
    $sql_set = '';
	foreach( $fields as $key => $value ) {
		if( empty($value) ) {
			unset( $fields[$key] );
		}
		else {
			$sql_set .= ", `$key`='$value'";
		}
	}
	
	//	No values to create/update.
	//	Should never happen but we're being cautious.
	if( empty($sql_set) ) {
		$errors->add('pp_db_connect_error', __('Error while updating/creating user: no values to store in record.'));
		return false;
	}
	$sql_set = substr($sql_set, 2);	//Remove heading ', ';
	
    if( $update == true ) {
    	
    	//	We're actually just updating a record, not creating a new one.
	    $sql = "UPDATE `{$db_table}` SET $sql_set WHERE `{$field_username}`='{$user->user_login}'";
	    
	}
	else {
		
		//	Create a new user record in external db.
		$sql = "INSERT INTO `{$db_table}` SET $sql_set";
		
	}
	
	$db_link = mysqli_connect($host, $db_user, $pass, $db);
	if( $db_link === false ) {
		$errors->add('pp_db_connect_error', __('Error while connecting to external database:<br/>'.mysqli_error($db_link)));
		return false;
	}
    $res = mysqli_query($db_link, $sql);
    if( $res === false ) {
    	$errors->add('pp_db_query_error', __('Error while executing query on external database:<br/>'.mysqli_error($db_link)));
    	return false;
    }
    elseif( mysqli_affected_rows($db_link) == 0 ) {
    	$errors->add('pp_db_update_error', __('Error while creating/updating external database account:<br/>'.mysqli_error($db_link)));
    	return false;
    }
    
    return true;
    
}

//	Function that stores username/email in external db upon self-registration.
function pp_db_register_user( $errors, $username, $email ) {

	if( !is_object($errors) ) $errors = new WP_Error();
	
	$host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $db_table = get_option('pp_db_table');
    $field_username = get_option('pp_db_namefield');
    $field_email = get_option('pp_db_user_email');
	
    $sql = "INSERT INTO `{$db_table}` (`{$field_username}`,`{$field_email}`) VALUES ('{$username}', '{$email}')";
	$db_link = mysqli_connect($host, $db_user, $pass, $db);
	if( $db_link === false ) {
		$errors->add('pp_db_connect_error', __('Error while connecting to external database:<br/>'.mysqli_error($db_link)));
		return false;
	}
    $res = mysqli_query($db_link, $sql);
    if( $res === false ) {
    	$errors->add('pp_db_query_error', __('Error while executing query on external database:<br/>'.mysqli_error($db_link)));
    	return false;
    }
    elseif( mysqli_affected_rows($db_link) == 0 ) {
    	$errors->add('pp_db_update_error', __('Error while creating/updating external database account:<br/>'.mysqli_error($db_link)));
    	return false;
    }
    
    return true;
    
}

/**
 * Generates a random password.
 * 
 * @param int $length Length of the password
 * @return password as string
 */
function generate_password($length = 10) {
	return substr(md5(uniqid(microtime())), 0, $length);
}

//actual meat of plugin - essentially, you're setting $username and $password to pass on to the system.
//You check from your external system and insert/update users into the WP system just before WP actually
//authenticates with its own database.
function pp_db_auth_check_login($user = NULL, $username = '', $password = '')
{
    
    $host = get_option('pp_host');
    $db_user = get_option('pp_db_user');
    $pass = get_option('pp_db_pw');
    $db = get_option('pp_db');
    $uname = get_option('pp_db_namefield');
    $upass = get_option('pp_db_pwfield');

    $resource = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($resource));

    $pp_hasher = new PasswordHash(8, FALSE);

    $mem = get_option('pp_db_table');

    $sql = mysqli_query($resource, "SELECT $uname, $upass FROM `" . $mem . "` WHERE $uname = '" . $username . "'");

    $row = mysqli_fetch_assoc($sql);

    //first figure out the DB type and connect...
    $driver = get_option('pp_db_type');
    //if on same host have to use resource id to make sure you don't lose the wp db connection        

    $mdbpath = get_option('pp_db_mdb2_path') . "/MDB2.php";
    if ($mdbpath != "/MDB2.php")
        require_once($mdbpath);

    $resource = db_functions($driver, "connect", "", "");
    //prepare the db for unicode queries
    //to pick up umlauts, non-latin text, etc., without choking
    $utfquery = "SET NAMES 'utf8'";
    $resultutf = db_functions($driver, "query", $resource, $utfquery);

    //do the password hash for comparing
    switch (get_option('pp_db_enc')) {
        case "SHA1" :
            $password2 = sha1($password);
            break;
        case "MD5" :
            $password2 = md5($password);
            break;
        case "HASH" :
            $password2 = pp_check_password($password, $row['password']);
            break;
        case "PHPass" :
            $password2 = pp_check_password($password, $row['password']);
            break;
        case "Other" :             //right now defaulting to plaintext.  People can change code here for their own special hash
            eval(get_option('pp_db_other_enc'));
            break;
    }
	
    //first check to see if login exists in external db
    $query = "SELECT count(*) AS numrows FROM " . get_option('pp_db_table') . " WHERE " . get_option('pp_db_namefield') . " = '$username'";
    $result = db_functions($driver, "query", $resource, $query);
    $numrows = db_functions($driver, "fetch", $result, "");
    $numrows = $numrows["numrows"];

    if ($numrows) {
        //then check to see if pw matches and get other fields...
        $sqlfields['first_name'] = get_option('pp_db_first_name');
        $sqlfields['last_name'] = get_option('pp_db_last_name');
        $sqlfields['user_url'] = get_option('pp_db_user_url');
        $sqlfields['user_email'] = get_option('pp_db_user_email');
        $sqlfields['description'] = get_option('pp_db_description');
        $sqlfields['aim'] = get_option('pp_db_aim');
        $sqlfields['yim'] = get_option('pp_db_yim');
        $sqlfields['jabber'] = get_option('pp_db_jabber');
        $sqlfields['pp_db_role'] = get_option('pp_db_role');

        foreach ($sqlfields as $key => $value) {
            if ($value == "")
                unset($sqlfields[$key]);
        }
        $sqlfields2 = implode(", ", $sqlfields);

        //just so queries won't error out if there are no relevant fields for extended data.
        if (empty($sqlfields2))
            $sqlfields2 = get_option('pp_db_namefield');

        if (get_option('pp_db_enc') == 'HASH') {
            $query = "SELECT $sqlfields2 FROM " . get_option('pp_db_table') . " WHERE " . get_option('pp_db_namefield') . " = '$username' AND active = '1'";
            $result = db_functions($driver, "query", $resource, $query);
            $numrows = db_functions($driver, "numrows", $result, "");
        } elseif (get_option('pp_db_enc') == 'PHPass') {
            $query = "SELECT $sqlfields2 FROM " . get_option('pp_db_table') . " WHERE " . get_option('pp_db_namefield') . " = '$username'";
            $result = db_functions($driver, "query", $resource, $query);
            $numrows = db_functions($driver, "numrows", $result, "");
        } elseif (get_option('pp_db_enc') == 'SHA1' || get_option('pp_db_enc') == 'MD5') {
            $query = "SELECT $sqlfields2 FROM " . get_option('pp_db_table') . " WHERE " . get_option('pp_db_namefield') . " = '$username' AND " . get_option('pp_db_pwfield') . " = '$password2'";
            $result = db_functions($driver, "query", $resource, $query);
            $numrows = db_functions($driver, "numrows", $result, "");
        } elseif (get_option('pp_db_enc') == 'Other') {
            $query = "SELECT $sqlfields2 FROM " . get_option('pp_db_table') . " WHERE " . get_option('pp_db_namefield') . " = '$username' AND " . get_option('pp_db_pwfield') . " = '$password2'";
            $result = db_functions($driver, "query", $resource, $query);
            $numrows = db_functions($driver, "numrows", $result, "");
        }
		
        if ($numrows) {    //create/update wp account from external database if login/pw exact match exists in that db	
            $extfields = db_functions($driver, "fetch", $result, "");
            $process = TRUE;

            //check role, if present.
            $role = get_option('pp_db_role');
            if (!empty($role)) { //build the role checker too					
                $rolevalue = $extfields[$sqlfields['pp_db_role']];
                $rolethresh = get_option('pp_db_role_value');
                $rolebool = get_option('pp_db_role_bool');
                global $pp_error;
                if ($rolebool == 'is') {
                    if ($rolevalue == $rolethresh) {
                        
                    } else {
                        $username = NULL;
                        $pp_error = "wrongrole";
                        $process = FALSE;
                    }
                }
                if ($rolebool == 'greater than') {
                    if ($rolevalue > $rolethresh) {
                        
                    } else {
                        $username = NULL;
                        $pp_error = "wrongrole";
                        $process = FALSE;
                    }
                }
                if ($rolebool == 'less than') {
                    if ($rolevalue < $rolethresh) {
                        
                    } else {
                        $username = NULL;
                        $pp_error = "wrongrole";
                        $process = FALSE;
                    }
                }
            }
            //only continue with user update/creation if login/pw is valid AND, if used, proper role perms
            if ((get_option('pp_db_enc') == 'HASH' || get_option('pp_db_enc') == 'PHPass') && pp_check_password($password, $row['password'])) {
                if ($process) {
                    $userarray['user_login'] = $username;
                    $userarray['user_pass'] = $password;
                    $userarray['first_name'] = $extfields[$sqlfields['first_name']];
                    $userarray['last_name'] = $extfields[$sqlfields['last_name']];
                    $userarray['user_url'] = $extfields[$sqlfields['user_url']];
                    $userarray['user_email'] = $extfields[$sqlfields['user_email']];
                    $userarray['description'] = $extfields[$sqlfields['description']];
                    $userarray['aim'] = $extfields[$sqlfields['aim']];
                    $userarray['yim'] = $extfields[$sqlfields['yim']];
                    $userarray['jabber'] = $extfields[$sqlfields['jabber']];
                    $userarray['display_name'] = $extfields[$sqlfields['first_name']] . " " . $extfields[$sqlfields['last_name']];

                    //also if no extended data fields
                    if ($userarray['display_name'] == " ")
                        $userarray['display_name'] = $username;

                    db_functions($driver, "close", $resource, "");

                    //looks like wp functions clean up data before entry, so I'm not going to try to clean out fields beforehand.
                    if ($id = username_exists($username)) {   //just do an update
                        $userarray['ID'] = $id;
                        wp_update_user($userarray);
                    } else
                        wp_insert_user($userarray);          //otherwise create
                }
            }

            if (get_option('pp_db_enc') == 'MD5' || get_option('pp_db_enc') == 'SHA1') {
                if ($process) {
                    $userarray['user_login'] = $username;
                    $userarray['user_pass'] = $password;
                    $userarray['first_name'] = $extfields[$sqlfields['first_name']];
                    $userarray['last_name'] = $extfields[$sqlfields['last_name']];
                    $userarray['user_url'] = $extfields[$sqlfields['user_url']];
                    $userarray['user_email'] = $extfields[$sqlfields['user_email']];
                    $userarray['description'] = $extfields[$sqlfields['description']];
                    $userarray['aim'] = $extfields[$sqlfields['aim']];
                    $userarray['yim'] = $extfields[$sqlfields['yim']];
                    $userarray['jabber'] = $extfields[$sqlfields['jabber']];
                    $userarray['display_name'] = $extfields[$sqlfields['first_name']] . " " . $extfields[$sqlfields['last_name']];

                    //also if no extended data fields
                    if ($userarray['display_name'] == " ")
                        $userarray['display_name'] = $username;

                    db_functions($driver, "close", $resource, "");

                    //looks like wp functions clean up data before entry, so I'm not going to try to clean out fields beforehand.
                    if ($id = username_exists($username)) {   //just do an update
                        $userarray['ID'] = $id;
                        wp_update_user($userarray);
                    } else
                        wp_insert_user($userarray);
                }
            }

            if (get_option('pp_db_enc') == 'Other') {
                if ($process) {
                    $userarray['user_login'] = $username;
                    $userarray['user_pass'] = $password;
                    $userarray['first_name'] = $extfields[$sqlfields['first_name']];
                    $userarray['last_name'] = $extfields[$sqlfields['last_name']];
                    $userarray['user_url'] = $extfields[$sqlfields['user_url']];
                    $userarray['user_email'] = $extfields[$sqlfields['user_email']];
                    $userarray['description'] = $extfields[$sqlfields['description']];
                    $userarray['aim'] = $extfields[$sqlfields['aim']];
                    $userarray['yim'] = $extfields[$sqlfields['yim']];
                    $userarray['jabber'] = $extfields[$sqlfields['jabber']];
                    $userarray['display_name'] = $extfields[$sqlfields['first_name']] . " " . $extfields[$sqlfields['last_name']];

                    //also if no extended data fields
                    if ($userarray['display_name'] == " ")
                        $userarray['display_name'] = $username;

                    db_functions($driver, "close", $resource, "");

                    //looks like wp functions clean up data before entry, so I'm not going to try to clean out fields beforehand.
                    if ($id = username_exists($username)) {   //just do an update
                        $userarray['ID'] = $id;
                        wp_update_user($userarray);
                    } else
                        wp_insert_user($userarray);
                }
            }
            
            if ($id = username_exists($username)) {
            	$user = new WP_User($id);
            	update_user_meta($id, 'directory_service', get_option('pp_host'));
            	return $user;
            }
            
        }
        else { //username exists but wrong password...	
            global $pp_error;
            $pp_error = "wrongpw";
            return false;
        }
    } else {  //don't let login even if it's in the WP db - it needs to come only from the external db.
        global $pp_error;
        $pp_error = "notindb";
        return false;
    }
    //}  
}

//gives warning for login - where to get "source" login
function pp_db_auth_warning($message = '')
{
    $message .= "<p class=\"message\">" . get_option('pp_db_error_msg') . "</p>";
    return $message;
}

function pp_db_errors( $error = '' )
{
    global $pp_error;
	
	/*
    if ($pp_error == "notindb") {
        return $error;
    }
    */
    if ($pp_error == "wrongrole") {
        $error = "<strong>ERROR:</strong> You don't have permissions to log in.";
    }
    if ($pp_error == "wrongpw") {
        $error = "<strong>ERROR:</strong> Invalid password.";
    }
    
    return $error;
    
}

//hopefully grays stuff out.
function pp_db_warning()
{
    echo '<strong style="color:red;">Any changes made below WILL NOT be preserved when you login again. You have to change your personal information per instructions found @ <a href="' . get_option('pp_db_site_url') . '">login box</a>.</strong>';
}

//disables the (useless) password reset option in WP when this plugin is enabled.
function pp_db_show_password_fields()
{
    return false;
}
/*
 * Disable functions.  Idea taken from http auth plugin.
 */

/*
function disable_function_register()
{
    $errors = new WP_Error();
    $errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));

    ?></form><br /><div id="login_error"><?php _e('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'); ?></div>
    <p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display')); ?></a></p>
    <?php
    exit();
}
*/

function disable_function()
{
    $errors = new WP_Error();
    $errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.'));
    login_header(__('Log In'), '', $errors);

    ?>
    <p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display')); ?></a></p>
    <?php
    exit();
}

//	Adds columns headers into the user list.
function pp_db_manage_users_columns($columns) {
	$columns['directory_service'] = __('Authentication', 'pp_db');
	return $columns;
}

//	Adds column content for each user on user list.
//
//	@param mixed $value Value to show
//	@param string $column_name Name of column in user table
//	@param integer $user_id ID of user (the row)  
function pp_db_manage_users_custom_column( $value, $column_name, $user_id ) {

	// Column "Disabled"
	if ( $column_name == 'directory_service' ) {
		$value = get_user_meta($user_id, 'directory_service', true);
		if (empty($value)) {
			$value = 'internal';
		}
	}
	
	return $value;
}	

add_action('admin_init', 'pp_db_auth_init');
add_action('admin_menu', 'pp_db_auth_add_menu');
add_filter('authenticate', 'pp_db_auth_check_login', 10, 3);
add_action('lost_password', 'disable_function');
//add_action('user_register', 'pp_db_register_user');
//add_action('user_register', 'disable_function');
//add_action('register_form', 'disable_function_register');
add_action('retrieve_password', 'disable_function');
add_action('password_reset', 'disable_function');
add_action('profile_personal_options', 'pp_db_warning');
add_filter('login_errors', 'pp_db_errors', 10, 1);
add_filter('show_password_fields', 'pp_db_show_password_fields');
add_filter('login_message', 'pp_db_auth_warning', 10, 1);
add_filter('registration_errors', 'pp_db_registration_errors', 99999, 3);
add_filter('user_profile_update_errors', 'pp_db_user_profile_update_errors', 99999, 3);
add_action('edit_user_profile', 'pp_db_edit_user_profile', 10, 3);
add_filter( 'manage_users_columns', 'pp_db_manage_users_columns', 1, 1 );
add_filter( 'manage_users_custom_column', 'pp_db_manage_users_custom_column', 1, 3 );

register_activation_hook(__FILE__, 'pp_db_auth_activate');
