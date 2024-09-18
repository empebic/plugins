<?php
/**
 * Plugin Name: Main Side
 * Author: Jovan Pebic
 */


// Register REST API endpoint
add_action('rest_api_init', function () {
	// Register a new REST route for custom login
	register_rest_route('custom/v1', '/login', array(
		'methods' => 'POST', // Only allow POST requests
		'callback' => 'custom_login_rest_api_handler', // Function to handle the request
		'permission_callback' => '__return_true', // Open access; add your own permission checks if needed
	));
});

/**
 * Handles the custom login REST API request.
 *
 * @param WP_REST_Request $request The REST API request object.
 * @return WP_REST_Response The response object.
 */
function custom_login_rest_api_handler(WP_REST_Request $request)
{
	// Sanitize and retrieve email and password from the request
	$email = sanitize_text_field($request->get_param('email'));
	$password = sanitize_text_field($request->get_param('password'));

	// Validate email and password
	if (empty($email) || empty($password)) {
		return new WP_REST_Response('Email and password are required.', 400); // Return error if email or password is missing
	}

	// Attempt to authenticate the user
	$user = wp_authenticate($email, $password);

	// Check if authentication failed
	if (is_wp_error($user)) {
		return new WP_REST_Response(array(
			'status' => 'fail',
		), 500); // Return failure status if authentication failed
	}


	// Encrypt the email to generate a token
	$token = encrypt($email);
	$url = get_home_url();
	// Return success status and the token
	return new WP_REST_Response(array(
		'status' => 'success',
		'token' => $token,
		'url' => $url,
	), 200);
}

/**
 * Automatically logs in the user from the email token.
 */
function auto_login_user_from_email()
{
	// Check if the login token is present in the URL
	if (isset($_GET['logintoken'])) {
		$token = $_GET['logintoken']; // Retrieve the token from the URL
		$email = decrypt($token); // Decrypt the token to get the email

		// Validate the email
		if (!is_email($email)) {
			return; // Return if the email is not valid
		}

		// Check if a user exists with this email
		$user = get_user_by('email', $email);
		if ($user) {
			// Log in the user
			wp_set_auth_cookie($user->ID);
			wp_set_current_user($user->ID);

			// Redirect to the homepage or any other page
			wp_redirect(home_url());
			exit;
		}
	}
}
add_action('init', 'auto_login_user_from_email'); // Hook the function to the 'init' action

/**
 * Generates random bytes.
 *
 * @param int $length The length of the random bytes to generate.
 * @return string The generated random bytes.
 */
function generateRandomBytes($length)
{
	return random_bytes($length); // Generate and return random bytes of specified length
}

// Define constants for encryption key and method
define('ENCRYPTION_KEY', 'RHBk8lJRy3MOASacwgPe6z6KsnU5L7Ng'); // Make sure this key is 32 bytes for AES-256
define('ENCRYPTION_METHOD', 'AES-256-CBC'); // AES-256-CBC requires a 16-byte IV

/**
 * Encrypts a plaintext string.
 *
 * @param string $plaintext The text to encrypt.
 * @return string The encrypted text, base64-encoded.
 */
function encrypt($plaintext)
{
	$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(ENCRYPTION_METHOD)); // Generate a random IV
	$ciphertext = openssl_encrypt($plaintext, ENCRYPTION_METHOD, ENCRYPTION_KEY, 0, $iv); // Encrypt the plaintext
	// Combine the IV and the encrypted text, separated by "::", and base64-encode it
	return base64_encode($iv . '::' . $ciphertext);
}

/**
 * Decrypts an encrypted string.
 *
 * @param string $encrypted The encrypted, base64-encoded text.
 * @return string The decrypted text.
 */
function decrypt($encrypted)
{
	// Decode the base64-encoded string
	$data = base64_decode($encrypted);
	// Extract the IV and ciphertext from the decoded data
	list($iv, $ciphertext) = explode('::', $data, 2);
	// Decrypt the ciphertext
	return openssl_decrypt($ciphertext, ENCRYPTION_METHOD, ENCRYPTION_KEY, 0, $iv);
}

/**
 * Registers the custom REST API endpoint for password reset.
 */
function register_reset_password_endpoint()
{
	// Register a new REST route for password reset
	register_rest_route('custom-api/v1', '/reset-password', array(
		'methods' => 'POST', // HTTP method for the endpoint
		'callback' => 'handle_reset_password_request', // Callback function to handle the request
		'permission_callback' => '__return_true', // Permission callback to allow access
	));
}
add_action('rest_api_init', 'register_reset_password_endpoint');

/**
 * Handles the password reset request.
 *
 * @param WP_REST_Request $request The REST request object.
 * @return WP_REST_Response|WP_Error The response object or WP_Error on failure.
 */
function handle_reset_password_request($request)
{
	// Sanitize the email parameter from the request
	$email = sanitize_email($request->get_param('email'));

	// Check if the email is valid
	if (!is_email($email)) {
		return new WP_Error('invalid_email', 'Invalid email address', array('status' => 400));
	}

	// Get the user by email
	$user = get_user_by('email', $email);

	// Check if the user exists
	if (!$user) {
		return new WP_Error('mail_error', 'Failed to send password reset email', array('status' => 400));
	}

	// Generate a password reset key for the user
	$key = get_password_reset_key($user);

	// Check if there was an error generating the key
	if (is_wp_error($key)) {
		return $key;
	// Log the error to the WP debug log
	if (is_wp_error($key)) {
		error_log('Password reset key generation error for user: ' . $user->ID . ' - ' . $key->get_error_message());
		return $key;
	}
	}

	// Generate the password reset link
	$reset_link = network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user->user_login), 'login');
	$subject = 'Password Reset Request'; // Email subject
	$message = 'To reset your password, visit the following address: ' . $reset_link; // Email message

	// Send the password reset email
	$mail_sent = wp_mail($email, $subject, $message);

	// Check if the email was sent successfully
	if ($mail_sent) {
		return new WP_REST_Response(array(
			'status' => 'success',
			'message' => 'Password reset email sent successfully',
		), 200);
	} else {
		return new WP_Error('mail_error', 'Failed to send password reset email', array('status' => 400));
	}
}