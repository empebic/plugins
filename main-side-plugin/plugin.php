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
		), 200); // Return failure status if authentication failed
	}

	// If authentication is successful, return user info and encrypted email
	$encryption_secret = get_option('custom_login_encryption_secret');
	if (!$encryption_secret) {
		return new WP_REST_Response('Encryption secret not set.', 500); // Return error if encryption secret is not set
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
		$encryption_secret = get_option('custom_login_encryption_secret'); // Get the encryption secret
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