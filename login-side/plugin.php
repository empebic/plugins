<?php
/**
 * Plugin Name: Login Side
 * Author: Jovan Pebic
 */

/**
 * Shortcode function to display custom login form.
 *
 * @return string The HTML output of the login form.
 */
function custom_login_shortcode()
{
	ob_start();
	?>
	<!-- Custom login form -->
	<form id="custom-login-form">
		<label for="custom-email">Email:</label>
		<input id="custom-email" name="email" required />

		<label for="custom-password">Password:</label>
		<input type="password" id="custom-password" name="password" required />

		<button type="submit">Login</button>
	</form>
	<div id="login-message"></div>
	<script type="text/javascript">
		jQuery(document).ready(function ($) {
			// Handle form submission
			$('#custom-login-form').on('submit', function (e) {
				e.preventDefault();
				var email = $('#custom-email').val();
				var password = $('#custom-password').val();

				// Perform AJAX request to handle login
				$.ajax({
					url: '<?php echo admin_url('admin-ajax.php'); ?>',
					type: 'POST',
					dataType: 'json',
					data: {
						action: 'custom_login_action',
						email: email,
						password: password,
						security: '<?php echo wp_create_nonce("custom_login_nonce"); ?>'
					},
					success: function (response) {
						console.log(response);
						if (response.success) {
							// Redirect on successful login
							//console.log(response);
							window.location.href = response.data.url + '/?logintoken=' + response.data.token;
						} else {
							// Display error message
							$('#login-message').html(response.data.message);
						}
					},
					error: function (xhr, status, error) {
						// Handle AJAX request error
						var errorMessage = xhr.responseJSON && xhr.responseJSON.message ? xhr.responseJSON.message : 'An error occurred: ' + error;
						$('#login-message').html(errorMessage);
					}
				});
			});
		});
	</script>
	<?php
	return ob_get_clean();
}
add_shortcode('custom_login', 'custom_login_shortcode');

/**
 * Handle AJAX request for custom login.
 *
 * @return void
 */
function custom_login_action()
{
	check_ajax_referer('custom_login_nonce', 'security');

	$email = sanitize_text_field($_POST['email']);
	$password = sanitize_text_field($_POST['password']);

	// Retrieve endpoint and encryption secret from options
	$endpoint = get_option('custom_login_endpoint');
	$encryption_secret = get_option('custom_login_encryption_secret');

	if (!$endpoint || !$encryption_secret) {
		wp_send_json_error(array('message' => 'Endpoint or encryption secret not set.'));
	}

	// Perform the request to the API endpoint
	$response = wp_remote_post($endpoint, array(
		'method' => 'POST',
		'body' => json_encode(array(
			'email' => $email,
			'password' => $password
		)),
		'headers' => array(
			'Content-Type' => 'application/json',
			'Accept' => 'application/json',
		)
	));
	if (is_wp_error($response)) {
		// Handle request error
		wp_send_json_error(array('message' => 'Request to API endpoint failed.'));
	} else {
		$response_data = wp_remote_retrieve_body($response);
		$response_array = json_decode($response_data, true);
		if ($response_array['status'] === 'success') {
			// Successfully authenticated; handle success response
			wp_send_json_success(array('token' => $response_array['token'], 'url' => $response_array['url']));
		} else {
			// Authentication failed
			wp_send_json_error(array('message' => 'Invalid login credentials.'));
		}
	}

	wp_die();
}
add_action('wp_ajax_custom_login_action', 'custom_login_action');
add_action('wp_ajax_nopriv_custom_login_action', 'custom_login_action');

/**
 * Add options page for custom login settings.
 *
 * @return void
 */
function custom_login_options_page()
{
	add_options_page(
		'Custom Login Settings',
		'Custom Login',
		'manage_options',
		'custom-login-settings',
		'custom_login_settings_page'
	);
}
add_action('admin_menu', 'custom_login_options_page');

/**
 * Display content for the custom login settings page.
 *
 * @return void
 */
function custom_login_settings_page()
{
	?>
	<div class="wrap">
		<h1>Custom Login Settings</h1>
		<form method="post" action="options.php">
			<?php
			// Display settings fields and sections
			settings_fields('custom_login_settings_group');
			do_settings_sections('custom-login-settings');
			submit_button();
			?>
		</form>
	</div>
	<?php
}

/**
 * Register settings for custom login.
 *
 * @return void
 */
function custom_login_register_settings()
{
	register_setting('custom_login_settings_group', 'custom_login_endpoint');

	add_settings_section(
		'custom_login_settings_section',
		'API Settings',
		null,
		'custom-login-settings'
	);

	add_settings_field(
		'custom_login_endpoint',
		'API Endpoint',
		'custom_login_endpoint_callback',
		'custom-login-settings',
		'custom_login_settings_section'
	);

}
add_action('admin_init', 'custom_login_register_settings');

/**
 * Callback function to display the API endpoint field.
 *
 * @return void
 */
function custom_login_endpoint_callback()
{
	$endpoint = get_option('custom_login_endpoint');
	echo '<input type="text" name="custom_login_endpoint" value="' . esc_attr($endpoint) . '" />';
}