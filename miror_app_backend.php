<?php
/**
 * Plugin Name: Miror App Backend
 * Description: Backend API for the Miror Mobile App using WordPress REST API
 * Version: 1.0.0
 * Author: Anand Patil
 */

define('MIROR_PLUGIN_DIR', plugin_dir_path(__FILE__));

require_once MIROR_PLUGIN_DIR . 'includes/class-miror-controller.php';
require_once MIROR_PLUGIN_DIR . 'includes/class-miror-jwt.php';

add_action('rest_api_init', function () {
    $controller = new Miror_Controller();
    $controller->register_routes();
});

add_action('plugins_loaded', function () {
    load_plugin_textdomain('miror_app_backend', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

// Disable WP JWT plugin if active to avoid conflict
add_action('init', function () {
    if (is_plugin_active('jwt-authentication-for-wp-rest-api/jwt-authentication.php')) {
        deactivate_plugins('jwt-authentication-for-wp-rest-api/jwt-authentication.php');
    }
});
