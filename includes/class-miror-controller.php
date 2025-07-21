<!-- includes/class-miror-controller.php -->
<?php
class Miror_Controller {

    public function register_routes() {
        register_rest_route('miror/v1', '/register/send-otp', [
            'methods' => 'POST',
            'callback' => [$this, 'send_otp_register'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('miror/v1', '/register/verify-otp', [
            'methods' => 'POST',
            'callback' => [$this, 'verify_otp_register'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('miror/v1', '/login/send-otp', [
            'methods' => 'POST',
            'callback' => [$this, 'send_otp_login'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('miror/v1', '/login/verify-otp', [
            'methods' => 'POST',
            'callback' => [$this, 'verify_otp_login'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('miror/v1', '/user/onboarding', [
            'methods' => 'POST',
            'callback' => [$this, 'user_onboarding'],
            'permission_callback' => [$this, 'authorize_request']
        ]);
    }

    private function generate_otp() {
        return rand(100000, 999999);
    }

    private function get_user_by_email($email) {
        return get_user_by('email', $email);
    }

    private function sanitize_input($input, $type = 'text') {
        switch ($type) {
            case 'email': return sanitize_email($input);
            case 'text': default: return sanitize_text_field($input);
        }
    }

    private function send_otp_email($email, $otp) {
        $subject = 'Your OTP Code';
        $message = 'Your OTP is: ' . $otp;
        wp_mail($email, $subject, $message);
    }

    public function send_otp_register($request) {
        $email = $this->sanitize_input($request['email'], 'email');
        if (!is_email($email)) return new WP_Error('invalid_email', 'Invalid email address.', ['status' => 400]);
        if ($this->get_user_by_email($email)) return new WP_Error('user_exists', 'Email is already registered.', ['status' => 400]);
        $otp = $this->generate_otp();
        set_transient('miror_reg_otp_' . $email, $otp, 10 * MINUTE_IN_SECONDS);
        $this->send_otp_email($email, $otp);
        return rest_ensure_response(['message' => 'OTP sent successfully']);
    }

    public function verify_otp_register($request) {
        $email = $this->sanitize_input($request['email'], 'email');
        $otp = $this->sanitize_input($request['otp']);
        $name = $this->sanitize_input($request['name']);
        $mobile = $this->sanitize_input($request['mobile']);
        $stored_otp = get_transient('miror_reg_otp_' . $email);
        if ($otp != $stored_otp) return new WP_Error('invalid_otp', 'Invalid OTP.', ['status' => 400]);
        $user_id = wp_create_user($email, wp_generate_password(), $email);
        wp_update_user(['ID' => $user_id, 'display_name' => $name]);
        update_user_meta($user_id, 'digits_phone_no', $mobile);
        wp_update_user(['ID' => $user_id, 'role' => 'customer']);
        delete_transient('miror_reg_otp_' . $email);
        $token = Miror_JWT::generate_token($user_id);
        return rest_ensure_response(['token' => $token, 'user' => ['id' => $user_id, 'email' => $email, 'name' => $name, 'mobile' => $mobile]]);
    }

    public function send_otp_login($request) {
        $email = $this->sanitize_input($request['email'], 'email');
        $user = $this->get_user_by_email($email);
        if (!$user) return new WP_Error('not_registered', 'Email is not registered.', ['status' => 400]);
        $otp = $this->generate_otp();
        set_transient('miror_login_otp_' . $email, $otp, 10 * MINUTE_IN_SECONDS);
        $this->send_otp_email($email, $otp);
        return rest_ensure_response(['message' => 'OTP sent successfully']);
    }

    public function verify_otp_login($request) {
        $email = $this->sanitize_input($request['email'], 'email');
        $otp = $this->sanitize_input($request['otp']);
        $user = $this->get_user_by_email($email);
        $stored_otp = get_transient('miror_login_otp_' . $email);
        if ($otp != $stored_otp) return new WP_Error('invalid_otp', 'Invalid OTP.', ['status' => 400]);
        $user_id = $user->ID;
        $token = Miror_JWT::generate_token($user_id);
        delete_transient('miror_login_otp_' . $email);
        $name = $user->display_name;
        $mobile = get_user_meta($user_id, 'digits_phone_no', true);
        $onboarding = [
            'birth_day' => get_user_meta($user_id, 'birth_day', true),
            'location' => get_user_meta($user_id, 'location', true),
            'lifestyle' => get_user_meta($user_id, 'lifestyle', true),
            'wellness_priority' => get_user_meta($user_id, 'wellness_priority', true),
            'care_about' => get_user_meta($user_id, 'care_about', true),
        ];
        return rest_ensure_response(['token' => $token, 'user' => ['id' => $user_id, 'email' => $email, 'name' => $name, 'mobile' => $mobile], 'onboarding' => $onboarding]);
    }

    public function user_onboarding($request) {
        $user_id = $this->authorize_request($request);
        if (!$user_id) return new WP_Error('unauthorized', 'Invalid or expired token.', ['status' => 403]);
        foreach (['birth_day', 'location', 'lifestyle', 'wellness_priority', 'care_about'] as $field) {
            update_user_meta($user_id, $field, sanitize_text_field($request[$field]));
        }
        return rest_ensure_response(['message' => 'Onboarding completed']);
    }

    public function authorize_request($request) {
        $auth = $request->get_header('authorization');
        if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $matches)) return false;
        return Miror_JWT::verify_token($matches[1]);
    }
}
