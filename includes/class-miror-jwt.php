<!-- includes/class-miror-jwt.php -->
<?php
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Miror_JWT {

    private static $secret_key = '471Pvux471Pvux';
    private static $algorithm = 'HS256';

    public static function generate_token($user_id) {
        $issuedAt = time();
        $expire = $issuedAt + (14 * DAY_IN_SECONDS);
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expire,
            'sub' => $user_id,
        ];
        return JWT::encode($payload, self::$secret_key, self::$algorithm);
    }

    public static function verify_token($token) {
        try {
            $decoded = JWT::decode($token, new Key(self::$secret_key, self::$algorithm));
            return $decoded->sub;
        } catch (Exception $e) {
            return false;
        }
    }
}
