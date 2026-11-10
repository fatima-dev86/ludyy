<?php
/**
 * Private owner login persistence for Lady English.
 *
 * The browser keeps a long-lived random token, never the password.
 * Only a SHA-256 hash of the token is stored on the server, inside a PHP file.
 */
require_once __DIR__ . '/lib.php';

const OWNER_REMEMBER_COOKIE = 'lady_owner_remember';
const OWNER_REMEMBER_DAYS = 90;
const OWNER_REMEMBER_SECONDS = OWNER_REMEMBER_DAYS * 24 * 60 * 60;

function owner_https(): bool {
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

function owner_cookie_path(): string {
    $dir = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/admin.php')));
    return $dir === '/' || $dir === '.' ? '/' : rtrim($dir, '/') . '/';
}

function owner_remember_cookie(string $value, int $expires): void {
    setcookie(OWNER_REMEMBER_COOKIE, $value, [
        'expires' => $expires,
        'path' => owner_cookie_path(),
        'secure' => owner_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

/**
 * Execute a read/update under a filesystem lock. A PHP file is used so the
 * saved tokens are not downloadable even on servers without .htaccess support.
 */
function owner_token_transaction(callable $change): bool {
    ensure_data_dir();
    $lock = @fopen(DATA_DIR . '/.owner_tokens.lock', 'c');
    if (!$lock) { return false; }
    if (!flock($lock, LOCK_EX)) { fclose($lock); return false; }

    $file = DATA_DIR . '/owner_tokens.php';
    $tokens = [];
    if (is_file($file)) {
        $raw = (string)@file_get_contents($file);
        $guard = '<?php exit; ?>';
        if (strncmp($raw, $guard, strlen($guard)) === 0) {
            $decoded = json_decode(trim(substr($raw, strlen($guard))), true);
            if (is_array($decoded)) { $tokens = $decoded; }
        } else {
            // Read remember tokens from previous installs and migrate them.
            if (function_exists('opcache_invalidate')) { @opcache_invalidate($file, true); }
            $legacy = @include $file;
            if (is_array($legacy)) { $tokens = $legacy; }
        }
    }

    $now = time();
    foreach ($tokens as $selector => $record) {
        if (!is_string($selector) || !is_array($record) ||
            !isset($record['hash'], $record['expires']) ||
            !is_string($record['hash']) || (int)$record['expires'] <= $now) {
            unset($tokens[$selector]);
        }
    }

    $accepted = $change($tokens);
    if ($accepted) {
        // The PHP exit guard blocks direct download even when .htaccess is unavailable.
        // JSON is read as text to avoid PHP opcache staleness after token rotation.
        $php = "<?php exit; ?>\n" . json_encode($tokens, JSON_UNESCAPED_SLASHES);
        $tmp = @tempnam(DATA_DIR, '.owner-');
        if ($tmp === false || @file_put_contents($tmp, $php) === false || !@rename($tmp, $file)) {
            if ($tmp !== false && is_file($tmp)) { @unlink($tmp); }
            $accepted = false;
        }
    }

    flock($lock, LOCK_UN);
    fclose($lock);
    return (bool)$accepted;
}

function owner_remember_login(string $passwordHash): bool {
    $selector = bin2hex(random_bytes(12));
    $validator = bin2hex(random_bytes(32));
    $expires = time() + OWNER_REMEMBER_SECONDS;
    $hash = hash('sha256', $validator);
    $fingerprint = hash('sha256', $passwordHash);

    $saved = owner_token_transaction(static function (array &$tokens) use ($selector, $hash, $expires, $fingerprint): bool {
        $tokens[$selector] = ['hash' => $hash, 'expires' => $expires, 'fingerprint' => $fingerprint];
        // Keep at most 12 remembered browsers. Evict the oldest when full.
        if (count($tokens) > 12) {
            uasort($tokens, static fn($a, $b) => ((int)$a['expires']) <=> ((int)$b['expires']));
            $tokens = array_slice($tokens, -12, null, true);
        }
        return true;
    });

    if ($saved) {
        owner_remember_cookie($selector . ':' . $validator, $expires);
        $_COOKIE[OWNER_REMEMBER_COOKIE] = $selector . ':' . $validator;
    }
    return $saved;
}

function owner_remember_restore(string $passwordHash): bool {
    $cookie = (string)($_COOKIE[OWNER_REMEMBER_COOKIE] ?? '');
    if (!preg_match('/^([a-f0-9]{24}):([a-f0-9]{64})$/D', $cookie, $m)) {
        if ($cookie !== '') { owner_remember_cookie('', time() - 3600); }
        return false;
    }

    $selector = $m[1];
    $validator = $m[2];
    $replacement = bin2hex(random_bytes(32));
    $expires = time() + OWNER_REMEMBER_SECONDS;
    $fingerprint = hash('sha256', $passwordHash);
    $matched = owner_token_transaction(static function (array &$tokens) use ($selector, $validator, $replacement, $expires, $fingerprint): bool {
        if (empty($tokens[$selector]) ||
            !hash_equals((string)$tokens[$selector]['hash'], hash('sha256', $validator)) ||
            !hash_equals((string)($tokens[$selector]['fingerprint'] ?? ''), $fingerprint)) {
            return false;
        }
        // Rotate the secret after recovering a session. Renew the 90-day window.
        $tokens[$selector] = ['hash' => hash('sha256', $replacement), 'expires' => $expires, 'fingerprint' => $fingerprint];
        return true;
    });

    if (!$matched) {
        owner_remember_cookie('', time() - 3600);
        return false;
    }

    owner_mark_signed_in($passwordHash);
    owner_remember_cookie($selector . ':' . $replacement, $expires);
    $_COOKIE[OWNER_REMEMBER_COOKIE] = $selector . ':' . $replacement;
    return true;
}

function owner_forget_remember(): void {
    $cookie = (string)($_COOKIE[OWNER_REMEMBER_COOKIE] ?? '');
    if (preg_match('/^([a-f0-9]{24}):[a-f0-9]{64}$/D', $cookie, $m)) {
        $selector = $m[1];
        owner_token_transaction(static function (array &$tokens) use ($selector): bool {
            unset($tokens[$selector]);
            return true;
        });
    }
    owner_remember_cookie('', time() - 3600);
    unset($_COOKIE[OWNER_REMEMBER_COOKIE]);
}


/** The session is bound to the password hash. A password reset revokes old sessions. */
function owner_mark_signed_in(string $passwordHash): void {
    session_regenerate_id(true);
    $_SESSION['in'] = true;
    $_SESSION['owner_fingerprint'] = hash('sha256', $passwordHash);
}

function owner_config(): array {
    $file = DATA_DIR . '/admin.php';
    if (!is_file($file)) { return []; }
    // Store credentials as JSON following an executable PHP exit guard.
    // Reading the bytes directly avoids stale PHP opcache after a password reset.
    $raw = (string)@file_get_contents($file);
    $guard = '<?php exit; ?>';
    if (strncmp($raw, $guard, strlen($guard)) === 0) {
        $config = json_decode(trim(substr($raw, strlen($guard))), true);
        return is_array($config) ? $config : [];
    }
    // Compatibility with older installations. owner-setup.php replaces this.
    if (function_exists('opcache_invalidate')) { @opcache_invalidate($file, true); }
    $config = @include $file;
    return is_array($config) ? $config : [];
}

function owner_start_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) { return; }
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'cookie_secure' => owner_https(),
        'use_strict_mode' => true,
    ]);
}

function owner_authorized(): bool {
    $config = owner_config();
    $hash = (string)($config['hash'] ?? '');
    if ($hash === '') { return false; }
    $fingerprint = hash('sha256', $hash);
    if (!empty($_SESSION['in']) && hash_equals((string)($_SESSION['owner_fingerprint'] ?? ''), $fingerprint)) {
        return true;
    }
    unset($_SESSION['in'], $_SESSION['owner_fingerprint']);
    return owner_remember_restore($hash);
}
