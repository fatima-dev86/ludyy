<?php
/**
 * Local-only owner enrollment/password reset.
 * Never make this page reachable on a public web host.
 * Remove this file after setting up the online website.
 */
require_once __DIR__ . '/owner_auth.php';
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
$host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
if (!in_array($remote, ['127.0.0.1', '::1'], true) || !in_array($host, ['localhost','localhost:80','127.0.0.1','127.0.0.1:80','[::1]','[::1]:80'], true)) {
    http_response_code(403);
    exit('For your safety, owner setup is available only on localhost. Complete setup in Wampserver before putting the site online.');
}
owner_start_session();
if (empty($_SESSION['owner_setup_csrf'])) { $_SESSION['owner_setup_csrf'] = bin2hex(random_bytes(16)); }
$error = '';
$success = false;
$cfg = owner_config();
$email = (string)($cfg['email'] ?? 'ladyenglishcourse@gmail.com');
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $email = strtolower(trim((string)($_POST['email'] ?? '')));
    $password = (string)($_POST['password'] ?? '');
    $confirmation = (string)($_POST['confirm'] ?? '');
    if (!hash_equals((string)$_SESSION['owner_setup_csrf'], (string)($_POST['csrf'] ?? ''))) {
        $error = 'The setup page expired. Refresh and try again.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
        $error = 'Please enter a valid owner email.';
    } elseif (strlen($password) < 12 || strlen($password) > 200 || !preg_match('/[a-zA-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
        $error = 'Choose a password of 12 or more characters with letters and numbers.';
    } elseif (!hash_equals($password, $confirmation)) {
        $error = 'The passwords do not match.';
    } else {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $php = "<?php exit; ?>\n" . json_encode(['email' => $email, 'hash' => $hash], JSON_UNESCAPED_SLASHES);
        ensure_data_dir();
        $file = DATA_DIR . '/admin.php';
        $temp = @tempnam(DATA_DIR, '.auth-');
        if ($temp === false || @file_put_contents($temp, $php) === false || !@rename($temp, $file)) {
            if ($temp !== false) { @unlink($temp); }
            $error = 'Could not save. Check the data folder write permissions.';
        } else {
            // No existing browser session or remember token can survive a changed password.
            @unlink(DATA_DIR . '/owner_tokens.php');
            owner_forget_remember();
            $_SESSION = [];
            owner_mark_signed_in($hash);
            activity_log('security', 'Owner password and login email were configured locally.');
            $success = true;
        }
    }
}
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Lady English — Owner setup</title>
<style>body{font-family:system-ui,sans-serif;background:#F2E6D0;color:#352917;margin:0;padding:6vh 16px}.panel{background:#fffdf8;border:1px solid #dcc9a5;box-shadow:8px 8px 0 #f5c431;border-radius:22px;max-width:540px;margin:auto;padding:28px}input{display:block;width:100%;padding:12px;margin:7px 0 18px;border:1px solid #dcc9a5;border-radius:10px;font:inherit;box-sizing:border-box}button,.button{display:inline-block;background:#f5c431;border:0;border-radius:30px;padding:12px 20px;font:inherit;font-weight:700;color:#352917;text-decoration:none;cursor:pointer}p{line-height:1.5}.error{color:#8b3434;font-weight:700}small{color:#6e5e47}</style></head><body><main class="panel">
<?php if ($success): ?><h1>Owner account ready ✅</h1><p>Your new owner email and password are saved securely. Your earlier admin login sessions are no longer valid.</p><p><strong>Before publishing:</strong> delete <code>owner-setup.php</code> from the hosted site. Do not share your admin password.</p><a class="button" href="admin.php">Open my dashboard</a>
<?php else: ?><h1>Lady English — Owner setup</h1><p>This page works only from your own laptop on <code>localhost</code>. It sets a new password even if the old password was forgotten. It does <strong>not</strong> delete messages or offers.</p><small>Once on public hosting, this page is blocked. Remove it from the online upload.</small>
<?php if ($error): ?><p class="error" role="alert"><?= h($error) ?></p><?php endif; ?>
<form method="post"><input type="hidden" name="csrf" value="<?= h($_SESSION['owner_setup_csrf']) ?>"><label for="email">Owner email</label><input id="email" type="email" name="email" value="<?= h($email) ?>" autocomplete="email" required maxlength="150"><label for="password">New strong password</label><input id="password" type="password" name="password" minlength="12" autocomplete="new-password" required><label for="confirm">Confirm password</label><input id="confirm" type="password" name="confirm" minlength="12" autocomplete="new-password" required><button type="submit">Save owner account</button></form><?php endif; ?></main></body></html>
