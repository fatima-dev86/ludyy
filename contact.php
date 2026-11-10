<?php
require_once __DIR__ . '/owner_auth.php';

// Notification email goes to the owner address configured on localhost.
// PHP mail() only works if the host has properly configured outbound mail.

function back(string $code): void {
    header('Location: index.php?sent=' . $code . '#contact');
    exit;
}

function message_length(string $value): int {
    return function_exists('mb_strlen')
        ? mb_strlen($value, 'UTF-8')
        : strlen($value);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Location: index.php#contact');
    exit;
}

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax'
]);

// Spam protection
if (!empty($_POST['website'])) {
    back('1');
}

// Read and validate form fields
$name = trim(preg_replace('/[\r\n]+/', ' ', (string)($_POST['name'] ?? '')));
$email = trim((string)($_POST['email'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));

if (
    $name === '' ||
    $message === '' ||
    message_length($name) > 100 ||
    message_length($message) > 3000 ||
    strlen($email) > 150
) {
    back('2');
}

if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    back('2');
}

// Rate limit
if (
    isset($_SESSION['last_msg']) &&
    time() - (int)$_SESSION['last_msg'] < 30
) {
    back('3');
}

// Save the enquiry. Hold a lock for both read and write so simultaneous
// visitors never overwrite one another's messages.
ensure_data_dir();
$file = DATA_DIR . '/messages.json';
$handle = @fopen($file, 'c+');
if (!$handle || !flock($handle, LOCK_EX)) {
    if ($handle) { fclose($handle); }
    back('0');
}
rewind($handle);
$existing = json_decode((string)stream_get_contents($handle), true);
$messages = is_array($existing) ? $existing : [];
$messages[] = [
    'id' => bin2hex(random_bytes(8)),
    'name' => $name,
    'email' => $email,
    'message' => $message,
    'date' => date('Y-m-d H:i:s'),
    'read' => false,
];
$json = json_encode($messages, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
$success = $json !== false && rewind($handle) && ftruncate($handle, 0)
    && fwrite($handle, $json) === strlen($json) && fflush($handle);
flock($handle, LOCK_UN);
fclose($handle);
if (!$success) { back('0'); }
$_SESSION['last_msg'] = time();
activity_log('new_message', 'New enquiry received from ' . $name . '.');

// Optional email notification
$subject = 'New message from Lady English website';

$body =
    "New website message\n\n" .
    "Name: $name\n" .
    "Email: " . ($email !== '' ? $email : 'Not provided') . "\n\n" .
    "Message:\n$message";

$headers = [
    'From: Lady English <noreply@ladyenglish.com>',
    'Content-Type: text/plain; charset=UTF-8'
];

if ($email !== '') {
    $headers[] = 'Reply-To: ' . $email;
}

$ownerEmail = (string)(owner_config()['email'] ?? '');
if (filter_var($ownerEmail, FILTER_VALIDATE_EMAIL)) {
    @mail(
        $ownerEmail,
        '=?UTF-8?B?' . base64_encode($subject) . '?=',
        $body,
        implode("\r\n", $headers)
    );
}

// The message is safely stored even if email fails.
back('1');