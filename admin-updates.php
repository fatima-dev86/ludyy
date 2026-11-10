<?php
/** Authenticated polling endpoint for the owner's open dashboard. */
require_once __DIR__ . '/owner_auth.php';
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Content-Type: application/json; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') { http_response_code(405); exit; }
owner_start_session();
if (!owner_authorized()) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
    exit;
}
$events = activity_recent(30);
$file = DATA_DIR . '/messages.json';
$rows = [];
if (is_file($file)) {
    $fp = @fopen($file, 'rb');
    if ($fp) {
        flock($fp, LOCK_SH);
        $data = json_decode((string)stream_get_contents($fp), true);
        flock($fp, LOCK_UN);
        fclose($fp);
        if (is_array($data)) { $rows = $data; }
    }
}
$unread = count(array_filter($rows, static fn($m) => is_array($m) && empty($m['read'])));
echo json_encode([
    'ok' => true,
    'total' => count($rows),
    'unread' => $unread,
    'latest' => (string)($events[0]['id'] ?? ''),
    'events' => $events,
], JSON_INVALID_UTF8_SUBSTITUTE);
