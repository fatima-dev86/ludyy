
<?php
// Lady English owner page: special offers + private messages inbox.
require __DIR__ . '/lib.php';
require __DIR__ . '/owner_auth.php';

header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store, private');
owner_start_session();
$owner = owner_config();
$hash = (string)($owner['hash'] ?? '');
$in = owner_authorized();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$msg = '';
$err = '';

// Read saved messages.
function admin_read_messages(): array {
    $file = DATA_DIR . '/messages.json';

    if (!is_file($file)) {
        return [];
    }

    $handle = @fopen($file, 'rb');
    if (!$handle) {
        return [];
    }

    flock($handle, LOCK_SH);
    $content = stream_get_contents($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    $messages = json_decode((string)$content, true);

    return is_array($messages) ? $messages : [];
}

// Update a message safely while preventing simultaneous file writes.
function admin_update_message(string $id, string $action): bool {
    if (!in_array($action, ['read', 'delete'], true)) {
        return false;
    }

    ensure_data_dir();

    $file = DATA_DIR . '/messages.json';
    $handle = @fopen($file, 'c+');

    if (!$handle) {
        return false;
    }

    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return false;
    }

    rewind($handle);
    $content = stream_get_contents($handle);
    $messages = json_decode((string)$content, true);

    if (!is_array($messages)) {
        flock($handle, LOCK_UN);
        fclose($handle);
        return false;
    }

    $found = false;
    $updated = [];

    foreach ($messages as $message) {
        if (!is_array($message)) {
            continue;
        }

        if (($message['id'] ?? '') === $id) {
            $found = true;

            if ($action === 'read') {
                $message['read'] = true;
                $updated[] = $message;
            }

            // For delete, do not add the message back.
        } else {
            $updated[] = $message;
        }
    }

    if (!$found) {
        flock($handle, LOCK_UN);
        fclose($handle);
        return false;
    }

    $json = json_encode(
        array_values($updated),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE
    );

    if ($json === false) {
        flock($handle, LOCK_UN);
        fclose($handle);
        return false;
    }

    rewind($handle);
    $written = ftruncate($handle, 0)
        && fwrite($handle, $json) !== false
        && fflush($handle);

    flock($handle, LOCK_UN);
    fclose($handle);

    return $written;
}

// Handle submitted actions.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $act = (string)($_POST['action'] ?? '');

    if (
        !isset($_POST['csrf']) ||
        !hash_equals($_SESSION['csrf'], (string)$_POST['csrf'])
    ) {
        $err = 'The page expired. Please try again.';
    }

    // Login.
    elseif ($act === 'login' && $hash && !$in) {
        $submittedEmail = strtolower(trim((string)($_POST['email'] ?? '')));
        $correctEmail = strtolower(trim((string)($owner['email'] ?? '')));
        // Existing installs may have a legacy hash-only config. Owner must
        // configure the new email and password at owner-setup.php on localhost.
        if ($correctEmail !== '' && hash_equals($correctEmail, $submittedEmail)
            && password_verify((string)($_POST['password'] ?? ''), $hash)) {
            owner_mark_signed_in($hash);
            $in = true;
            owner_forget_remember();
            if (!empty($_POST['remember'])) { owner_remember_login($hash); }
            activity_log('security', 'The owner signed in.');
        } else {
            sleep(1);
            $err = 'Incorrect email or password.';
        }
    }

    // Logout.
    elseif ($act === 'logout') {
        owner_forget_remember();
        $_SESSION = [];
        session_destroy();
        $cookieParams = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => $cookieParams['path'],
            'domain' => $cookieParams['domain'],
            'secure' => $cookieParams['secure'],
            'httponly' => $cookieParams['httponly'],
            'samesite' => $cookieParams['samesite'] ?? 'Lax',
        ]);
        header('Location: admin.php');
        exit;
    }

    // Change the password after entering the current one. Works online too.
    elseif ($act === 'change_password' && $in) {
        $current = (string)($_POST['current_password'] ?? '');
        $next = (string)($_POST['new_password'] ?? '');
        $confirm = (string)($_POST['confirm_password'] ?? '');
        if (!password_verify($current, $hash)) {
            $err = 'Your current password is incorrect.';
        } elseif (strlen($next) < 12 || strlen($next) > 200 ||
                  !preg_match('/[a-zA-Z]/', $next) || !preg_match('/[0-9]/', $next)) {
            $err = 'Use at least 12 characters with letters and numbers.';
        } elseif (!hash_equals($next, $confirm)) {
            $err = 'The new passwords do not match.';
        } else {
            $nextHash = password_hash($next, PASSWORD_DEFAULT);
            $newConfig = ['email' => (string)($owner['email'] ?? ''), 'hash' => $nextHash];
            $raw = "<?php exit; ?>\n" . json_encode($newConfig, JSON_UNESCAPED_SLASHES);
            $tmp = @tempnam(DATA_DIR, '.auth-');
            if ($tmp === false || @file_put_contents($tmp, $raw) === false || !@rename($tmp, DATA_DIR . '/admin.php')) {
                if ($tmp !== false) { @unlink($tmp); }
                $err = 'Could not save the new password.';
            } else {
                $hash = $nextHash;
                $owner = $newConfig;
                owner_forget_remember();
                owner_mark_signed_in($nextHash);
                if (!empty($_POST['remember'])) { owner_remember_login($nextHash); }
                $msg = 'Password changed. Other devices must sign in again.';
                activity_log('security', 'The owner changed the account password.');
            }
        }
    }

    // Save special offer settings.
    elseif ($act === 'save' && $in) {
        $on = (($_POST['offer'] ?? '') === 'on');
        $pct = (int)($_POST['percent'] ?? 30);

        if ($pct < 1 || $pct > 90) {
            $err = 'The percentage must be between 1 and 90.';
        } else {
            if (save_settings($on, $pct)) {
                $msg = 'Saved. The website now shows the new prices.';
                activity_log('offer_updated', 'Special offer ' . ($on ? 'enabled' : 'disabled') . ' (' . $pct . '%).');
            } else {
                $err = 'Could not save. Make sure the data folder is writable.';
            }
        }
    }

    // Mark a message as read.
    elseif ($act === 'mark_read' && $in) {
        $id = (string)($_POST['id'] ?? '');

        if (admin_update_message($id, 'read')) {
            $msg = 'Message marked as read.';
            activity_log('message_read', 'The owner marked a message as read.');
        } else {
            $err = 'Could not update this message.';
        }
    }

    // Delete a message.
    elseif ($act === 'delete_message' && $in) {
        $id = (string)($_POST['id'] ?? '');

        if (admin_update_message($id, 'delete')) {
            $msg = 'Message deleted.';
            activity_log('message_deleted', 'The owner deleted a message.');
        } else {
            $err = 'Could not delete this message.';
        }
    }
}

$in = owner_authorized();
$S = settings();

$messages = $in ? admin_read_messages() : [];

$unreadCount = count(array_filter(
    $messages,
    fn($message) => is_array($message) && empty($message['read'])
));

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Lady English – Owner Dashboard</title>

<style>
*{box-sizing:border-box}

body{
    margin:0;
    font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;
    background:#F2E6D0;
    color:#3A2E1E;
    line-height:1.6;
}

.container{
    max-width:850px;
    margin:35px auto;
    padding:0 16px;
}

.box{
    background:#FFFDF8;
    border:1px solid #DCC9A5;
    border-radius:22px;
    padding:25px;
    margin-bottom:22px;
    box-shadow:7px 7px 0 #F5C431;
}

h1{font-size:1.7rem;margin:0 0 5px}
h2{font-size:1.3rem;margin:0 0 14px}
p{margin:.4rem 0 1rem}

label{
    display:block;
    font-weight:700;
    margin:14px 0 6px;
}

input[type=password],
input[type=number]{
    width:100%;
    padding:12px;
    border:1px solid #DCC9A5;
    border-radius:12px;
    font:inherit;
}

.row{
    display:flex;
    gap:18px;
    flex-wrap:wrap;
}

label.remember-choice{
    display:flex;
    align-items:center;
    gap:10px;
    font-weight:600;
    font-size:.95rem;
    cursor:pointer;
}
label.remember-choice input{width:18px;height:18px;flex:none;accent-color:#D9A410}

.row label{
    font-weight:600;
    display:flex;
    gap:8px;
    align-items:center;
    margin:6px 0;
}

button{
    margin-top:14px;
    padding:11px 22px;
    border:0;
    border-radius:999px;
    background:#F5C431;
    color:#3A2E1E;
    font:inherit;
    font-weight:700;
    cursor:pointer;
}

button:hover{opacity:.85}

button.link{
    background:none;
    text-decoration:underline;
    padding:0;
    margin:0;
}

button.delete{
    background:#8B3434;
    color:white;
}

button.small{
    padding:8px 15px;
    font-size:.9rem;
}

.ok{
    background:#F5C431;
    padding:10px 14px;
    border-radius:12px;
    font-weight:700;
}

.bad{
    border:2px solid #D9A410;
    padding:10px 14px;
    border-radius:12px;
    font-weight:700;
}

a{color:inherit}

.dashboard-nav{
    display:flex;
    gap:12px;
    flex-wrap:wrap;
    margin:18px 0;
}

.dashboard-nav a{
    text-decoration:none;
    background:#F2E6D0;
    border:1px solid #DCC9A5;
    padding:9px 15px;
    border-radius:999px;
    font-weight:700;
}

.dashboard-nav a:hover{
    background:#F5C431;
}

.count{
    display:inline-block;
    background:#F5C431;
    padding:2px 10px;
    border-radius:999px;
    font-size:.85rem;
    margin-left:5px;
}

.message-card{
    background:#FFFDF8;
    border:1px solid #DCC9A5;
    border-radius:16px;
    padding:17px;
    margin:14px 0;
    overflow-wrap:anywhere;
}

.message-card.unread{
    border:2px solid #D9A410;
    background:#FFFAE9;
}

.message-top{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:10px;
    flex-wrap:wrap;
}

.message-status{
    font-size:.8rem;
    font-weight:700;
    padding:3px 10px;
    border-radius:999px;
    background:#E8E3D9;
}

.message-card.unread .message-status{
    background:#F5C431;
}

.message-meta{
    font-size:.9rem;
    color:#776A57;
    margin:5px 0 12px;
}

.message-content{
    white-space:pre-wrap;
    overflow-wrap:anywhere;
    background:#F8F1E5;
    border-radius:12px;
    padding:13px;
}

.message-actions{
    display:flex;
    gap:10px;
    flex-wrap:wrap;
    align-items:center;
}

.message-actions form{margin:0}

.empty{
    text-align:center;
    padding:28px 15px;
    background:#F8F1E5;
    border-radius:14px;
}

@media(max-width:550px){
    .box{padding:19px}
    .container{margin:20px auto}
}

.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:11px;margin:18px 0}
.stat{background:#fff8e2;border:1px solid #dcc9a5;padding:15px;border-radius:16px;display:flex;flex-direction:column;gap:2px}
.stat strong{font-size:1.7rem}.stat span{font-size:.8rem;color:#73654d}
.tiny{font-size:.85rem;color:#6e5e47}
.activity-list{list-style:none;padding:0;margin:0}
.activity-list li{padding:12px 0;border-bottom:1px solid #e6dccb;display:flex;justify-content:space-between;gap:12px}
.activity-list time{color:#776a57;font-size:.78rem;white-space:nowrap}
input[type=email]{width:100%;padding:12px;border:1px solid #DCC9A5;border-radius:12px;font:inherit}
@media(max-width:550px){.stats{grid-template-columns:1fr}.activity-list li{flex-direction:column;gap:2px}}
</style>
</head>

<body>
<div class="container">

<?php if ($msg): ?>
<p class="ok"><?= h($msg) ?></p>
<?php endif; ?>

<?php if ($err): ?>
<p class="bad"><?= h($err) ?></p>
<?php endif; ?>

<?php if (!$hash || empty($owner['email'])): ?>
<div class="box">
    <h1>Lady English — Owner setup needed</h1>
    <p>The owner account is not configured yet. To prevent someone on the internet claiming your admin account, account setup is only allowed on your own laptop.</p>
    <p>On the laptop with Wampserver, visit <code>http://localhost/lady-english-php/owner-setup.php</code> to choose the private owner email and password.</p>
</div>

<?php elseif (!$in): ?>

<div class="box">
    <h1>Lady English – Owner page</h1>
    <p>Please sign in to manage your website.</p>

    <form method="post">
        <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="login">

        <label for="e">Owner email</label>
        <input id="e" type="email" name="email" required autocomplete="username" placeholder="Owner email">
        <label for="p">Password</label>
        <input id="p" type="password" name="password"
               required autocomplete="current-password">

        <label class="remember-choice"><input type="checkbox" name="remember" value="1" checked>
          Keep me signed in on this device for 90 days
        </label>
        <button type="submit">Sign in</button>
    </form>
</div>

<?php else: ?>

<div class="box">
    <h1>Lady English – Owner Dashboard</h1>
    <p>Welcome back! Your messages, changes, and special offers are all here.</p>
    <div class="stats">
      <div class="stat"><strong><?= count($messages) ?></strong><span>Total messages</span></div>
      <div class="stat"><strong><?= $unreadCount ?></strong><span>Unread messages</span></div>
      <div class="stat"><strong><?= count(activity_recent(50)) ?></strong><span>Recent activities</span></div>
    </div>
    <p class="tiny"><strong>Signed in:</strong> <?= h($owner['email'] ?? 'Owner') ?>. This dashboard is private. Visitors cannot see it.</p>

    <nav class="dashboard-nav">
        <a href="#notifications">Notifications</a>
        <a href="#activity">Recent Activity</a>
        <a href="#offers">Special Offers</a>
        <a href="#security">Password</a>
        <a href="#inbox">
            Messages / Inbox
            <?php if ($unreadCount > 0): ?>
                <span class="count"><?= $unreadCount ?></span>
            <?php endif; ?>
        </a>
    </nav>

    <form method="post">
        <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="logout">
        <button class="link" type="submit">Sign out</button>
    </form>
</div>

<!-- NOTIFICATIONS -->
<section class="box" id="notifications">
  <h2>Notifications <span class="count">Live</span></h2>
  <p>Incoming messages appear automatically in this dashboard. Click below to allow Chrome to show a desktop alert when a new message comes in.</p>
  <button id="allowNotifications" type="button">Enable desktop notifications</button>
  <p class="tiny" id="notificationState" role="status">Notifications require browser permission and HTTPS (or localhost). Keep this dashboard tab open for live alerts. Notifications while the browser is fully closed require a separate push service after hosting.</p>
  <p class="tiny">Email alerts are best-effort and depend on your hosting company's mail configuration. They are not guaranteed by Wampserver.</p>
</section>

<!-- RECENT ACTIVITY -->
<section class="box" id="activity">
  <h2>Recent Activity</h2>
  <p>New enquiries and owner changes are tracked here.</p>
  <?php $activities = activity_recent(15); ?>
  <?php if (!$activities): ?><p class="empty">No activity recorded yet.</p>
  <?php else: ?><ul class="activity-list">
    <?php foreach ($activities as $event): ?>
      <li><span><?= h($event['description'] ?? '') ?></span><time><?= h($event['date'] ?? '') ?></time></li>
    <?php endforeach; ?>
  </ul><?php endif; ?>
</section>

<!-- SPECIAL OFFERS -->
<section class="box" id="offers">
    <h2>Special Offer Settings</h2>
    <p>Control the special offer. The website changes right after you press Save.</p>

    <form method="post">
        <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="save">

        <label>Special offer</label>

        <div class="row">
            <label>
                <input type="radio" name="offer" value="on"
                    <?= $S['offerActive'] ? 'checked' : '' ?>>
                ON (discounted prices)
            </label>

            <label>
                <input type="radio" name="offer" value="off"
                    <?= !$S['offerActive'] ? 'checked' : '' ?>>
                OFF (original prices)
            </label>
        </div>

        <label for="pc">Discount percentage</label>
        <input id="pc" type="number" name="percent"
               min="1" max="90"
               value="<?= (int)$S['offerPercent'] ?>" required>

        <button type="submit">Save</button>
    </form>

    <p style="margin-top:22px">
        <a href="index.php#courses" target="_blank" rel="noopener">
            See the courses on the website
        </a>
    </p>
</section>

<!-- OWNER SECURITY -->
<section class="box" id="security">
  <h2>Change owner password</h2>
  <p>Only the signed-in owner can change this password. Your other logged-in devices will need to sign in again.</p>
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
    <input type="hidden" name="action" value="change_password">
    <label for="currentPass">Current password</label>
    <input type="password" name="current_password" id="currentPass" required autocomplete="current-password">
    <label for="newPass">New password (12+ characters with letters and numbers)</label>
    <input type="password" name="new_password" id="newPass" minlength="12" required autocomplete="new-password">
    <label for="confirmPass">Confirm new password</label>
    <input type="password" name="confirm_password" id="confirmPass" minlength="12" required autocomplete="new-password">
    <label class="remember-choice"><input type="checkbox" name="remember" value="1" checked> Keep this laptop signed in</label>
    <button type="submit">Change password</button>
  </form>
</section>

<!-- PRIVATE MESSAGE INBOX -->
<section class="box" id="inbox">
    <h2>
        Messages / Inbox
        <span class="count"><?= count($messages) ?></span>
    </h2>

    <p>
        You have <?= $unreadCount ?> unread
        <?= $unreadCount === 1 ? 'message' : 'messages' ?>.
    </p>

    <?php if (empty($messages)): ?>

        <div class="empty">
            <p><strong>Your inbox is empty.</strong></p>
            <p>Messages submitted through the website contact form will appear here.</p>
        </div>

    <?php else: ?>

        <?php foreach (array_reverse($messages) as $message): ?>
            <?php if (!is_array($message)) continue; ?>

            <article class="message-card <?= empty($message['read']) ? 'unread' : '' ?>">

                <div class="message-top">
                    <strong><?= h($message['name'] ?? 'Unknown sender') ?></strong>

                    <span class="message-status">
                        <?= empty($message['read']) ? 'Unread' : 'Read' ?>
                    </span>
                </div>

                <div class="message-meta">
                    <?php if (!empty($message['email'])): ?>
                        Email:
                        <a href="mailto:<?= h($message['email']) ?>">
                            <?= h($message['email']) ?>
                        </a>
                        <br>
                    <?php else: ?>
                        No email provided<br>
                    <?php endif; ?>

                    Date: <?= h($message['date'] ?? 'Unknown date') ?>
                </div>

                <div class="message-content"><?= h($message['message'] ?? '') ?></div>

                <div class="message-actions">

                    <?php if (empty($message['read']) && !empty($message['id'])): ?>
                        <form method="post">
                            <input type="hidden" name="csrf"
                                   value="<?= h($_SESSION['csrf']) ?>">
                            <input type="hidden" name="action" value="mark_read">
                            <input type="hidden" name="id"
                                   value="<?= h($message['id']) ?>">

                            <button class="small" type="submit">
                                Mark as Read
                            </button>
                        </form>
                    <?php endif; ?>

                    <?php if (!empty($message['id'])): ?>
                        <form method="post"
                              onsubmit="return confirm('Are you sure you want to delete this message?');">
                            <input type="hidden" name="csrf"
                                   value="<?= h($_SESSION['csrf']) ?>">
                            <input type="hidden" name="action"
                                   value="delete_message">
                            <input type="hidden" name="id"
                                   value="<?= h($message['id']) ?>">

                            <button class="delete small" type="submit">
                                Delete
                            </button>
                        </form>
                    <?php endif; ?>

                </div>
            </article>

        <?php endforeach; ?>

    <?php endif; ?>
</section>

<?php endif; ?>

</div>
<?php if ($in): ?>
<script>
(() => {
  const button = document.getElementById('allowNotifications');
  const state = document.getElementById('notificationState');
  const canNotify = ('Notification' in window) && window.isSecureContext;
  function updateState() {
    if (!canNotify) {
      button.disabled = true;
      state.textContent = 'Desktop alerts need Chrome on HTTPS or localhost. The inbox will still update while this tab is open.';
    } else if (Notification.permission === 'granted') {
      button.textContent = 'Desktop notifications enabled ✓';
      state.textContent = 'You will receive an alert for newly received messages while the admin tab is open. Allow notifications in your computer settings too.';
    } else if (Notification.permission === 'denied') {
      button.disabled = true;
      state.textContent = 'Chrome blocked notifications. You can change this in the site permissions (padlock icon).';
    }
  }
  button.addEventListener('click', async () => {
    if (!canNotify) return;
    try { await Notification.requestPermission(); } catch(e) {}
    updateState();
  });
  updateState();

  let lastEventId = <?= json_encode((activity_recent(1)[0]['id'] ?? ''), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
  let polling = false;
  async function pollChanges() {
    if (polling) return;
    polling = true;
    try {
      const response = await fetch('admin-updates.php', {cache: 'no-store', credentials: 'same-origin'});
      if (response.status === 401) { location.reload(); return; }
      if (!response.ok) return;
      const data = await response.json();
      if (data.latest && data.latest !== lastEventId) {
        const entries = Array.isArray(data.events) ? data.events : [];
        const position = entries.findIndex(e => e.id === lastEventId);
        const recent = position < 0 ? entries.slice(0, 8) : entries.slice(0, position);
        const hasNewMessage = recent.some(e => e.type === 'new_message');
        lastEventId = data.latest;
        if (hasNewMessage && canNotify && Notification.permission === 'granted') {
          try { new Notification('Lady English — New enquiry', {body: 'A new message arrived. Open your dashboard to read it.', tag: 'lady-message-' + lastEventId}); } catch(e) {}
        }
        // Reload the dashboard to show new messages, counts and activity.
        // Don't discard unsaved changes in a form the owner is currently editing.
        const focused = document.activeElement;
        const editing = focused && (focused.tagName === 'INPUT' && focused.type !== 'submit') && focused.closest('#offers');
        if (!editing) location.reload();
        else {
          state.textContent = 'New changes arrived! Save your form, then refresh to view them.';
        }
      }
    } catch(e) { /* temporarily offline; the next poll retries */ }
    finally { polling = false; }
  }
  setInterval(pollChanges, 12000);
})();
</script>
<?php endif; ?>
</body>
</html>
