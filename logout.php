<?php
session_start();
require 'db.php';

if (isset($_SESSION['session_id'])) {
    $session_id = $_SESSION['session_id'];

    // Update logout time for this session
    $update = $conn->prepare("UPDATE user_sessions SET logout_time = NOW() WHERE session_id = ?");
    if ($update) {
        $update->bind_param("i", $session_id);
        $update->execute();
    }
}

// Clear all session data and destroy session
$_SESSION = [];
session_destroy();

header("Location: login_form.php");
exit;
?>
