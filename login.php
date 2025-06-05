<?php
session_start();
require 'db.php';       // Your mysqli connection setup
require 'csrf.php';     // Your CSRF token functions

define('MAX_ATTEMPTS', 5);
define('LOCK_TIME', 900); // 15 minutes lockout

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if account is locked out due to too many failed attempts
function isLockedOut($conn, $email) {
    $stmt = $conn->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE email = ?");
    if (!$stmt) return false;
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($attempts, $last_attempt);
    if ($stmt->fetch()) {
        if ($last_attempt && $attempts >= MAX_ATTEMPTS && (time() - strtotime($last_attempt)) < LOCK_TIME) {
            $stmt->close();
            return true;
        }
    }
    $stmt->close();
    return false;
}

function recordLoginAttempt($conn, $email, $success) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    $stmt = $conn->prepare("INSERT INTO login_attempt_logs (email, ip_address, user_agent, success, attempt_time) VALUES (?, ?, ?, ?, NOW())");
    if ($stmt) {
        $stmt->bind_param("sssi", $email, $ip, $agent, $success);
        $stmt->execute();
        $stmt->close();
    }
}

function logFailedAttempt($conn, $email) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    $stmt = $conn->prepare("INSERT INTO failed_login_logs (email, ip_address, user_agent) VALUES (?, ?, ?)");
    if ($stmt) {
        $stmt->bind_param("sss", $email, $ip, $agent);
        $stmt->execute();
        $stmt->close();
    }
}

// Record a failed login attempt or increment counter
function recordFailedLogin($conn, $email) {
    $stmt = $conn->prepare("INSERT INTO login_attempts (email, attempts) VALUES (?, 1)
        ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP");
    if ($stmt) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->close();
    }
}

// Clear failed login attempts after a successful login
function clearLoginAttempts($conn, $email) {
    $stmt = $conn->prepare("DELETE FROM login_attempts WHERE email = ?");
    if ($stmt) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->close();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyToken($_POST['csrf_token'])) {
        die("CSRF validation failed.");
    }

    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (isLockedOut($conn, $email)) {
        $_SESSION['error_message'] = "⛔ Account temporarily locked. Try again in 15 minutes.";
        header("Location: login_form.php");
        exit;
    }

    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE email = ?");
    if (!$stmt) {
        die("Database error: " . $conn->error);
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 1) {
        $stmt->bind_result($id, $username, $hashed_password);
        $stmt->fetch();

        if (!empty($hashed_password) && password_verify($password, $hashed_password)) {
            // Successful login
            clearLoginAttempts($conn, $email);
            recordLoginAttempt($conn, $email, 1);

            session_regenerate_id(true);

            $_SESSION['user_id'] = $id;
            $_SESSION['username'] = $username;

            // Update last login time
            $update = $conn->prepare('UPDATE users SET last_login = ? WHERE id = ?');
            if ($update) {
                $now = date('Y-m-d H:i:s');
                $update->bind_param("si", $now, $id);
                $update->execute();
                $update->close();
            }

            // Insert login session record
            $insertSession = $conn->prepare("INSERT INTO user_sessions (user_id, login_time) VALUES (?, NOW())");
            if ($insertSession) {
                $insertSession->bind_param("i", $id);
                $insertSession->execute();
                $_SESSION['session_id'] = $insertSession->insert_id;
                $insertSession->close();
            }

            $stmt->close();

            header("Location: index.php");
            exit;
        } else {
            // Password incorrect
            recordFailedLogin($conn, $email);
            logFailedAttempt($conn, $email);
            recordLoginAttempt($conn, $email, 0);

            $_SESSION['error_message'] = "❌ Invalid credentials. Please try again.";
            header("Location: login_form.php");
            exit;
        }
    } else {
        // Email not found
        recordFailedLogin($conn, $email);
        logFailedAttempt($conn, $email);
        recordLoginAttempt($conn, $email, 0);

        $_SESSION['error_message'] = "❌ Invalid credentials. Please try again.";
        header("Location: login_form.php");
        exit;
    }
}
?>
