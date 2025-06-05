<?php
session_start();
require 'db.php';       // Your mysqli connection setup
require 'csrf.php';     // Your CSRF token functions

define('MAX_ATTEMPTS', 5);
define('LOCK_TIME', 900); // 15 minutes lockout

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// 🔒 Check if account is locked out due to too many failed attempts
function isLockedOut($conn, $email) {
    $stmt = $conn->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE email = ?");
    if (!$stmt) return false;
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($attempts, $last_attempt);
    if ($stmt->fetch()) {
        if ($last_attempt && $attempts >= MAX_ATTEMPTS && (time() - strtotime($last_attempt)) < LOCK_TIME) {
            return true;
        }
    }
    return false;
}

// 🔒 Record a failed login attempt or increment counter
function recordFailedLogin($conn, $email) {
    $stmt = $conn->prepare("INSERT INTO login_attempts (email, attempts) VALUES (?, 1)
        ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP");
    if ($stmt) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
    }
}

// ✅ Clear failed login attempts after a successful login
function clearLoginAttempts($conn, $email) {
    $stmt = $conn->prepare("DELETE FROM login_attempts WHERE email = ?");
    if ($stmt) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
    }
}

$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ✅ CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyToken($_POST['csrf_token'])) {
        die("CSRF validation failed.");
    }

    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // ✅ Check lockout status
    if (isLockedOut($conn, $email)) {
        $error_message = "⛔ Account temporarily locked. Try again in 15 minutes.";
    } else {
        // Fetch user by email
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

            // Verify password
            if (!empty($hashed_password) && password_verify($password, $hashed_password)) {
                clearLoginAttempts($conn, $email);
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
                recordFailedLogin($conn, $email);
                $error_message = "❌ Invalid credentials. Please try again.";
            }
        } else {
            recordFailedLogin($conn, $email);
            $error_message = "❌ Invalid credentials. Please try again.";
        }
    }
}

?>
