<?php
session_start();
require 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login_form.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Fetch last login time from users table
$stmt = $conn->prepare("SELECT last_login FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($last_login);
$stmt->fetch();
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - <?php echo htmlspecialchars($username); ?></title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        body {
            background-color: #f4f6f8;
            color: #212529;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            background-color: #004085;
        }
        .navbar .navbar-brand {
            color: #fff;
            font-weight: bold;
        }
        .card {
            background-color: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.05);
        }
        a {
            color: #004085;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .btn-corporate {
            background-color: #004085;
            color: white;
            font-weight: 500;
        }
        .btn-corporate:hover {
            background-color: #003166;
        }
    </style>
</head>
<body>

<!-- Navbar -->
<nav class="navbar navbar-expand-lg navbar-dark mb-4">
    <div class="container-fluid">
        <a class="navbar-brand" href="#">SecureLogin</a>
        <div class="d-flex">
            <span class="navbar-text me-3">
                Logged in as: <?php echo htmlspecialchars($username); ?>
            </span>
            <a href="logout.php" class="btn btn-danger btn-sm">Logout</a>
        </div>
    </div>
</nav>

<!-- Main Content -->
<div class="container">
    <div class="mb-4">
        <h2>Welcome, <?php echo htmlspecialchars($username); ?>!</h2>
        <p class="text-muted">Last login: <?php echo htmlspecialchars($last_login ?? 'N/A'); ?></p>
    </div>

    <!-- Recent Login Attempts -->
    <div class="card p-3 mb-4">
        <h4>Recent Login Attempts</h4>
        <table class="table table-dark table-hover table-bordered mt-3">
            <thead>
                <tr>
                    <th>Email</th>
                    <th>Attempts</th>
                    <th>Last Attempt</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $result = $conn->query("SELECT email, attempts, last_attempt FROM login_attempts ORDER BY last_attempt DESC LIMIT 10");
            if ($result && $result->num_rows > 0):
                while ($row = $result->fetch_assoc()):
            ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['email']); ?></td>
                    <td><?php echo (int)$row['attempts']; ?></td>
                    <td><?php echo htmlspecialchars($row['last_attempt']); ?></td>
                </tr>
            <?php endwhile; else: ?>
                <tr><td colspan="3">No login attempts found.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- User's Login Sessions -->
    <div class="card p-3">
        <h4>Your Login Sessions</h4>
        <table class="table table-striped table-hover table-bordered mt-3">
            <thead>
                <tr>
                    <th>Login Time</th>
                    <th>Logout Time</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $stmt = $conn->prepare("SELECT login_time, logout_time FROM user_sessions WHERE user_id = ? ORDER BY login_time DESC LIMIT 10");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows > 0):
                while ($session = $result->fetch_assoc()):
            ?>
                <tr>
                    <td><?php echo htmlspecialchars($session['login_time']); ?></td>
                    <td><?php echo $session['logout_time'] ? htmlspecialchars($session['logout_time']) : '<em>Still logged in</em>'; ?></td>
                </tr>
            <?php endwhile; else: ?>
                <tr><td colspan="2">No session data found.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

</div>

</body>
</html>
