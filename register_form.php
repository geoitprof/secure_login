<?php require 'csrf.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>

    <!-- ✅ Bootstrap CSS -->
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

<!-- ✅ Corporate Navbar -->
<nav class="navbar navbar-expand-lg">
    <div class="container">
        <a class="navbar-brand" href="#">SecureLogin</a>
    </div>
</nav>

<!-- ✅ Centered Registration Card -->
<div class="container d-flex justify-content-center align-items-center vh-100">
    <div class="card p-4 w-100" style="max-width: 400px;">
        <h3 class="text-center mb-3">Create Account</h3>
        <form method="POST" action="register.php">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" name="username" class="form-control" id="username" placeholder="Choose a username" required>
            </div>
            <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" name="email" class="form-control" id="email" placeholder="Enter your email" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password (min 6 characters)</label>
                <input type="password" name="password" class="form-control" id="password" placeholder="Create a password" required>
            </div>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generateToken()); ?>">
            <button type="submit" class="btn btn-corporate w-100">Register</button>
        </form>
        <div class="text-center mt-3">
            <small>Already have an account? <a href="login_form.php">Login here</a></small>
        </div>
    </div>
</div>

</body>
</html>
