<?php
$host = 'localhost';
$db = 'secure_login';
$user = 'root';
$pass = ''; // Set your DB password here

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
