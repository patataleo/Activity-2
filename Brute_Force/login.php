<?php
// Database connection
$host = "localhost";
$db = "brute_force_protection";
$user = "root";
$pass = "";

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Helper function to check if user is locked out
function isLockedOut($conn, $userId) {
    // Get the count of failed attempts in the last 5 minutes
    $failCountQuery = $conn->prepare("SELECT COUNT(*) AS fail_count FROM log_in_attempts WHERE user_id = ? AND attempt = 'failed' AND timestamp > (NOW() - INTERVAL 5 MINUTE)");
    $failCountQuery->bind_param("i", $userId);
    $failCountQuery->execute();
    $failCount = $failCountQuery->get_result()->fetch_assoc()['fail_count'];
    
    // If there are 5 or more failed attempts
    if ($failCount >= 5) {
        // Get the most recent failed attempt timestamp using UNIX_TIMESTAMP for consistency
        $lockTimeQuery = $conn->prepare("SELECT UNIX_TIMESTAMP(timestamp) as unix_time FROM log_in_attempts WHERE user_id = ? AND attempt = 'failed' ORDER BY timestamp DESC LIMIT 1");
        $lockTimeQuery->bind_param("i", $userId);
        $lockTimeQuery->execute();
        $result = $lockTimeQuery->get_result();
        
        if ($result->num_rows > 0) {
            $lastAttemptTime = $result->fetch_assoc()['unix_time'];
            $unlockTime = $lastAttemptTime + 300; // Exactly 5 minutes (300 seconds)
            $currentTime = time();
            
            if ($currentTime < $unlockTime) {
                // Cap at 300 seconds max to prevent any potentially large values
                $remainingSeconds = min(300, $unlockTime - $currentTime);
                return ['locked' => true, 'remainingSeconds' => $remainingSeconds];
            }
        }
    }
    
    return ['locked' => false, 'remainingSeconds' => 0];
}

// Helper function to get user ID by username
function getUserId($conn, $username) {
    $stmt = $conn->prepare("SELECT id FROM user WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result ? $result['id'] : null;
}

// Initialize variables
$isLocked = false;
$remainingSeconds = 0;
$enteredUsername = '';
$failedAttempts = 0;

// Process login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $enteredUsername = $username; // Save for form pre-fill
    $password = $_POST['password'] ?? '';

    // Find user
    $stmt = $conn->prepare("SELECT id, password FROM user WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if ($user) {
        $userId = $user['id'];

        // Check if locked out
        $lockoutInfo = isLockedOut($conn, $userId);
        $isLocked = $lockoutInfo['locked'];
        $remainingSeconds = $lockoutInfo['remainingSeconds'];
        
        // Get number of recent failed attempts
        $failQuery = $conn->prepare("SELECT COUNT(*) AS count FROM log_in_attempts WHERE user_id = ? AND attempt = 'failed' AND timestamp > (NOW() - INTERVAL 5 MINUTE)");
        $failQuery->bind_param("i", $userId);
        $failQuery->execute();
        $failedAttempts = $failQuery->get_result()->fetch_assoc()['count'];
        
        if ($isLocked) {
            $error_message = "Too many failed attempts. Try again after countdown expires.";
        }
        // Validate password
        else if ($password === $user['password']) {
            // Successful login
            $stmt = $conn->prepare("INSERT INTO log_in_attempts (user_id, attempt, timestamp) VALUES (?, 'success', NOW())");
            $stmt->bind_param("i", $userId);
            $stmt->execute();

            $success_message = "Login successful!";
            $failedAttempts = 0;
        } else {
            // Failed login
            $stmt = $conn->prepare("INSERT INTO log_in_attempts (user_id, attempt, timestamp) VALUES (?, 'failed', NOW())");
            $stmt->bind_param("i", $userId);
            $stmt->execute();

            // Increment failed attempts count
            $failedAttempts++;
            
            // Check if this new failure causes a lockout
            $lockoutInfo = isLockedOut($conn, $userId);
            $isLocked = $lockoutInfo['locked'];
            $remainingSeconds = $lockoutInfo['remainingSeconds'];
            
            if ($isLocked) {
                $error_message = "Too many failed attempts. Try again after countdown expires.";
            } else {
                $error_message = "Incorrect password.";
            }
        }
    } else {
        $error_message = "User not found.";
    }
} else if (isset($_GET['username']) && !empty($_GET['username'])) {
    // Check lockout status on page load if username is provided in URL
    $enteredUsername = $_GET['username'];
    $userId = getUserId($conn, $enteredUsername);
    
    if ($userId) {
        $lockoutInfo = isLockedOut($conn, $userId);
        $isLocked = $lockoutInfo['locked'];
        $remainingSeconds = $lockoutInfo['remainingSeconds'];
        
        // Get number of recent failed attempts
        $failQuery = $conn->prepare("SELECT COUNT(*) AS count FROM log_in_attempts WHERE user_id = ? AND attempt = 'failed' AND timestamp > (NOW() - INTERVAL 5 MINUTE)");
        $failQuery->bind_param("i", $userId);
        $failQuery->execute();
        $failedAttempts = $failQuery->get_result()->fetch_assoc()['count'];
        
        if ($isLocked) {
            $error_message = "Too many failed attempts. Try again after countdown expires.";
        }
    }
}

// Add debug info if there's an issue with the timer
if ($isLocked) {
    $debugQuery = $conn->prepare("SELECT timestamp, UNIX_TIMESTAMP(timestamp) as unix_time FROM log_in_attempts WHERE user_id = ? AND attempt = 'failed' ORDER BY timestamp DESC LIMIT 1");
    $debugQuery->bind_param("i", $userId);
    $debugQuery->execute();
    $debugResult = $debugQuery->get_result()->fetch_assoc();
    
    $debugInfo = [
        "Current server time" => time() . " (" . date('Y-m-d H:i:s') . ")",
        "Last attempt time" => $debugResult['unix_time'] . " (" . $debugResult['timestamp'] . ")",
        "Unlock time" => ($debugResult['unix_time'] + 300) . " (" . date('Y-m-d H:i:s', $debugResult['unix_time'] + 300) . ")",
        "Raw remaining seconds" => (($debugResult['unix_time'] + 300) - time()),
        "Capped remaining seconds" => $remainingSeconds
    ];
    
    // Store debug info in a hidden HTML comment
    $debug_comment = "<!-- Debug lockout info: " . json_encode($debugInfo, JSON_PRETTY_PRINT) . " -->";
}
?>

<!-- HTML Login Form -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4e54c8;
            --primary-dark: #363795;
            --secondary-color: #8f94fb;
            --text-color: #333;
            --error-color: #e74c3c;
            --success-color: #2ecc71;
            --light-color: #f9f9f9;
            --shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, var(--secondary-color) 0%, var(--primary-color) 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: var(--text-color);
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .bg-animation {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
        }
        
        .wave {
            position: absolute;
            opacity: 0.3;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            animation: wave 15s infinite;
            pointer-events: none;
        }
        
        .wave:nth-child(1) {
            width: 600px;
            height: 600px;
            left: -100px;
            bottom: -100px;
            animation-delay: 0s;
        }
        
        .wave:nth-child(2) {
            width: 400px;
            height: 400px;
            right: -50px;
            top: -50px;
            animation-delay: 3s;
            animation-duration: 12s;
        }
        
        .wave:nth-child(3) {
            width: 300px;
            height: 300px;
            right: 30%;
            bottom: 30%;
            animation-delay: 6s;
            animation-duration: 10s;
        }
        
        @keyframes wave {
            0% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.2);
            }
            100% {
                transform: scale(1);
            }
        }
        
        .container {
            background-color: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            box-shadow: var(--shadow);
            overflow: hidden;
            width: 100%;
            max-width: 400px;
            position: relative;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
        
        .login-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            padding: 25px 30px;
            text-align: center;
        }
        
        .login-header h1 {
            color: white;
            font-size: 28px;
            font-weight: 600;
            margin: 0;
        }
        
        .login-header p {
            color: rgba(255, 255, 255, 0.8);
            margin-top: 8px;
            font-size: 14px;
        }
        
        .login-form {
            padding: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
            position: relative;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-color);
            font-size: 14px;
        }
        
        .input-group {
            position: relative;
        }
        
        .input-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 12px 12px 40px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 16px;
            transition: all 0.3s ease;
            outline: none;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(78, 84, 200, 0.2);
        }
        
        .btn {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 14px;
            font-size: 16px;
            font-weight: 600;
            width: 100%;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(78, 84, 200, 0.2);
        }
        
        .btn:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary-color) 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 8px rgba(78, 84, 200, 0.3);
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-error {
            background-color: rgba(231, 76, 60, 0.1);
            border-left: 4px solid var(--error-color);
            color: var(--error-color);
        }
        
        .alert-success {
            background-color: rgba(46, 204, 113, 0.1);
            border-left: 4px solid var(--success-color);
            color: var(--success-color);
        }
        
        .security-badge {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 15px;
            padding: 10px;
            background-color: var(--light-color);
            border-radius: 6px;
            font-size: 12px;
            color: #666;
        }
        
        .security-badge i {
            color: var(--primary-color);
            margin-right: 6px;
            font-size: 14px;
        }
        
        .countdown-container {
            background-color: rgba(231, 76, 60, 0.08);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .countdown-timer {
            font-size: 32px;
            font-weight: bold;
            color: var(--error-color);
            margin: 15px 0;
            font-family: monospace;
        }
        
        .countdown-text {
            font-size: 14px;
            color: var(--text-color);
            margin-bottom: 10px;
        }
        
        .countdown-info {
            font-size: 12px;
            color: #666;
        }
        
        .locked-btn {
            background: #888;
            cursor: not-allowed;
        }
        
        .attempt-counter {
            font-size: 12px;
            text-align: center;
            color: #777;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <?php if (isset($debug_comment)) echo $debug_comment; ?>
    
    <div class="bg-animation">
        <div class="wave"></div>
        <div class="wave"></div>
        <div class="wave"></div>
    </div>
    
    <div class="container">
        <div class="login-header">
            <h1>Secure Login</h1>
            <p>Please enter your credentials to continue</p>
        </div>
        
        <div class="login-form">
            <?php if (isset($error_message)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                </div>
            <?php endif; ?>
            
            <?php if (isset($success_message)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> <?php echo $success_message; ?>
                </div>
            <?php endif; ?>
            
            <?php if ($isLocked): ?>
                <div class="countdown-container">
                    <div class="countdown-text">Account temporarily locked due to multiple failed attempts</div>
                    <div class="countdown-timer" id="countdown">05:00</div>
                    <div class="countdown-info">
                        <i class="fas fa-info-circle"></i> You can try again after the countdown expires
                    </div>
                </div>
                
                <button type="button" class="btn locked-btn">
                    <i class="fas fa-lock"></i> Locked
                </button>
                
                <script>
                    // Set the initial countdown time (ensure it's capped at 300 seconds maximum)
                    let remainingSeconds = Math.min(3000, <?php echo $remainingSeconds; ?>);
                    const countdownElement = document.getElementById('countdown');
                    
                    function updateCountdown() {    
                        const minutes = Math.floor(remainingSeconds / 60);
                        const seconds = remainingSeconds % 60;
                        
                        // Format the time as MM:SS
                        countdownElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                        
                        if (remainingSeconds <= 0) {
                            clearInterval(countdownInterval);
                            // Redirect to the same page to refresh login form
                            window.location.href = "?username=<?php echo urlencode($enteredUsername); ?>";
                        }
                        
                        remainingSeconds--;
                    }
                    
                    // Initialize the countdown and update every second
                    updateCountdown();
                    const countdownInterval = setInterval(updateCountdown, 1000);
                </script>
            <?php else: ?>
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <div class="input-group">
                            <i class="fas fa-user input-icon"></i>
                            <input type="text" id="username" name="username" class="form-control" required placeholder="Enter your username" value="<?php echo htmlspecialchars($enteredUsername); ?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <div class="input-group">
                            <i class="fas fa-lock input-icon"></i>
                            <input type="password" id="password" name="password" class="form-control" required placeholder="Enter your password">
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                    
                    <?php if ($failedAttempts > 0): ?>
                        <div class="attempt-counter">
                            <?php echo $failedAttempts; ?>/5 failed attempts
                        </div>
                    <?php endif; ?>
                </form>
            <?php endif; ?>
            
            <div class="security-badge">
                <i class="fas fa-shield-alt"></i> Protected with brute force detection
            </div>
        </div>
    </div>
</body>
</html>