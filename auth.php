<?php
require_once 'db.php';

class Auth {
    private $db;
    
    // Password hashing options
    private $hash_options = [
        'cost' => 12
    ];
    
    // Account lockout settings
    private $max_attempts = 5;
    private $lockout_time = 900; // 15 minutes in seconds

    public function __construct() {
        $database = new Database();
        $this->db = $database->getConnection();
    }
    public function getDb() {
        return $this->db;
    }

    // Register a new user
    public function register($username, $email, $password, $full_name = '', $phone = '') {
        // Validate inputs
        if (empty($username) || empty($email) || empty($password)) {
            return ['success' => false, 'message' => 'All fields are required'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'message' => 'Invalid email format'];
        }

        if (strlen($password) < 8) {
            return ['success' => false, 'message' => 'Password must be at least 8 characters'];
        }

        // Check if username or email already exists
        try {
            $stmt = $this->db->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            if ($stmt->fetch()) {
                return ['success' => false, 'message' => 'Username or email already exists'];
            }

            // Hash the password
            $password_hash = password_hash($password, PASSWORD_BCRYPT, $this->hash_options);

            // Insert new user
            $stmt = $this->db->prepare("INSERT INTO users (username, email, password_hash, full_name, phone) 
                                      VALUES (:username, :email, :password_hash, :full_name, :phone)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password_hash', $password_hash);
            $stmt->bindParam(':full_name', $full_name);
            $stmt->bindParam(':phone', $phone);
            
            if ($stmt->execute()) {
                return ['success' => true, 'message' => 'Registration successful'];
            } else {
                return ['success' => false, 'message' => 'Registration failed'];
            }
        } catch (PDOException $e) {
            error_log("Registration error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error'];
        }
    }

    // Login user
    public function login($username, $password, $remember_me = false) {
        // Check for brute force attempts
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $attempts = $this->checkLoginAttempts($username, $ip_address);
        
        if ($attempts >= $this->max_attempts) {
            return ['success' => false, 'message' => 'Account locked. Try again later.'];
        }

        try {
            // Get user by username or email
            $stmt = $this->db->prepare("SELECT * FROM users WHERE username = :username OR email = :username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                $this->recordLoginAttempt(null, $ip_address, false);
                return ['success' => false, 'message' => 'Invalid credentials'];
            }

            // Verify password
            if (password_verify($password, $user['password_hash'])) {
                // Check if password needs rehashing
                if (password_needs_rehash($user['password_hash'], PASSWORD_BCRYPT, $this->hash_options)) {
                    $new_hash = password_hash($password, PASSWORD_BCRYPT, $this->hash_options);
                    $this->updatePasswordHash($user['id'], $new_hash);
                }

                // Update last login
                $this->updateLastLogin($user['id']);

                // Record successful attempt
                $this->recordLoginAttempt($user['id'], $ip_address, true);

                // Start session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['logged_in'] = true;

                // Set remember me cookie if requested
                if ($remember_me) {
                    $this->setRememberMeCookie($user['id']);
                }

                return ['success' => true, 'message' => 'Login successful', 'user' => $user];
            } else {
                $this->recordLoginAttempt($user['id'], $ip_address, false);
                return ['success' => false, 'message' => 'Invalid credentials'];
            }
        } catch (PDOException $e) {
            error_log("Login error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error'];
        }
    }

    // Logout user
    public function logout() {
        // Unset all session variables
        $_SESSION = array();

        // Delete session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }

        // Destroy the session
        session_destroy();

        // Delete remember me cookie
        if (isset($_COOKIE['remember_token'])) {
            setcookie('remember_token', '', time() - 3600, '/');
        }
    }

    // Check if user is logged in
    public function isLoggedIn() {
        if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
            return true;
        }

        // Check for remember me cookie
        if (isset($_COOKIE['remember_token'])) {
            return $this->validateRememberMeToken($_COOKIE['remember_token']);
        }

        return false;
    }

    // Helper methods
    private function checkLoginAttempts($username, $ip_address) {
        try {
            $stmt = $this->db->prepare("SELECT COUNT(*) as attempts 
                                      FROM login_attempts 
                                      WHERE (user_id = (SELECT id FROM users WHERE username = :username OR email = :username) 
                                      OR ip_address = :ip_address
                                      AND attempt_time > datetime('now', '-' . $this->lockout_time . ' seconds')
                                      AND success = 0");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':ip_address', $ip_address);
            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return (int)$result['attempts'];
        } catch (PDOException $e) {
            error_log("Error checking login attempts: " . $e->getMessage());
            return 0;
        }
    }

    private function recordLoginAttempt($user_id, $ip_address, $success) {
        try {
            $stmt = $this->db->prepare("INSERT INTO login_attempts (user_id, ip_address, success) 
                                      VALUES (:user_id, :ip_address, :success)");
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':ip_address', $ip_address);
            $stmt->bindParam(':success', $success, PDO::PARAM_INT);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error recording login attempt: " . $e->getMessage());
        }
    }

    private function updateLastLogin($user_id) {
        try {
            $stmt = $this->db->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = :id");
            $stmt->bindParam(':id', $user_id);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error updating last login: " . $e->getMessage());
        }
    }

    private function updatePasswordHash($user_id, $new_hash) {
        try {
            $stmt = $this->db->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
            $stmt->bindParam(':hash', $new_hash);
            $stmt->bindParam(':id', $user_id);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error updating password hash: " . $e->getMessage());
        }
    }

    private function setRememberMeCookie($user_id) {
        $token = bin2hex(random_bytes(32));
        $expiry = time() + 60 * 60 * 24 * 30; // 30 days
        
        try {
            // Store token in database
            $stmt = $this->db->prepare("INSERT INTO remember_tokens (user_id, token, expires_at) 
                                      VALUES (:user_id, :token, datetime('now', '+30 days'))");
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':token', $token);
            $stmt->execute();
            
            // Set cookie
            setcookie('remember_token', $token, $expiry, '/');
        } catch (PDOException $e) {
            error_log("Error setting remember me token: " . $e->getMessage());
        }
    }

    private function validateRememberMeToken($token) {
        try {
            $stmt = $this->db->prepare("SELECT user_id FROM remember_tokens 
                                      WHERE token = :token 
                                      AND expires_at > datetime('now')");
            $stmt->bindParam(':token', $token);
            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result) {
                $user_id = $result['user_id'];
                
                // Get user data
                $stmt = $this->db->prepare("SELECT * FROM users WHERE id = :id");
                $stmt->bindParam(':id', $user_id);
                $stmt->execute();
                
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user) {
                    // Start session
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['logged_in'] = true;
                    
                    return true;
                }
            }
            
            // Invalid token - delete it
            setcookie('remember_token', '', time() - 3600, '/');
            return false;
        } catch (PDOException $e) {
            error_log("Error validating remember token: " . $e->getMessage());
            return false;
        }
    }
    // Check if user is admin
public function isAdmin($user_id) {
    try {
        $stmt = $this->db->prepare("SELECT is_admin FROM users WHERE id = :id");
        $stmt->bindParam(':id', $user_id);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        return $user && $user['is_admin'] == 1;
    } catch (PDOException $e) {
        error_log("Error checking admin status: " . $e->getMessage());
        return false;
    }
}

// Check if user has specific permission
public function hasPermission($user_id, $permission_name) {
    try {
        $stmt = $this->db->prepare("SELECT COUNT(*) as count 
                                  FROM user_permissions up
                                  JOIN permissions p ON up.permission_id = p.id
                                  WHERE up.user_id = :user_id AND p.name = :permission_name");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':permission_name', $permission_name);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['count'] > 0 || $this->isAdmin($user_id);
    } catch (PDOException $e) {
        error_log("Error checking permission: " . $e->getMessage());
        return false;
    }
}

// Make user an admin
public function makeAdmin($user_id) {
    try {
        $stmt = $this->db->prepare("UPDATE users SET is_admin = 1 WHERE id = :id");
        $stmt->bindParam(':id', $user_id);
        return $stmt->execute();
    } catch (PDOException $e) {
        error_log("Error making user admin: " . $e->getMessage());
        return false;
    }
}

// Add permission to user
public function addPermission($user_id, $permission_name) {
    try {
        // Get permission ID
        $stmt = $this->db->prepare("SELECT id FROM permissions WHERE name = :name");
        $stmt->bindParam(':name', $permission_name);
        $stmt->execute();
        $permission = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($permission) {
            $stmt = $this->db->prepare("INSERT OR IGNORE INTO user_permissions (user_id, permission_id) 
                                      VALUES (:user_id, :permission_id)");
            $stmt->bindParam(':user_id', $user_id);
            $stmt->bindParam(':permission_id', $permission['id']);
            return $stmt->execute();
        }
        return false;
    } catch (PDOException $e) {
        error_log("Error adding permission: " . $e->getMessage());
        return false;
    }
}
}
?>