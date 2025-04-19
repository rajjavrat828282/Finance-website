<?php
require_once 'auth.php';
session_start();

$auth = new Auth();

// Check if user is admin
if (!$auth->isLoggedIn() || !$auth->isAdmin($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['make_admin'])) {
        $user_id = $_POST['user_id'];
        $auth->makeAdmin($user_id);
    } elseif (isset($_POST['add_permission'])) {
        $user_id = $_POST['user_id'];
        $permission = $_POST['permission'];
        $auth->addPermission($user_id, $permission);
    }
}

// Get database connection from Auth class
$db = $auth->getDb(); // Changed from getConnection() to getDb()

// Get all users
try {
    $stmt = $db->prepare("SELECT id, username, email, is_admin FROM users");
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get all permissions
    $stmt = $db->prepare("SELECT * FROM permissions");
    $stmt->execute();
    $permissions = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Error fetching data: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .admin-panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }
        .user-card, .permission-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .admin-badge {
            background: var(--primary);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin-left: 0.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background-color: var(--secondary);
            color: white;
        }
        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <nav>
        <div class="nav-brand">Finance Tracker - Admin Panel</div>
        <div class="nav-links">
            <a href="dashboard.php">User Dashboard</a>
            <a href="admin.php" class="active">Admin Panel</a>
            <a href="logout.php">Logout</a>
        </div>
    </nav>

    <div class="container">
        <h1>Admin Dashboard</h1>
        
        <div class="admin-panel">
            <div class="user-card">
                <h2>User Management</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= htmlspecialchars($user['username']) ?></td>
                            <td><?= htmlspecialchars($user['email']) ?></td>
                            <td>
                                <?php if ($user['is_admin']): ?>
                                    <span class="admin-badge">Admin</span>
                                <?php else: ?>
                                    User
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (!$user['is_admin']): ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                    <button type="submit" name="make_admin" class="btn btn-primary btn-sm">Make Admin</button>
                                </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <div class="permission-card">
                <h2>Permission Management</h2>
                <form method="POST">
                    <div class="form-group">
                        <label for="user_id">Select User</label>
                        <select name="user_id" id="user_id" required>
                            <option value="">Select User</option>
                            <?php foreach ($users as $user): ?>
                            <option value="<?= $user['id'] ?>">
                                <?= htmlspecialchars($user['username']) ?>
                                <?php if ($user['is_admin']): ?>(Admin)<?php endif; ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="permission">Select Permission</label>
                        <select name="permission" id="permission" required>
                            <option value="">Select Permission</option>
                            <?php foreach ($permissions as $perm): ?>
                            <option value="<?= $perm['name'] ?>">
                                <?= htmlspecialchars($perm['name']) ?> - <?= htmlspecialchars($perm['description']) ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <button type="submit" name="add_permission" class="btn btn-primary">Add Permission</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>