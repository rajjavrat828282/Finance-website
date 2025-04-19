<?php
require_once 'auth.php';
session_start();

$auth = new Auth();

if (!$auth->isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Get user data
$user_id = $_SESSION['user_id'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Finance Tracker</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav>
        <div class="nav-brand">Finance Tracker</div>
        <div class="nav-links">
            <a href="dashboard.php" class="active">Dashboard</a>
            <a href="expenses.php">Expenses</a>
            <a href="budget.php">Budget</a>
            <a href="savings.php">Savings</a>
            <a href="reports.php">Reports</a>
            <a href="advice.php">Advice</a>
            <a href="logout.php">Logout</a>
        </div>
    </nav>

    <div class="container">
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
        
        <div class="dashboard-summary">
            <div class="summary-card">
                <h3>Monthly Expenses</h3>
                <p class="amount">₹12,345</p>
                <p class="change positive">+5% from last month</p>
            </div>
            
            <div class="summary-card">
                <h3>Budget Status</h3>
                <p class="amount">75% used</p>
                <div class="progress-bar">
                    <div class="progress" style="width: 75%"></div>
                </div>
            </div>
            
            <div class="summary-card">
                <h3>Savings Progress</h3>
                <p class="amount">₹25,000/₹50,000</p>
                <div class="progress-bar">
                    <div class="progress" style="width: 50%"></div>
                </div>
            </div>
        </div>
        
        <div class="recent-activities">
            <h2>Recent Activities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Description</th>
                        <th>Amount</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>2023-05-15</td>
                        <td>Grocery shopping</td>
                        <td class="expense">₹1,250</td>
                        <td>Food</td>
                    </tr>
                    <tr>
                        <td>2023-05-14</td>
                        <td>Electricity bill</td>
                        <td class="expense">₹1,800</td>
                        <td>Utilities</td>
                    </tr>
                    <tr>
                        <td>2023-05-10</td>
                        <td>Salary</td>
                        <td class="income">₹45,000</td>
                        <td>Income</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>