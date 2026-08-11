const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// قاعدة بيانات وهمية لإيضاح الثغرة
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "users_db"
});

// Placeholder for a simple authentication middleware (e.g., JWT, session)
// In a real application, this would verify a token or session and attach user info to req.user
const authenticateUser = (req, res, next) => {
    // For demonstration, let's assume a user with ID 1 is authenticated
    // In a real application, this would come from a JWT, session, etc.
    // And would check if the user is logged in.
    // If not authenticated, return 401 Unauthorized
    // Example: req.user = { id: 1, role: 'user' };
    
    // THIS IS A SIMPLIFIED PLACEHOLDER. 
    // In a production app, robust authentication (e.g., JWT verification) is essential.
    req.user = { id: 1, role: 'user' }; // Simulate an authenticated user
    next();
};

// 1. ثغرة حقن SQL خطيرة (SQL Injection)
// الكود يدمج مدخلات المستخدم مباشرة في الاستعلام دون تنظيف أو فحص
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // استخدام استعلامات مُعدَّة (Prepared Statements) لمنع حقن SQL
    let query = "SELECT * FROM users WHERE username = ? AND password = ?";
    
    db.query(query, [username, password], (err, result) => {
        if (err) {
            console.error("Login query error:", err);
            return res.status(500).send("Internal Server Error");
        }
        if (result.length > 0) {
            res.send("Login successful");
        } else {
            res.status(401).send("Invalid credentials");
        }
    });
});

// 2. ثغرة تشفير ضعيف جداً (Broken Authentication & Weak Cryptography)
// يتم استخدام خوارزمية MD5 القديمة والمنتهية أمنياً لتشفير كلمات المرور
app.post('/register', (req, res) => {
    const password = req.body.password;
    
    // MD5 يعتبر ثغرة أمنية ويسهل كسر تشفيره
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    
    res.json({ status: "success", hash: hashedPassword });
});

// 3. ثغرة تسريب معلومات حساسة وعدم فحص الصلاحيات (BOLA / IDOR)
// يمكن لأي مستخدم تغيير الـ id في الرابط ورؤية بيانات مستخدمين آخرين دون تحقق
app.get('/api/user/:id', authenticateUser, (req, res) => {
    const userId = req.params.id;
    
    // Ensure the authenticated user can only access their own data
    if (req.user && req.user.id.toString() !== userId) {
        return res.status(403).send("Access Denied: You can only view your own user data.");
    }

    // الكود يجلب كل البيانات بما فيها كلمة المرور ويسلمها للواجهة مباشرة
    // Modified to use prepared statements and exclude sensitive fields like password and credit_card
    let query = `SELECT id, username, email FROM users WHERE id = ?`;
    
    db.query(query, [userId], (err, result) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).send("Internal Server Error");
        }
        if (result.length === 0) {
            return res.status(404).send("User not found.");
        }
        res.json(result[0]); 
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
