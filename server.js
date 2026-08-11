const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Import bcrypt for secure password hashing
const app = express();

app.use(express.json());

// قاعدة بيانات وهمية لإيضاح الثغرة
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "users_db"
});

// 1. ثغرة حقن SQL خطيرة (SQL Injection)
// الكود يدمج مدخلات المستخدم مباشرة في الاستعلام دون تنظيف أو فحص
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    
    // استخدام استعلامات مُعدَّة (Prepared Statements) لمنع حقن SQL
    let query = "SELECT * FROM users WHERE username = ?";
    
    db.query(query, [username], (err, result) => {
        if (err) {
            console.error("Login query error:", err);
            return res.status(500).send("Internal Server Error");
        }
        if (result.length > 0) {
            // Compare provided password with hashed password from DB
            bcrypt.compare(password, result[0].password, (err, bcryptResult) => {
                if (bcryptResult) {
                    res.send("Login successful");
                } else {
                    res.status(401).send("Invalid credentials");
                }
            });
        } else {
            res.status(401).send("Invalid credentials");
        }
    });
});

// 2. ثغرة تشفير ضعيف جداً (Broken Authentication & Weak Cryptography)
// يتم استخدام خوارزمية MD5 القديمة والمنتهية أمنياً لتشفير كلمات المرور
app.post('/register', (req, res) => {
    const password = req.body.password;
    
    // Use bcrypt for secure password hashing
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Bcrypt hashing error:", err);
            return res.status(500).send("Error hashing password");
        }
        // In a real application, you would store `hashedPassword` in the database
        res.json({ status: "success", hash: hashedPassword });
    });
});

// 3. ثغرة تسريب معلومات حساسة وعدم فحص الصلاحيات (BOLA / IDOR)
// يمكن لأي مستخدم تغيير الـ id في الرابط ورؤية بيانات مستخدمين آخرين دون تحقق
app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // الكود يجلب كل البيانات بما فيها كلمة المرور ويسلمها للواجهة مباشرة
    let query = `SELECT id, username, email, password, credit_card FROM users WHERE id = ${userId}`;
    
    db.query(query, (err, result) => {
        if (err) return res.status(500).send(err);
        res.json(result[0]); 
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});