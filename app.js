const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'UserAuth'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to database.');
});

const JWT_SECRET = 'your_secret_key';

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Signup endpoint
app.post('/signup', (req, res) => {
    const { name, username, age, gender, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Database error: ' + err);
        if (results.length > 0) return res.status(400).send('Username already exists!');

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).send('Error hashing password: ' + err);

            db.query('INSERT INTO users (name, username, age, gender, password) VALUES (?, ?, ?, ?, ?)', 
            [name, username, age, gender, hash], (err, results) => {
                if (err) return res.status(500).send('Database error: ' + err);
                res.send('Sign-up successful!');
            });
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0) return res.status(400).send('User not found');
        
        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) return res.status(401).send('Incorrect password');
            
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });
    });
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Get users endpoint
app.get('/users', authenticateToken, (req, res) => {
    db.query('SELECT id, name, username, age, gender FROM users', (err, results) => {
        if (err) return res.status(500).send('Database error: ' + err);
        res.json(results);
    });
});

app.delete('/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    db.query('DELETE FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) return res.status(500).send('Database error: ' + err);
        if (results.affectedRows === 0) {
            return res.status(404).send('User not found.');
        }
        res.send('User deleted successfully');
    });
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
