const express = require('express');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs'); // File System module to delete files
const db = require('./database.js');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'a-super-secret-key-that-should-be-long-and-random';

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Multer Configuration ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + file.originalname;
        cb(null, uniqueName);
    }
});
const upload = multer({ storage: storage });

// --- Authentication Middleware ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// --- API ROUTES ---
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
    db.run(sql, [email, hashedPassword], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ message: 'This email is already registered.' });
            }
            return res.status(500).json({ message: 'Error registering user.' });
        }
        res.status(201).json({ message: 'User registered successfully!' });
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const isPasswordCorrect = bcrypt.compareSync(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const payload = { userId: user.id, email: user.email };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Logged in successfully!', token: token });
    });
});

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }
    const { originalname, filename } = req.file;
    const userId = req.user.userId;
    const sql = 'INSERT INTO files (original_name, saved_filename, user_id) VALUES (?, ?, ?)';
    db.run(sql, [originalname, filename, userId], function(err) {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Error saving file info to database.' });
        }
        res.status(200).json({ message: 'File uploaded successfully!' });
    });
});

app.get('/api/myfiles', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const sql = 'SELECT id, original_name, saved_filename, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC';
    db.all(sql, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching files.' });
        }
        res.status(200).json(rows);
    });
});

// New route to download a file
app.get('/download/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.filename);
    res.download(filePath, (err) => {
        if (err) {
            res.status(404).send('File not found.');
        }
    });
});

// New route to delete a file
app.delete('/api/files/:id', authenticateToken, (req, res) => {
    const fileId = req.params.id;
    const userId = req.user.userId;

    // First, get the filename from the DB to delete it from the folder
    const getFileSql = 'SELECT saved_filename FROM files WHERE id = ? AND user_id = ?';
    db.get(getFileSql, [fileId, userId], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ message: 'File not found or you do not have permission.' });
        }
        
        // Delete the physical file
        const filePath = path.join(__dirname, 'uploads', row.saved_filename);
        fs.unlink(filePath, (unlinkErr) => {
            if (unlinkErr) {
                // Still proceed to delete from DB, but log the error
                console.error("Error deleting physical file:", unlinkErr);
            }
            
            // Delete the record from the database
            const deleteSql = 'DELETE FROM files WHERE id = ? AND user_id = ?';
            db.run(deleteSql, [fileId, userId], function(dbErr) {
                if (dbErr) {
                    return res.status(500).json({ message: 'Error deleting file from database.' });
                }
                res.status(200).json({ message: 'File deleted successfully.' });
            });
        });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});