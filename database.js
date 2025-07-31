const sqlite3 = require('sqlite3').verbose();
const DB_PATH = './featherdrop.db';

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        return console.error('Error connecting to database:', err.message);
    }
    console.log('Connected to the FeatherDrop SQLite database. ✅');
    createTables();
});

function createTables() {
    const createUserTableSql = `
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    `;
    db.run(createUserTableSql, (err) => {
        if (err) return console.error('Error creating users table:', err.message);
        console.log('Users table is ready.');
    });

    // New table for files
    const createFilesTableSql = `
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            saved_filename TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    `;
    db.run(createFilesTableSql, (err) => {
        if (err) return console.error('Error creating files table:', err.message);
        console.log('Files table is ready.');
    });
}

module.exports = db;