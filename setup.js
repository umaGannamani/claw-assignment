const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

const databasePath = path.join(__dirname, 'userData.db');

const setupDatabase = async () => {
  const db = await open({
    filename: databasePath,
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS todos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      description TEXT NOT NULL,
      status TEXT CHECK(status IN ('pending', 'completed')) DEFAULT 'pending',
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await db.close();
};

setupDatabase().catch((err) => {
  console.error(`Error setting up database: ${err.message}`);
});
