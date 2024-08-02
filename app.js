const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const databasePath = path.join(__dirname, 'userData.db');
const app = express();

app.use(express.json());
app.use(cors());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () => console.log('Server Running at http://localhost:3000/'));
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

const validatePassword = (password) => password.length > 4;

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!validatePassword(password)) {
    return res.status(400).send('Password is too short');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const selectUserQuery = 'SELECT * FROM users WHERE username = ?';
    const user = await database.get(selectUserQuery, [username]);

    if (user) {
      return res.status(400).send('User already exists');
    }

    const createUserQuery = `
      INSERT INTO users (username, password)
      VALUES (?, ?)
    `;
    await database.run(createUserQuery, [username, hashedPassword]);
    res.send('User created successfully');
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const selectUserQuery = 'SELECT * FROM users WHERE username = ?';
    const user = await database.get(selectUserQuery, [username]);

    if (!user) {
      return res.status(400).send('Invalid user');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (isPasswordMatched) {
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
        expiresIn: '1h',
      });
      res.json({ token });
    } else {
      res.status(400).send('Invalid password');
    }
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).send('Access Denied');
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).send('Invalid Token');
      req.user = user;
      next();
    });
  };
  
  app.post('/register', async (req, res) => {
    const { username, password, name, gender, location } = req.body;
  
    if (!validatePassword(password)) {
      return res.status(400).send('Password is too short');
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      const selectUserQuery = 'SELECT * FROM users WHERE username = ?';
      const user = await database.get(selectUserQuery, [username]);
  
      if (user) {
        return res.status(400).send('User already exists');
      }
  
      const createUserQuery = `
        INSERT INTO users (username, name, password, gender, location)
        VALUES (?, ?, ?, ?, ?)
      `;
      await database.run(createUserQuery, [username, name, hashedPassword, gender, location]);
      res.send('User created successfully');
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    try {
      const selectUserQuery = 'SELECT * FROM users WHERE username = ?';
      const user = await database.get(selectUserQuery, [username]);
  
      if (!user) {
        return res.status(400).send('Invalid user');
      }
  
      const isPasswordMatched = await bcrypt.compare(password, user.password);
  
      if (isPasswordMatched) {
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
          expiresIn: '1h',
        });
        res.json({ token });
      } else {
        res.status(400).send('Invalid password');
      }
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  
  app.post('/todos', authenticateToken, async (req, res) => {
    const { description } = req.body;
    const userId = req.user.userId;
  
    try {
      const createTodoQuery = `
        INSERT INTO todos (user_id, description)
        VALUES (?, ?)
      `;
      await database.run(createTodoQuery, [userId, description]);
      res.send('To-Do item created successfully');
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  
  app.get('/todos', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
  
    try {
      const selectTodosQuery = 'SELECT * FROM todos WHERE user_id = ?';
      const todos = await database.all(selectTodosQuery, [userId]);
      res.json(todos);
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  
  app.put('/todos/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { description, status } = req.body;
  
    try {
      const updateTodoQuery = `
        UPDATE todos
        SET description = ?, status = ?
        WHERE id = ?
      `;
      await database.run(updateTodoQuery, [description, status, id]);
      res.send('To-Do item updated successfully');
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  
  app.delete('/todos/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
  
    try {
      const deleteTodoQuery = 'DELETE FROM todos WHERE id = ?';
      await database.run(deleteTodoQuery, [id]);
      res.send('To-Do item deleted successfully');
    } catch (error) {
      res.status(500).send('Internal Server Error');
    }
  });
  