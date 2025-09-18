const express = require('express');
const app = express();
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { authenticateToken, is_admin } = require('./middleware/auth');
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views'); // Optional if you keep templates in /views
const resetTokens = {}; // token -> email

dotenv.config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts. Please try again later.'
});
app.use(cookieParser());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('./public'));


app.get('/login', (req, res) => {
  res.status(200).sendFile(__dirname + '/public/login.html');
});
app.get('/success', (req, res) => {
  res.status(200).sendFile(__dirname + '/public/success.html');
});
app.post('/login', async (req, res) => { 
  const {username, password} = req.body;
  const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
  const token = jwt.sign({ username: user.username , role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: 3600000
  });
  res.status(200).json({ message: 'Login successful', token: token });
});
app.post('/logout',authenticateToken,(req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true, // match cookie settings used when setting the token
    sameSite: 'Strict'
  });

  // If you're storing tokens (e.g., in a DB blacklist), invalidate it here

  return res.status(200).json({ message: 'Logged out successfully' });
});

app.get('/register', (req, res) => {
  res.status(200).sendFile(__dirname + '/public/register.html');
});
app.post('/register', async (req, res) => {
  const { name, username, password, email } = req.body;
  const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (user) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  const result2 = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  const user2 = result2.rows[0];
  if (user2) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const result3 = await db.query('INSERT INTO users (name, username, password, email, role) VALUES ($1, $2, $3, $4, $5) RETURNING *', [name, username, hashedPassword, email, 'user']);
  const user3 = result3.rows[0];
  if (!user3) {
    return res.status(400).json({ error: 'Failed to register user' });
  }
  res.status(201).redirect('/success');
});
const crypto = require('crypto');

app.get('/admin', authenticateToken, is_admin, (req, res) => {
  const base = process.env.flag || 'CTF{admin_access}';

  const dynamicPart = crypto.randomBytes(8).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);

  const flag = `${base}_${dynamicPart}`;

  res.render('admin', { flag });
});


app.get('/user', authenticateToken, (req, res) => {
  console.log(req.user);
  res.status(200).sendFile(__dirname + '/user.html');
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT name, username, email, role FROM users WHERE username = $1', [req.user.username]);
    const user = result.rows[0];
    if (!user) return res.status(404).send('User not found');

    res.render('profile', { user });
  } catch (err) {
    console.error('Error loading profile:', err);
    res.status(500).send('Internal Server Error');
  }
});
app.get('/posts', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, content FROM posts WHERE post_owner = $1 ORDER BY id DESC',
      [req.user.username]
    );

    res.json({ posts: result.rows });
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/posts', authenticateToken, async (req, res) => {
  const { content } = req.body;

  if (!content || content.trim() === '') {
    return res.status(400).json({ error: 'Post content is required' });
  }

  try {
    await db.query(
      'INSERT INTO posts (post_owner, content) VALUES ($1, $2)',
      [req.user.username, content]
    );

    res.status(201).json({ message: 'Post created successfully' });
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.delete('/posts/:id', authenticateToken, async (req, res) => {
  const postId = req.params.id;

  try {
    const result = await db.query(
      'DELETE FROM posts WHERE id = $1 AND post_owner = $2 RETURNING *',
      [postId, req.user.username]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Post not found or not owned by user' });
    }

    res.json({ message: 'Post deleted' });
  } catch (err) {
    console.error('Error deleting post:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/profile/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const result = await db.query('SELECT name, username, email, role FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(404).send('User not found');

    const posts = await db.query('SELECT content FROM posts WHERE post_owner = $1 ORDER BY id DESC', [username]);

    res.render('profile_other', { user, posts: posts.rows });
  } catch (err) {
    console.error('Error loading profile:', err);
    res.status(500).send('Internal Server Error');
  }
});
app.get('/search', authenticateToken, async (req, res) => {
  const query = req.query.q;

  if (!query || query.trim() === '') {
    return res.status(400).json({ error: 'Query required' });
  }

  try {
    const userResults = await db.query(
      'SELECT username, name FROM users WHERE username ILIKE $1 OR name ILIKE $1 LIMIT 10',
      [`%${query}%`]
    );

    const postResults = await db.query(
      'SELECT content, post_owner FROM posts WHERE content ILIKE $1 LIMIT 10',
      [`%${query}%`]
    );

    res.json({
      users: userResults.rows,
      posts: postResults.rows
    });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/feed', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT post_owner, content
      FROM posts
      ORDER BY id DESC
      LIMIT 50
    `);

    res.render('feed', { posts: result.rows, currentUser: req.user.username });
  } catch (err) {
    console.error('Error loading feed:', err);
    res.status(500).send('Internal Server Error');
  }
});
// 404 Not Found handler
app.use((req, res, next) => {
  res.status(404).render('error', {
    status: 404,
    message: 'Page Not Found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  res.status(err.status || 500).render('error', {
    status: err.status || 500,
    message: err.message || 'Internal Server Error'
  });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});