const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

console.log('JWT_SECRET:', JWT_SECRET);
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  var token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  if (!token) {
    token = req.cookies.token; // Check for token in cookies
    if (!token) {
      return res.status(401).render('error', {
  status: 401,
  message: 'Token required'
      });
    }
  }
  if (!token) return res.status(401).render('error', {
  status: 401,
  message: 'Token required'
});

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).render('error', {
  status: 403,
  message: 'Invalid token'
  });
    req.user = user; // Save decoded user info
    next();
  });
}

function is_admin(req, res, next) {
  const authUser = req.headers['authorization'];
  var token = authUser && authUser.split(' ')[1]; // Bearer <token>
  if (!token) {
    token = req.cookies.token; // Check for token in cookies
  }
  if (!token) return res.status(401).render('error', {
  status: 401,
  message: 'Token required'
});
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).render('error', {
  status: 401,
  message: 'Invalid token'
});
    if (user.role !== 'admin') return res.status(403).render('error', {
  status: 401,
  message: 'Unauthorized: Admin access required'
});
    req.user = user; // Save decoded user info
    next();
  });
}
module.exports = {authenticateToken, is_admin};