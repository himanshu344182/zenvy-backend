const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SECRET_KEY = process.env.JWT_SECRET_KEY || 'your-secret-key-change-in-production';
const ALGORITHM = 'HS256';
const ACCESS_TOKEN_EXPIRE_MINUTES = 1440;

/**
 * Create a JWT access token
 */
function createAccessToken(data) {
  const payload = {
    ...data,
    exp: Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRE_MINUTES * 60
  };
  return jwt.sign(payload, SECRET_KEY, { algorithm: ALGORITHM });
}

/**
 * Express middleware to verify JWT Bearer token.
 * Attaches `req.username` on success.
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Not authenticated' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, SECRET_KEY, { algorithms: [ALGORITHM] });
    const username = payload.sub;
    if (!username) {
      return res.status(401).json({ detail: 'Invalid authentication credentials' });
    }
    req.username = username;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ detail: 'Token has expired' });
    }
    return res.status(401).json({ detail: 'Could not validate credentials' });
  }
}

/**
 * Hash a plaintext password
 */
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(12);
  return bcrypt.hashSync(password, salt);
}

/**
 * Verify a plaintext password against a hash
 */
function verifyPassword(password, hashed) {
  return bcrypt.compareSync(password, hashed);
}

module.exports = {
  createAccessToken,
  verifyToken,
  hashPassword,
  verifyPassword
};
