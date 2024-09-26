const { JWT_SECRET } = require('../secrets');
const jwt = require('jsonwebtoken');
const { findBy } = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({ message: 'Token required' });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: 'Token invalid' });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  }
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedJwt.role_name === role_name) {
    next();
  } else {
    res.status(403).json({ message: 'This is not for you' });
  }
};

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  try {
    const [user] = await findBy({ username });
    if (user) {
      req.user = user;
      next();
    } else {
      next({ message: 'Invalid credentials', status: 401 });
    }
  } catch (err) {
    next(err);
  }
};

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (role_name === undefined || role_name.trim() === '') {
    req.body.role_name = 'student';
    next();
  } else if (role_name.trim() === 'admin') {
    next({ message: 'Role name can not be admin', status: 422 });
  } else if (role_name.trim().length > 32) {
    next({ message: 'Role name can not be longer than 32 chars', status: 422 });
  } else {
    req.body.role_name = role_name.trim();
    next();
  }
};

const buildToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const config = {
    expiresIn: '1d',
  };
  return jwt.sign(payload, JWT_SECRET, config);
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  buildToken,
};
