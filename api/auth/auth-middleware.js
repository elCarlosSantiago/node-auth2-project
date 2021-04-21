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
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  const decodedToken = req.decodedJwt;
  next();
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

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
