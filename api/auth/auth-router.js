const router = require('express').Router();
const {
  checkUsernameExists,
  validateRoleName,
  buildToken,
} = require('./auth-middleware');
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

router.post('/register', validateRoleName, async (req, res, next) => {
  try {
    let user = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 10;
    const hash = bcrypt.hashSync(user.password, rounds);
    user.password = hash;
    const newUser = await Users.add(user);
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

router.post('/login', checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  const user = req.user;
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = buildToken(user);
    res.json({ message: `${user.username} is back!`, token });
  } else {
    res.status(401).json({ message: 'Invalid Credentials' });
  }
});

module.exports = router;
