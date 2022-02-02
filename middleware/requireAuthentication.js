require('dotenv').config()
const jwt = require('jsonwebtoken')
const db = require('../db')

const users = db.users

function requireAuthentication(req, res, next) {
  // get headers
  const authorizationHeader = req.headers.authorization

  // check if authorization header is present
  if (!authorizationHeader) {
    return res.status(401).send({ error: 'Unauthorized' })
  }

  // get token from authorization header
  const token = authorizationHeader.split(' ')[1]

  // check if token is present
  if (!token) {
    return res.status(401).send({ error: 'Unauthorized' })
  }

  try {
    // verify token
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET)

    // attach user to the request
    const user = users.find((user) => user.email === payload.sub)
    delete user.password
    req.user = user

    next()
  } catch (error) {
    res.status(401).send({ error: 'Unauthorized' })
  }
}

module.exports = requireAuthentication
