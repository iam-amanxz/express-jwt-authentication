require('dotenv').config()
const router = require('express').Router()
const jwt = require('jsonwebtoken')
const requireAuthentication = require('../middleware/requireAuthentication')
const db = require('../db')

const users = db.users

router.post('/register', (req, res) => {
  const { email, password } = req.body

  // check if already registered
  const registered = users.find((user) => user.email === email)
  if (registered) {
    return res.status(400).send({ error: 'Email already registered' })
  }

  // register
  const user = { email, password }
  users.push(user)

  // generate access token
  const accessToken = jwt.sign({ sub: email }, process.env.JWT_ACCESS_SECRET)

  res.status(201).json({ accessToken })
})

router.post('/login', (req, res) => {
  const { email, password } = req.body

  // check if user registered
  const registered = users.find((user) => user.email === email)
  if (!registered) {
    return res.status(302).send({ error: 'Invalid credentials' })
  }

  // check if password is correct
  if (registered.password !== password) {
    return res.status(302).send({ error: 'Invalid credentials' })
  }

  // generate access token
  const accessToken = jwt.sign({ sub: email }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
  })

  res.status(200).json({ accessToken })
})

router.get('/private', requireAuthentication, (req, res) => {
  const { email } = req.user
  res.status(200).json({ message: `You are ${email}` })
})

module.exports = router
