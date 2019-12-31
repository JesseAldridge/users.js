const fs = require('fs');
const child_process = require('child_process');
const path = require('path');

const bcrypt = require('bcrypt');
const expand_home_dir = require('expand-home-dir');
const shell = require('shelljs');

const config = require('./config');

let email_to_user = {}
if(fs.existsSync(config.USERS_PATH)) {
  const users_json = fs.readFileSync(config.USERS_PATH, 'utf8')
  email_to_user = JSON.parse(users_json)
}

function get_user(email) {
  return email_to_user[sanitize(email)]
}

function read_user_file(req, name) {
  const username = sanitize(req.session.email)
  const private_path = path.join(config.DATA_DIR_PATH, username, name)
  return fs.readFileSync(private_path, 'utf8')
}

function sanitize(filename) {
  // http://gavinmiller.io/2016/creating-a-secure-sanitization-function/
  // Bad as defined by wikipedia: https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
  // Also have to escape the backslash

  // TODO: test this more

  if(!filename)
    return null
  const bad_chars = [ '/', /\\/, /\?/, '%', /\*/, ':', /\|/, '"', '<', '>', /\./, ' ' ]
  for(let bad_char of bad_chars)
    filename = filename.replace(new RegExp(bad_char, 'g'), '_')
  return filename
}

function signup_post(req, res) {
  // Validate email
  const email = req.body.email.toLowerCase()
  if(!email.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}/)) {
    res.statusCode = 400
    res.end('invalid email')
    return
  }

  // Do log-in instead if user already signed up
  if(get_user(email)) {
    login_post(req, res)
    return
  }

  // Create new user with salted, hashed password. Save to config.USERS_PATH json file.
  const saltRounds = 10;
  bcrypt.genSalt(saltRounds, function(err, salt) {
    bcrypt.hash(req.body.password, salt, function(err, password_hash) {
      const user_id = Math.round(Math.random() * Math.pow(10, 10))
      const user = {
        email: email,
        username: sanitize(email),
        salt: salt,
        password_hash: password_hash,
        user_id: user_id,
      }
      email_to_user[user.username] = user
      if(!fs.existsSync(config.DATA_DIR_PATH))
        shell.mkdir('-p', config.DATA_DIR_PATH)
      const users_json = JSON.stringify(email_to_user, null, 2)
      fs.writeFileSync(config.USERS_PATH, users_json, 'utf8')

      const user_dir = path.join(config.DATA_DIR_PATH, user.username)
      shell.mkdir('-p', user_dir)

      req.session.auth_token = Math.random()
      req.session.email  = email
      res.writeHead(302, {'Location': `/app`})
      res.end()
    });
  });
}


function login_post(req, res) {
  // Lookup the user; error if not found.
  const user = get_user(req.body.email)
  if(!user) {
    res.statusCode = 401
    res.end('user not found')
    return
  }

  // If password matches, create a random auth token in cookie session.
  bcrypt.compare(req.body.password, user.password_hash, function(err, is_match) {
    if(is_match) {
      req.session.auth_token = Math.random()
      req.session.email = req.body.email.toLowerCase()
      res.writeHead(302, {'Location': `/app`})
      res.end()
    }
    else {
      res.statusCode = 401
      res.end('wrong password')
    }
  });
}

function auth_check(req, res) {
  const auth_token = req.session.auth_token
  const user = get_user(req.session.email)
  if(!auth_token || !user || auth_token != req.session.auth_token) {
    res.writeHead(302, {'Location': `/sign-up`})
    res.end()
    return false
  }
  return true
}

if(typeof exports != 'undefined') {
  exports.login_post = login_post
  exports.signup_post = signup_post
  exports.auth_check = auth_check
  exports.read_user_file = read_user_file
}
