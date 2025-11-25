const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userUUID: String,
  userName: String,
  userEmail: String,
  userPassword: String,
  userAuthenticateType: String,
  googleId: String
});

module.exports = mongoose.model('User', userSchema);

