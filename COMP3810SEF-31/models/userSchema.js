const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userUUID: { type: String, required: true },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true, unique: true },
  userPassword: { type: String }, // optional for local auth
  userAuthenticateType: { type: String, enum: ['local', 'google'], required: true },
  googleId: { type: String } // optional for Google auth
});

module.exports = mongoose.model('User', userSchema);
