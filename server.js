// COMP3810SEF Group Project - Note Taking App
// Built by combining Lab05–Lab10 patterns

require('dotenv').config();   // Load environment variables from .env

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;   // MongoDB URI from .env
const PORT = process.env.PORT || 8099;         // Port from .env or fallback

// ===== Middleware =====
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Cookie-session (Lab08 style)
app.use(session({
  secret: process.env.SECRETKEY || 'SECRETKEY',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set secure:true only if running HTTPS
}));



// ===== MongoDB Connection (Lab05 style) =====
mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error(err));

// ===== Mongoose Schemas (Lab06–07 style) =====
const userSchema = new mongoose.Schema({
  userUUID: String,
  userName: String,
  userEmail: String,
  userPassword: String,   // hashed password for local login
  userAuthenticateType: String,
  googleId: String
});

const User = mongoose.model('User', userSchema);

const noteSchema = new mongoose.Schema({
  noteUUID: String,
  noteContent: String,
  noteUserUUID: String,
  noteLastModified: { type: Date, default: Date.now }
});
const Note = mongoose.model('Note', noteSchema);

// ===== Passport Google OAuth (Lab10 style) =====
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || "",
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
  callbackURL: "http://localhost:8099/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  let user = await User.findOne({ googleId: profile.id });
  if (!user) {
    user = new User({
      userUUID: profile.id,
      userName: profile.displayName,
      userEmail: profile.emails[0].value,
      userAuthenticateType: "google",
      googleId: profile.id
    });
    await user.save();
  }
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

// ===== Middleware to protect routes =====
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated() || req.session.user) return next();
  res.redirect('/login');
}

// ===== Routes =====

// Login page
app.get('/login', (req, res) => {
  res.render('login');
});

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup');
});

// Local signup
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  let existingUser = await User.findOne({ userEmail: email });
  if (existingUser) {
    return res.send("User already exists. Please login.");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    userUUID: new mongoose.Types.ObjectId().toString(),
    userName: name,
    userEmail: email,
    userPassword: hashedPassword,
    userAuthenticateType: "local"
  });

  await newUser.save();
  res.redirect('/login');
});

// Local login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ userEmail: email });
  if (!user) {
    return res.send("No user found. Please sign up.");
  }

  const match = await bcrypt.compare(password, user.userPassword);
  if (!match) {
    return res.send("Invalid password.");
  }

  // Save user in session
  req.session.user = user;
  res.redirect('/homepage');
});

// Google login
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/homepage',
    failureRedirect: '/login'
  })
);

// Home page with notes
app.get('/homepage', isLoggedIn, async (req, res) => {
  const currentUser = req.user || req.session.user;
  const notes = await Note.find({ noteUserUUID: currentUser.userUUID });
  res.render('homepage', { user: currentUser, notes });
});

// Add note
app.post('/notes', isLoggedIn, async (req, res) => {
  const currentUser = req.user || req.session.user;
  const note = new Note({
    noteUUID: new mongoose.Types.ObjectId().toString(),
    noteContent: req.body.noteContent,
    noteUserUUID: currentUser.userUUID
  });
  await note.save();
  res.redirect('/homepage');
});

// Edit note
app.post('/notes/edit/:id', isLoggedIn, async (req, res) => {
  await Note.findByIdAndUpdate(req.params.id, {
    noteContent: req.body.noteContent,
    noteLastModified: Date.now()
  });
  res.redirect('/homepage');
});

// Delete note
app.get('/notes/delete/:id', isLoggedIn, async (req, res) => {
  await Note.findByIdAndDelete(req.params.id);
  res.redirect('/homepage');
});

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    req.session = null;
    res.redirect('/login');
  });
});

// ===== Start Server =====
app.listen(PORT, () => {
  console.log(`🚀 App running at http://localhost:${PORT}`);
});

