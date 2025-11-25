// ===== Environment Variables ===== (AI generated: added dotenv for config management)
require('dotenv').config();

const express = require('express');              // Lab06: HTTP server with Express
const mongoose = require('mongoose');            // Lab05: Connect to MongoDB via Node.js driver
const bodyParser = require('body-parser');       // Lab06: Handle GET/POST requests
const session = require('express-session');      // Lab08: Express middleware (session)
const passport = require('passport');            // Lab10: OAuth with Passport
const GoogleStrategy = require('passport-google-oauth20').Strategy; // Lab10: Google OAuth strategy
const path = require('path');
const bcrypt = require('bcryptjs');              // Lab07: Mongoose + bcrypt for password hashing
const fetch = require('node-fetch');             // Lab08: Background image fetch (RESTful service)

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;
const PORT = process.env.PORT || 8099;

// ===== Views & static ===== (Lab07: Express + EJS templating)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ===== Sessions ===== (Lab08: Cookie/session middleware)
app.use(session({
  secret: process.env.SECRETKEY || 'SECRETKEY',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// ===== MongoDB ===== (Lab05: MongoDB driver connection)
mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ===== Models ===== (Lab07: Mongoose schema/models)
const User = require('./models/User');
const Note = require('./models/Note');

// ===== Google OAuth ===== (Lab10: Passport OAuth strategy)
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || "",
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:8099/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
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
  } catch (err) {
    return done(err, null);
  }
}));

// ===== Passport session handling ===== (Lab10: serialize/deserialize user)
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

app.use(passport.initialize());
app.use(passport.session());

// ===== Auth guard ===== (Lab10: Middleware isLoggedIn)
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated() || req.session.user) return next();
  res.redirect('/login');
}

// ===== Routes =====
// Login & Signup pages (Lab06: GET/POST services)
app.get('/login', (req, res) => res.render('login', { title: 'Login' }));
app.get('/signup', (req, res) => res.render('signup', { title: 'Sign up' }));

// Signup (Lab07: bcrypt password hashing + MongoDB insert)
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let existingUser = await User.findOne({ userEmail: email });
    if (existingUser) return res.send("User already exists. Please login.");

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
  } catch (err) {
    res.status(500).send("Signup failed.");
  }
});

// Login (Lab06: POST request handling)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ userEmail: email });
    if (!user) return res.send("No user found. Please sign up.");

    const match = await bcrypt.compare(password, user.userPassword);
    if (!match) return res.send("Invalid password.");

    req.session.user = user;
    res.redirect('/homepage');
  } catch (err) {
    res.status(500).send("Login failed.");
  }
});

// Google login (Lab10: OAuth strategy)
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { successRedirect: '/homepage', failureRedirect: '/login' })
);

// Homepage (Lab07: EJS rendering with MongoDB data)
app.get('/homepage', isLoggedIn, async (req, res) => {
  const currentUser = req.user || req.session.user;
  const notes = await Note.find({ noteUserUUID: currentUser.userUUID });
  res.render('homepage', { title: 'Homepage', user: currentUser, notes });
});

// Notes CRUD (Lab09: RESTful CRUD services adapted to notes)
app.post('/notes', isLoggedIn, async (req, res) => {
  try {
    const currentUser = req.user || req.session.user;
    const note = new Note({
      noteUUID: new mongoose.Types.ObjectId().toString(),
      noteContent: req.body.noteContent,
      noteUserUUID: currentUser.userUUID
    });
    await note.save();
    res.redirect('/homepage');
  } catch (err) {
    res.status(500).send("Failed to add note.");
  }
});

app.post('/notes/edit/:id', isLoggedIn, async (req, res) => {
  try {
    await Note.findByIdAndUpdate(req.params.id, {
      noteContent: req.body.noteContent,
      noteLastModified: Date.now()
    });
    res.redirect('/homepage');
  } catch (err) {
    res.status(500).send("Failed to edit note.");
  }
});

app.get('/notes/delete/:id', isLoggedIn, async (req, res) => {
  try {
    await Note.findByIdAndDelete(req.params.id);
    res.redirect('/homepage');
  } catch (err) {
    res.status(500).send("Failed to delete note.");
  }
});

// Logout (Lab10: session clear)
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session = null;
    res.redirect('/login');
  });
});

// Root route (Lab06: GET redirect)
app.get('/', (req, res) => {
  if (req.isAuthenticated() || req.session.user) {
    res.redirect('/homepage');
  } else {
    res.redirect('/login');
  }
});

// Background route (Lab08: RESTful service returning JSON, AI generated adaptation for Unsplash)
app.get('/background', async (req, res) => {
  try {
    if (!process.env.UNSPLASH_API_KEY) {
      return res.json({ imageUrl: '/images/default-bg.jpg' });
    }
    const response = await fetch(`https://api.unsplash.com/photos/random?query=landscape&client_id=${process.env.UNSPLASH_API_KEY}`);
    const data = await response.json();
    res.json({ imageUrl: data.urls.full });
  } catch (err) {
    res.json({ imageUrl: '/images/default-bg.jpg' });
  }
});

// ===== Start ===== (Lab06: HTTP server listen)
app.listen(PORT, () => console.log(`🚀 App running at http://localhost:${PORT}`));
