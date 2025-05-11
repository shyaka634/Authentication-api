const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const User = require('./models/User');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true, // Changed from false to true
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI })
}));

// Redirect to welcome if logged in
function ensureAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
  res.redirect('/signup');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPwd = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPwd });
    await user.save();
    req.session.userId = user._id;
    res.redirect('/welcome');
  } catch (err) {
    console.error(err);
    res.redirect('/signup');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.redirect('/login');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.redirect('/login');
    }
    req.session.userId = user._id;
    res.redirect('/welcome');
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.get('/welcome', ensureAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId).lean();
  res.render('welcome', { user });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));