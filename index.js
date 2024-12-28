const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./db');

require('dotenv').config();

const app = express();

app.use('/public', express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', './views');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
    session({
        secret: 'secret',
        resave: false,
        saveUninitialized: true,
    })
);

// Routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedPassword],
        (err) => {
            if (err) throw err;
            res.redirect('/login');
        }
    );
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length === 0 || !(await bcrypt.compare(password, results[0].password))) {
            return res.send('Invalid Email or Password');
        }
        req.session.userId = results[0].id;
        res.redirect('/dashboard');
    });
});

// app.get('/dashboard', (req, res) => {
//     if (!req.session.userId) return res.redirect('/login');
//     res.render('dashboard', { userId: req.session.userId });
// });


app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
      return res.redirect('/login');
    }
  
    // Retrieve user data based on the userId stored in session
    db.query('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, results) => {
      if (err) throw err;
      res.render('dashboard', {
        user: results[0] 
      });
    });
  });
  



app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
