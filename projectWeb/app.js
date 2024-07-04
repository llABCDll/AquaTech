const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000 // 1hr
}));

// Middleware สำหรับตรวจสอบว่าผู้ใช้ยังไม่ได้ล็อกอิน
const ifNotLoggedIn = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        res.redirect('/login'); // ถ้ายังไม่ได้ล็อกอิน ให้ redirect ไปที่หน้า '/login'
    } else {
        next(); // ถ้าล็อกอินแล้ว ให้ดำเนินการต่อไป
    }
};

const ifLoggedIn = (req, res, next) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/');
    }
    next();
};

app.get('/register', ifLoggedIn, (req, res) => {
    res.render('register');
});

app.get('/login', ifLoggedIn, (req, res) => {
    res.render('login');
});



app.get('/', ifNotLoggedIn, (req, res, next) => {
    dbConnection.query("SELECT email FROM users WHERE id = $1", [req.session.userID])
        .then((result) => {
            if (result.rows.length > 0) {
                res.render('index', {
                    username: result.rows[0].email,
                });
            } else {
                res.status(404).send('User not found');
            }
        })
        .catch(err => {
            console.error('Error fetching user data:', err);
            res.status(500).send('Error fetching user data');
        });
});


app.post('/register', ifLoggedIn, [
    body('user_email', 'Invalid Email Address!').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users WHERE email = $1', [value])
            .then(({ rows }) => {
                if (rows.length > 0) {
                    return Promise.reject('Email already in use!');
                }
            });
    }),
    body('user_name', 'Username is empty!').trim().not().isEmpty(),
    body('user_pass', 'The password must be at least 6 characters long').trim().isLength({ min: 6 }),
], (req, res, next) => {
    const validation_result = validationResult(req);
    const { user_name, user_pass, user_email } = req.body;

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [user_name, user_email, hashedPassword])
                    .then(() => {
                        res.send(`Your account has been created successfully. Now you can <a href="/">Login</a>`);
                    })
                    .catch(err => {
                        console.error('Error inserting user:', err);
                        res.status(500).send('Error creating user');
                    });
            })
            .catch(err => {
                console.error('Error hashing password:', err);
                res.status(500).send('Error hashing password');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);

        res.render('register', {
            register_error: allErrors,
            old_data: req.body
        });
    }
});

app.post('/login', ifLoggedIn, [
    body('user_email').custom((value) => {
        return dbConnection.query("SELECT email FROM users WHERE email = $1", [value])
            .then(({ rows }) => {
                if (rows.length === 1) {
                    return true;
                }
                return Promise.reject('Invalid Email Address!');
            });
    }),
    body('user_pass', 'Password is empty').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, user_email } = req.body;

    if (validation_result.isEmpty()) {
        dbConnection.query("SELECT * FROM users WHERE email = $1", [user_email])
            .then((result) => {
               
                    bcrypt.compare(user_pass, result.rows[0].password)
                        .then(compare_result => {
                            if (compare_result === true) {
                               req.session.isLoggedIn = true;
                                req.session.userID = result.rows[0].id;
                                
                                res.redirect('/');
                            } else {
                                res.render('login', {
                                    login_errors: ['Invalid Password']
                                });
                            }
                        })
                        .catch(err => {
                            console.error('Error comparing passwords:', err);
                            res.status(500).send('Error comparing passwords');
                        });
                
            })
            .catch(err => {
                console.error('Error selecting user:', err);
                res.status(500).send('Error selecting user');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);

        res.render('login', {
            login_errors: allErrors
        });
    }
});

app.post('/logout', (req, res) => {
    req.session = null
    res.redirect('/login')
})
app.listen(3000, () => console.log("Server is running..."));
