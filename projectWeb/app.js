const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const transporter = require('./nodemailerConfig'); // ใช้ Nodemailer

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
        res.redirect('/home'); // ถ้ายังไม่ได้ล็อกอิน ให้ redirect ไปที่หน้า '/login'
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

// register page
app.get('/register', ifLoggedIn, (req, res) => {
    res.render('register');
});

// login page
app.get('/login', ifLoggedIn, (req, res) => {
    res.render('login');
});

// home page
app.get('/home', ifLoggedIn, (req, res) => {
    res.render('home');
});

// forgot password page
app.get('/forgotpass', ifLoggedIn, (req, res) => {
    res.render('forgotpass');
});

// logout back to home page
app.post('/logout', (req, res) => {
    req.session = null
    res.redirect('/home')
})


app.get('/', ifNotLoggedIn, (req, res, next) => {
    dbConnection.query("SELECT email FROM users WHERE id = $1", [req.session.userID])
        .then((result) => {
            if (result.rows.length > 0) {
                const userEmail = result.rows[0].email;
                dbConnection.query("SELECT * FROM createbtn WHERE email = $1", [userEmail])
                    .then((boardsResult) => {
                        res.render('index', {
                            username: userEmail,
                            boards: boardsResult.rows
                        });
                    })
                    .catch(err => {
                        console.error('Error fetching boards:', err);
                        res.render('index', {
                            username: userEmail,
                            boards: []
                        });
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

// register
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

// login
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

// createbtn
app.post('/createboard', ifNotLoggedIn, (req, res) => {
    const { nameboard, user_email, token } = req.body;
    dbConnection.query(
        "INSERT INTO createbtn (nameboard, email, token) VALUES ($1, $2, $3)",
        [nameboard, user_email, token]
    )
    .then(() => {
        res.redirect('/');
    })
    .catch(err => {
        console.error('Error inserting board:', err);
        res.status(500).send('Error creating board');
    });
});

// deleteboard
app.post('/deleteboard', ifNotLoggedIn, (req, res) => {
    const { board_id } = req.body;
    dbConnection.query(
        "DELETE FROM createbtn WHERE id = $1", [board_id]
    )
    .then(() => {
        res.redirect('/');
    })
    .catch(err => {
        console.error('Error deleting board:', err);
        res.status(500).send('Error deleting board');
    });
});

// Route สำหรับแสดงรายละเอียดของบอร์ด
app.get('/board/:id', ifNotLoggedIn, (req, res) => {
    const boardId = req.params.id;
    dbConnection.query("SELECT * FROM createbtn WHERE id = $1", [boardId])
        .then((result) => {
            if (result.rows.length > 0) {
                res.render('boardDetails', {
                    board: result.rows[0],
                });
            } else {
                res.status(404).send('Board not found');
            }
        })
        .catch(err => {
            console.error('Error fetching board details:', err);
            res.status(500).send('Error fetching board details');
        });
});

// forgotpassword
app.post('/forgotpass', ifLoggedIn, [
    body('user_email', 'Invalid Email Address!').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users WHERE email = $1', [value])
            .then(({ rows }) => {
                if (rows.length === 0) {
                    return Promise.reject('Email not found!');
                }
            });
    })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_email } = req.body;

    if (validation_result.isEmpty()) {
        const token = crypto.randomBytes(20).toString('hex');
        const resetPasswordUrl = `http://localhost:3000/resetpass/${token}`;

        // อัปเดต token ในฐานข้อมูล
        dbConnection.query("UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3", [token, Date.now() + 3600000, user_email])
            .then(() => {
                // ส่งอีเมลรีเซ็ตรหัสผ่าน
                const mailOptions = {
                    to: user_email,
                    from: 'admin@gmail.com',
                    subject: 'Password Reset',
                    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                    Please click on the following link, or paste this into your browser to complete the process:\n\n
                    ${resetPasswordUrl}\n\n
                    If you did not request this, please ignore this email and your password will remain unchanged.\n`
                };

                transporter.sendMail(mailOptions, (err, response) => {
                    if (err) {
                        console.error('Error sending email:', err);
                        res.status(500).send('Error sending email');
                    } else {
                        res.send('Password reset instructions have been sent to your email.');
                    }
                });
            })
            .catch(err => {
                console.error('Error updating reset token:', err);
                res.status(500).send('Error updating reset token');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);
        res.render('forgotpass', {
            forgotpass_error: allErrors
        });
    }
});

// reset password
app.get('/resetpass/:token', (req, res) => {
    const token = req.params.token;
    dbConnection.query("SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > $2", [token, Date.now()])
        .then(({ rows }) => {
            if (rows.length > 0) {
                res.render('resetpass', { token });
            } else {
                res.send('Password reset token is invalid or has expired.');
            }
        })
        .catch(err => {
            console.error('Error verifying reset token:', err);
            res.status(500).send('Error verifying reset token');
        });
});

// set New password
app.post('/resetpass/:token', [
    body('user_pass', 'The password must be at least 6 characters long').trim().isLength({ min: 6 })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass } = req.body;
    const token = req.params.token;

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2", [hashedPassword, token])
                    .then(() => {
                        res.send('Your password has been updated successfully. Now you can <a href="/login">Login</a>');
                    })
                    .catch(err => {
                        console.error('Error updating password:', err);
                        res.status(500).send('Error updating password');
                    });
            })
            .catch(err => {
                console.error('Error hashing password:', err);
                res.status(500).send('Error hashing password');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);
        res.render('resetpass', {
            resetpass_error: allErrors,
            token
        });
    }
});


app.listen(3000, () => console.log("Server is running..."));
