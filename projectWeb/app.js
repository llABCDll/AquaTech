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
    const { nameboard, user_email, token, temp_min, temp_max } = req.body;
    const temp_default = JSON.stringify({ min: temp_min, max: temp_max });

    console.log('Request Body:', req.body);

    dbConnection.query(
        "INSERT INTO createbtn (nameboard, email, token, temp_default) VALUES ($1, $2, $3, $4)",
        [nameboard, user_email, token, temp_default]
    )
    .then(() => {
        res.redirect('/');
    })
    .catch(err => {
        console.error('Error inserting board:', err);
        res.status(500).send('Error creating board');
    });
});

// tempbtn
app.post('/updateTemp', (req, res) => {
    const { token, temp } = req.body;

    dbConnection.query('UPDATE boards SET temp = $1 WHERE token = $2', [temp, token])
        .then(() => {
            res.status(200).send('Temperature updated');
        })
        .catch(err => {
            console.error('Error updating temperature:', err);
            res.status(500).send('Failed to update temperature');
        });
});

//dashboard
app.get('/dashboard', ifLoggedIn, (req, res) => {
    const user_email = req.session.user.email;

    dbConnection.query('SELECT id, nameboard, email, token, temp, ph FROM boards WHERE email = $1', [user_email])
        .then(({ rows }) => {
            res.render('dashboard', {
                username: req.session.user.username,
                boards: rows
            });
        })
        .catch(err => {
            console.error('Error fetching boards:', err);
            res.status(500).send('Error fetching boards');
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
    body('user_email', 'ที่อยู่อีเมลไม่ถูกต้อง!').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users WHERE email = $1', [value])
            .then(({ rows }) => {
                if (rows.length === 0) {
                    return Promise.reject('ไม่พบอีเมล!');
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
                    subject: 'รีเซ็ตรหัสผ่าน',
                    text: `คุณได้รับอีเมลนี้เพราะคุณ (หรือคนอื่น) ได้ขอรีเซ็ตรหัสผ่านของบัญชีของคุณ\n\n
                    โปรดคลิกลิงก์ต่อไปนี้ หรือวางลิงก์นี้ในเบราว์เซอร์ของคุณเพื่อดำเนินการให้เสร็จสมบูรณ์:\n\n
                    ${resetPasswordUrl}\n\n
                    หากคุณไม่ได้ขอสิ่งนี้ โปรดละเว้นอีเมลนี้ และรหัสผ่านของคุณจะยังคงไม่เปลี่ยนแปลง\n`
                };

                transporter.sendMail(mailOptions, (err, response) => {
                    if (err) {
                        console.error('ข้อผิดพลาดในการส่งอีเมล:', err);
                        res.status(500).send('ข้อผิดพลาดในการส่งอีเมล');
                    } else {
                        res.send('คำแนะนำการรีเซ็ตรหัสผ่านได้ถูกส่งไปยังอีเมลของคุณแล้ว');
                    }
                });
            })
            .catch(err => {
                console.error('ข้อผิดพลาดในการอัปเดตโทเค็น:', err);
                res.status(500).send('ข้อผิดพลาดในการอัปเดตโทเค็น');
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
                res.send('โทเค็นการรีเซ็ตรหัสผ่านไม่ถูกต้องหรือหมดอายุแล้ว');
            }
        })
        .catch(err => {
            console.error('ข้อผิดพลาดในการยืนยันโทเค็น:', err);
            res.status(500).send('ข้อผิดพลาดในการยืนยันโทเค็น');
        });
});

// set New password
app.post('/resetpass/:token', [
    body('user_pass', 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร').trim().isLength({ min: 6 })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass } = req.body;
    const token = req.params.token;

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2", [hashedPassword, token])
                    .then(() => {
                        res.send('รหัสผ่านของคุณได้รับการอัปเดตเรียบร้อยแล้ว คุณสามารถ <a href="/login">เข้าสู่ระบบ</a> ได้แล้ว');
                    })
                    .catch(err => {
                        console.error('ข้อผิดพลาดในการอัปเดตรหัสผ่าน:', err);
                        res.status(500).send('ข้อผิดพลาดในการอัปเดตรหัสผ่าน');
                    });
            })
            .catch(err => {
                console.error('ข้อผิดพลาดในการแฮชรหัสผ่าน:', err);
                res.status(500).send('ข้อผิดพลาดในการแฮชรหัสผ่าน');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);
        res.render('resetpass', {
            resetpass_error: allErrors,
            token
        });
    }
});

// สร้าง API สำหรับดึงข้อมูล token
app.get('/api/token/:boardId', (req, res) => {
    const boardId = req.params.boardId;

    pool.query('SELECT token FROM createbtn WHERE id = $1', [boardId])
        .then(result => {
            if (result.rows.length > 0) {
                res.json({ token: result.rows[0].token });
            } else {
                res.status(404).send('Board not found');
            }
        })
        .catch(err => {
            console.error('Error executing query', err.stack);
            res.status(500).send('Error retrieving token');
        });
});

// API สำหรับรับและบันทึกข้อมูลจาก ESP32
app.post('/api/data', (req, res) => {
    const { token, temperature, ph } = req.body;

    // ตรวจสอบ token ว่าถูกต้องหรือไม่
    pool.query('SELECT id FROM createbtn WHERE token = $1', [token])
        .then(result => {
            if (result.rows.length > 0) {
                const boardId = result.rows[0].id;
                // บันทึกข้อมูลลงในฐานข้อมูล
                return pool.query(
                    'INSERT INTO sensor_data (board_id, temperature, ph, timestamp) VALUES ($1, $2, $3, NOW())',
                    [boardId, temperature, ph]
                );
            } else {
                res.status(400).send('Invalid token');
            }
        })
        .then(() => {
            res.send('Data saved successfully');
        })
        .catch(err => {
            console.error('Error executing query', err.stack);
            res.status(500).send('Error saving data');
        });
});

// เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});