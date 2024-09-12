const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const { timeStamp } = require('console');
const moment = require('moment-timezone');

const currentTimestamp = moment().tz('Asia/Bangkok').format('YYYY-MM-DD HH:mm:ss');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static('public'));


// ใช้ body-parser เพื่อจัดการกับข้อมูล JSON ที่ส่งมาจาก POST
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware สำหรับ JSON
app.use(express.json());

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000 // 1hr
}));

// Middleware สำหรับตรวจสอบว่าผู้ใช้ยังไม่ได้ล็อกอิน
const ifNotLoggedIn = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        res.redirect('/home'); // ถ้ายังไม่ได้ล็อกอิน ให้ redirect ไปที่หน้า '/home'
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

function generateRandomToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 25; i++) { // Token length is 25 characters
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

// register page
app.get('/register', ifLoggedIn, (req, res) => {
    res.render('register');
});

// login page
app.get('/login', ifLoggedIn, (req, res) => {
    res.render('login');
});

// logout back to home page
app.post('/logout', (req, res) => {
    req.session = null
    res.redirect('/home')
})

// home page
app.get('/home', ifLoggedIn, (req, res) => {
    res.render('home');
});

// forgot password page
app.get('/forgotpass', ifLoggedIn, (req, res) => {
    res.render('forgotpass');
});

// ดึง token จาก URL และส่งไป EJS
app.get('/resetpass', (req, res) => {
    const token = req.query.token; // หรือวิธีที่คุณส่ง token เข้ามา
    if (token) {
        res.render('resetpass', { token });
    } else {
        res.status(400).send('Token is missing');
    }
});

app.get('/', ifNotLoggedIn, (req, res, next) => {
    dbConnection.query("SELECT email FROM users_iptcn WHERE id = $1", [req.session.userID])
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
        return dbConnection.query('SELECT email FROM users_iptcn WHERE email = $1', [value])
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
                dbConnection.query("INSERT INTO users_iptcn (username, email, password) VALUES ($1, $2, $3)", [user_name, user_email, hashedPassword])
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
        return dbConnection.query("SELECT email FROM users_iptcn WHERE email = $1", [value])
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
        dbConnection.query("SELECT * FROM users_iptcn WHERE email = $1", [user_email])
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
        "INSERT INTO createbtn (nameboard, email, token, temp_default, timestamp) VALUES ($1, $2, $3, $4, NOW())",
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

// เส้นทางสำหรับอัพเดตชื่อบอร์ด
app.post('/updateName', (req, res) => {
    const { token, name } = req.body;

    if (!token || !name) {
        return res.status(400).send('Both token and name are required');
    }

    const query = `UPDATE createbtn SET nameboard = $1 WHERE token = $2`;

    dbConnection.query(query, [name, token])
        .then(() => {
            res.send('Name updated successfully!');
        })
        .catch(err => {
            console.error('Error updating name:', err);
            res.status(500).send('Failed to update name');
        });
});


// เส้นทางสำหรับอัพเดตค่า temp_default
app.post('/updateTempDefault', (req, res) => {
    const { token, temp_min, temp_max } = req.body;

    if (!temp_min || !temp_max) {
        return res.status(400).send('Both temp_min and temp_max are required');
    }

    // สร้างวัตถุ JSON สำหรับ temp_default
    const temp_default = {
        min: temp_min,
        max: temp_max
    };

    const query = `UPDATE createbtn SET temp_default = $1 WHERE token = $2`;

    dbConnection.query(query, [temp_default, token])
        .then(() => {
            res.status(200).send('Temperature default updated successfully');
        })
        .catch(err => {
            console.error('Error updating temp_default:', err);
            res.status(500).send('Failed to update temperature default');
        });
});

// updateTemp
app.post('/updateTemp', (req, res) => {
    const { token, temp } = req.body;

    console.log(req.body);

    // Update the new_temp column in the 'createbtn' table
    dbConnection.query('UPDATE createbtn SET new_temp = $1 WHERE token = $2', [temp, token])
        .then(() => {
            // Fetch the updated data and order by id
            return dbConnection.query('SELECT * FROM createbtn ORDER BY id ASC');
        })
        .then(result => {
            // ส่งข้อมูลที่อัพเดตกลับไปยังหน้าเว็บหรือทำสิ่งที่ต้องการ
            res.status(200).json(result.rows);
        })
        .catch(err => {
            console.error('Error updating temperature:', err);
            res.status(500).send('Failed to update temperature');
        });
});

// ESP32 จะดึงค่าจาก endpoint นี้เพื่อนำ temp ไปปรับใช้
app.get('/getNewTemp', (req, res) => {
    const { token } = req.query;

    dbConnection.query('SELECT new_temp FROM createbtn WHERE token = $1', [token])
        .then(result => {
            if (result.rows.length > 0) {
                res.status(200).json({ temp: result.rows[0].new_temp });
            } else {
                res.status(404).send('Token not found');
            }
        })
        .catch(err => {
            console.error('Error fetching new temperature:', err);
            res.status(500).send('Failed to fetch new temperature');
        });
});

// dashboard
app.get('/dashboard', ifLoggedIn, (req, res) => {
    const user_email = req.session.user.email;

    dbConnection.query('SELECT id, nameboard, email, token, temp, ph FROM createbtn WHERE email = $1 ORDER BY ABS(`id`) ASC', [user_email])
        .then(({ rows }) => {
            console.log(rows);  // ตรวจสอบผลลัพธ์ที่ได้รับ
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
    console.log(req.body);
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

// forgot password 
app.post('/forgotpass', ifLoggedIn, [
    body('user_email', 'ที่อยู่อีเมลไม่ถูกต้อง!').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users_iptcn WHERE email = $1', [value])
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
        // สร้าง token และจัดเก็บในฐานข้อมูล
        const token = generateRandomToken(); // สร้าง token

        dbConnection.query('UPDATE users_iptcn SET reset_token = $1 WHERE email = $2', [token, user_email])
            .then(() => {
                // ส่งอีเมลที่มีลิงก์รีเซ็ตรหัสผ่านให้กับผู้ใช้
                // ตัวอย่าง: /resetpass?token=your_generated_token
                res.render('resetpass', { email: user_email, token: token });
            })
            .catch(err => {
                console.error('ข้อผิดพลาดในการอัปเดต token:', err);
                res.status(500).send('ข้อผิดพลาดในการอัปเดต token');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);
        res.render('forgotpass', {
            forgotpass_error: allErrors
        });
    }
});

// set new password 
app.post('/resetpass', [
    body('user_pass', 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร').trim().isLength({ min: 6 })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, token } = req.body;

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("UPDATE users_iptcn SET password = $1 WHERE reset_token = $2", [hashedPassword, token])
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
            token: token // ส่ง token กลับไปให้หน้า EJS อีกครั้ง
        });
    }
});

// API สำหรับดึงข้อมูล token
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

// api บันทึกค่า temp, ph และ เก็บข้อมูลทุกๆ 1 ชม.
app.post('/api/data', (req, res) => {
    const { token, temp, ph } = req.body;

    console.log(req.body); // ตรวจสอบข้อมูลที่รับมา

    // ตรวจสอบว่าข้อมูลครบถ้วนหรือไม่
    if (!token || temp === undefined || ph === undefined) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // กำหนด timestamp ปัจจุบันในเขตเวลาที่ต้องการ (เช่น Asia/Bangkok)
    const currentTimestamp = moment().tz('Asia/Bangkok').format('YYYY-MM-DD HH:mm:ss');

    dbConnection.query('SELECT id FROM createbtn WHERE token = $1', [token])
        .then(result => {
            if (result.rows.length > 0) {
                const boardId = result.rows[0].id;

                // อัปเดต temp และ ph ใน createbtn
                const updateCreateBtnQuery = dbConnection.query(
                    'UPDATE createbtn SET temp = $1, ph = $2, timestamp = NOW() WHERE id = $3',
                    [temp, ph, boardId]
                );

                // ตรวจสอบข้อมูลล่าสุดที่บันทึกใน sensor_data ว่าผ่านไปแล้ว 1 ชั่วโมงหรือไม่
                const checkLastInsertQuery = dbConnection.query(
                    `SELECT timestamp FROM sensor_data 
                     WHERE token = $1 
                     ORDER BY timestamp DESC LIMIT 1`,
                    [token]
                );

                return Promise.all([updateCreateBtnQuery, checkLastInsertQuery]);
            } else {
                return Promise.reject({ status: 400, message: 'Invalid token' });
            }
        })
        .then(results => {
            const lastInsertTimestamp = results[1].rows[0]?.timestamp;
            const currentMoment = moment(currentTimestamp);

            // ถ้าไม่มีข้อมูลล่าสุด หรือข้อมูลล่าสุดเกินกว่า 1 ชั่วโมงแล้ว
            if (!lastInsertTimestamp || currentMoment.diff(moment(lastInsertTimestamp), 'hours') >= 1) {
                // แทรกข้อมูลลงใน sensor_data
                return dbConnection.query(
                    'INSERT INTO sensor_data (temp, ph, token, timestamp) VALUES ($1, $2, $3, $4)',
                    [temp, ph, token, currentTimestamp]
                );
            } else {
                return Promise.resolve(); // ถ้าไม่ถึง 1 ชั่วโมง ไม่ต้องแทรกข้อมูลใหม่
            }
        })
        .then(() => {
            res.status(200).send('Data updated successfully, sensor data recorded if passed 1 hour');
        })
        .catch(err => {
            if (err.status) {
                res.status(err.status).send(err.message);
            } else {
                console.error('Error executing query', err.stack);
                res.status(500).send('Error updating or inserting data');
            }
        });
});

// api บันทึกค่า temp, ph เก็บข้อมูลทุกๆ 1 ชม.
app.post('/api/savedata', (req, res) => {
    const { token, temp, ph, email } = req.body;

    console.log(req.body);

    // ตรวจสอบว่าข้อมูลครบถ้วนหรือไม่
    if (!token || temp === undefined || ph === undefined || !email) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // กำหนดเวลาในเขตเวลาที่ต้องการ (เช่น Asia/Bangkok)
    const currentTimestamp = moment().tz('Asia/Bangkok').format('YYYY-MM-DD HH:mm:ss');

    // ตรวจสอบ token และ email และแทรกข้อมูลใหม่พร้อม timestamp จากเซิร์ฟเวอร์
    dbConnection.query('SELECT id FROM createbtn WHERE token = $1 AND email = $2', [token, email])
        .then(result => {
            if (result.rows.length > 0) {
                const boardId = result.rows[0].id;
                return dbConnection.query(
                    'INSERT INTO sensor_data (temp, ph, email, token, timestamp) VALUES ($1, $2, $3, $4, $5)',
                    [temp, ph, email, token, currentTimestamp]
                );
            } else {
                return Promise.reject({ status: 400, message: 'Invalid token or email' });
            }
        })
        .then(() => {
            res.status(200).send('Data inserted successfully');
        })
        .catch(err => {
            if (err.status) {
                res.status(err.status).send(err.message);
            } else {
                console.error('Error executing query', err.stack);
                res.status(500).send('Error inserting data');
            }
        });
});

// แสดงกราฟและตาราง
app.get('/getHourlyData', async (req, res) => {
    const { token } = req.query; // รับค่า token จาก query parameter
    const yesterdayStart = moment().tz('Asia/Bangkok').subtract(1, 'days').startOf('day').format('YYYY-MM-DD HH:mm:ss'); // 00:00 ของวันก่อนหน้า
    const yesterdayEnd = moment().tz('Asia/Bangkok').subtract(1, 'days').endOf('day').format('YYYY-MM-DD HH:mm:ss'); // 23:59 ของวันก่อนหน้า

    try {
        const result = await dbConnection.query(`
            SELECT TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok' AS timestamp, temp, ph 
            FROM sensor_data 
            WHERE token = $1
            AND TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' BETWEEN $2::timestamp AND $3::timestamp
            ORDER BY TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' ASC
        `, [token, yesterdayStart, yesterdayEnd]);

        res.json(result.rows); // ส่งผลลัพธ์กลับในรูปแบบ JSON
    } catch (error) {
        console.error('Error fetching hourly data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});