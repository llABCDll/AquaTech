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

const port = 8080;

const app = express();
app.use(express.urlencoded({ extended: false }));

const WebSocket = require('ws');
const http = require('http');
const { name } = require('ejs');

// สร้าง HTTP server จาก Express
const server = http.createServer(app);

// สร้าง WebSocket Server
const wss = new WebSocket.Server({ server }); // เชื่อมต่อกับเซิร์ฟเวอร์ Express

// เมื่อมีการเชื่อมต่อใหม่
wss.on('connection', (ws) => {
    console.log('Client connected');

    // ส่งข้อมูล sensor-data ไปยัง client
    setInterval(() => {
        dbConnection.query("SELECT token, temp, ph FROM createbtn")
            .then((result) => {
                // ส่งข้อมูลเซ็นเซอร์ไปยัง client
                ws.send(JSON.stringify(result.rows));
            })
            .catch((err) => {
                console.error('เกิดข้อผิดพลาดในการดึงข้อมูลเซ็นเซอร์:', err);
            });
    }, 3000); // อัปเดตทุก ๆ 3 วินาที

    // จัดการการเชื่อมต่อขาด
    ws.on('close', () => {
        console.log('Client disconnected');
    });
});

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
        res.status(400).send('ไม่พบ Token');
    }
});

app.get('/', ifNotLoggedIn, (req, res, next) => {
    dbConnection.query("SELECT email, username FROM users_iptcn WHERE id = $1", [req.session.userID])
        .then((result) => {
            if (result.rows.length > 0) {
                const userName = result.rows[0].username;
                const userEmail = result.rows[0].email;
                dbConnection.query("SELECT * FROM createbtn WHERE email = $1", [userEmail])
                    .then((boardsResult) => {
                        res.render('index', {
                            username: userEmail,
                            user : userName || null,
                            boards: boardsResult.rows
                        });
                    })
                    .catch(err => {
                        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลบอร์ด:', err);
                        res.render('index', {
                            username: userEmail,
                            user: userName || null,
                            boards: []
                        });
                    });
            } else {
                res.status(404).send('ไม่พบผู้ใช้');
            }
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้');
        });
});

// register
app.post('/register', ifLoggedIn, [
    body('user_email', 'อีเมลไม่ถูกต้อง!').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users_iptcn WHERE email = $1', [value])
            .then(({ rows }) => {
                if (rows.length > 0) {
                    return Promise.reject('อีเมลนี้ถูกใช้งานแล้ว!');
                }
            });
    }),
    body('user_name', 'ชื่อผู้ใช้ว่างเปล่า!').trim().not().isEmpty(),
    body('user_pass', 'รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร').trim().isLength({ min: 6 }),
], (req, res, next) => {
    const validation_result = validationResult(req);
    const { user_name, user_pass, user_email } = req.body;

    if (!user_name || !user_pass || !user_email) {
        return res.render('register', {
            register_error: ['กรุณากรอกข้อมูลให้ครบถ้วน'],
            old_data: req.body
        });
    }

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("INSERT INTO users_iptcn (username, email, password) VALUES ($1, $2, $3)", [user_name, user_email, hashedPassword])
                    .then(() => {
                        res.render('login', {
                            success_message: 'สมัครสำเร็จแล้ว',
                            showPopup: true
                        });
                    })
                    .catch(err => {
                        console.error('เกิดข้อผิดพลาดในการสร้างผู้ใช้:', err);
                        res.status(500).send('เกิดข้อผิดพลาดในการสร้างผู้ใช้');
                    });
            })
            .catch(err => {
                console.error('เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน:', err);
                res.status(500).send('เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน');
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
                return Promise.reject('อีเมลไม่ถูกต้อง!');
            });
    }),
    body('user_pass', 'รหัสผ่านว่างเปล่า').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, user_email } = req.body;

    if (!user_email || !user_pass) {
        return res.render('login', {
            login_errors: ['กรุณากรอกข้อมูลให้ครบถ้วน']
        });
    }

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
                                login_errors: ['รหัสผ่านไม่ถูกต้อง']
                            });
                        }
                    })
                    .catch(err => {
                        console.error('เกิดข้อผิดพลาดในการเปรียบเทียบรหัสผ่าน:', err);
                        res.status(500).send('เกิดข้อผิดพลาดในการเปรียบเทียบรหัสผ่าน');
                    });

            })
            .catch(err => {
                console.error('เกิดข้อผิดพลาดในการเลือกผู้ใช้:', err);
                res.status(500).send('เกิดข้อผิดพลาดในการเลือกผู้ใช้');
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
    const { nameboard, user_email, token} = req.body;

    console.log('Request Body:', req.body);

    dbConnection.query(
        "INSERT INTO createbtn (nameboard, email, token) VALUES ($1, $2, $3)",
        [nameboard, user_email, token]
    )
        .then(() => {
            res.redirect('/');
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการสร้างบอร์ด:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการสร้างบอร์ด');
        });
});

// เส้นทางสำหรับอัพเดตชื่อบอร์ด
app.post('/updateName', (req, res) => {
    const { token, name } = req.body;

    if (!token || !name) {
        return res.status(400).send('ต้องระบุทั้ง token และชื่อ');
    }

    const query = `UPDATE createbtn SET nameboard = $1 WHERE token = $2`;

    dbConnection.query(query, [name, token])
        .then(() => {
            res.send('อัปเดตชื่อสำเร็จ!');
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการอัปเดตชื่อ:', err);
            res.status(500).send('ไม่สามารถอัปเดตชื่อได้');
        });
});

// updateTemp
app.post('/updateTemp', (req, res) => {
    const { token, temp } = req.body;

    console.log(req.body);

    // เริ่มต้นด้วยการอัปเดตค่า new_temp และ update_status
    dbConnection.query(
        'UPDATE createbtn SET new_temp = $1, update_status = 1 WHERE token = $2',
        [temp, token]
    )
        .then(() => {
            // ดึงข้อมูลที่อัปเดตแล้วและเรียงตาม id
            return dbConnection.query('SELECT * FROM createbtn ORDER BY id ASC');
        })
        .then(result => {
            // ส่งข้อมูลที่อัปเดตกลับไปยังหน้าเว็บ
            res.status(200).json(result.rows);
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการอัปเดตอุณหภูมิ:', err);
            res.status(500).send('ไม่สามารถอัปเดตอุณหภูมิได้');
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
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลบอร์ด:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการดึงข้อมูลบอร์ด');
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
            console.error('เกิดข้อผิดพลาดในการลบบอร์ด:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการลบบอร์ด');
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
                res.status(404).send('ไม่พบบอร์ด');
            }
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการดึงรายละเอียดบอร์ด:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการดึงรายละเอียดบอร์ด');
        });
});

// forgot password 
app.post('/forgotpass', ifLoggedIn, [
    body('user_email', 'กรุณากรอกที่อยู่อีเมลให้ถูกต้อง').isEmail().custom((value) => {
        return dbConnection.query('SELECT email FROM users_iptcn WHERE email = $1', [value])
            .then(({ rows }) => {
                if (rows.length === 0) {
                    return Promise.reject('ไม่พบอีเมลนี้ในระบบ กรุณาตรวจสอบและลองใหม่อีกครั้ง');
                }
            });
    })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_email } = req.body;

    if (!user_email) {
        return res.render('forgotpass', {
            forgotpass_error: ['กรุณากรอกอีเมลของคุณ']
        });
    }

    if (validation_result.isEmpty()) {
        const token = generateRandomToken();

        dbConnection.query('UPDATE users_iptcn SET reset_token = $1 WHERE email = $2', [token, user_email])
            .then(() => {
                res.render('resetpass', {
                    email: user_email,
                    token: token,
                    success_message: 'กรุณาตรวจสอบอีเมลของคุณเพื่อรีเซ็ตรหัสผ่าน'
                });
            })
            .catch(err => {
                console.error('เกิดข้อผิดพลาดในการอัปเดตโทเคน:', err);
                res.render('forgotpass', {
                    forgotpass_error: ['เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่อีกครั้ง']
                });
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
    body('user_pass', 'กรุณากรอกรหัสผ่านอย่างน้อย 6 ตัวอักษร').trim().isLength({ min: 6 }),
    body('confirm_pass', 'กรุณายืนยันรหัสผ่าน').notEmpty(),
    body('confirm_pass', 'รหัสผ่านไม่ตรงกัน').custom((value, { req }) => {
        if (value !== req.body.user_pass) {
            return false;
        }
        return true;
    })
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, confirm_pass, token } = req.body;

    if (!user_pass || !confirm_pass) {
        return res.render('resetpass', {
            resetpass_error: ['กรุณากรอกข้อมูลให้ครบถ้วน'],
            token: token
        });
    }

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12)
            .then((hashedPassword) => {
                dbConnection.query("UPDATE users_iptcn SET password = $1, reset_token = NULL WHERE reset_token = $2", [hashedPassword, token])
                    .then(() => {
                        res.render('login', {
                            success_message: 'เปลี่ยนรหัสผ่านสำเร็จ',
                            showPopup: true

                        });
                    })
                    .catch(err => {
                        console.error('ข้อผิดพลาดในการอัปเดตรหัสผ่าน:', err);
                        res.status(500).send('ข้อผิดพลาดในการอัปเดตรหัสผ่าน กรุณาลองใหม่อีกครั้ง');
                    });
            })
            .catch(err => {
                console.error('ข้อผิดพลาดในการแฮชรหัสผ่าน:', err);
                res.status(500).send('ข้อผิดพลาดในการประมวลผลรหัสผ่าน กรุณาลองใหม่อีกครั้ง');
            });
    } else {
        let allErrors = validation_result.errors.map((error) => error.msg);
        res.render('resetpass', {
            resetpass_error: allErrors,
            token: token
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
                res.status(404).send('ไม่พบบอร์ด');
            }
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการดำเนินการคิวรี', err.stack);
            res.status(500).send('เกิดข้อผิดพลาดในการดึงข้อมูล token');
        });
});

// API สำหรับดึงข้อมูล temp และ ph ตาม token
app.get('/api/sensor-data', async (req, res) => {
    const { token } = req.query; // รับ token จาก query parameter

    if (!token) {
        return res.status(400).json({ error: 'ต้องระบุ Token' });
    }

    try {
        // Query ข้อมูลจากตาราง createbtn โดยใช้ token
        const result = await dbConnection.query('SELECT temp, ph FROM createbtn WHERE token = $1', [token]);

        // ถ้าไม่พบข้อมูล
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'ไม่พบข้อมูล' });
        }

        // ส่งข้อมูลกลับในรูปแบบ JSON
        const { temp, ph } = result.rows[0];
        res.json({ temp, ph });

    } catch (error) {
        console.error('เกิดข้อผิดพลาดในการดึงข้อมูลเซ็นเซอร์:', error);
        res.status(500).json({ error: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์' });
    }
});

// api บันทึกค่า temp, ph และ เก็บข้อมูลทุกๆ วินาที
app.post('/api/data', (req, res) => {
    const { token, temp, ph } = req.body;

    console.log(req.body); // ตรวจสอบข้อมูลที่รับมา

    // ตรวจสอบว่าข้อมูลครบถ้วนหรือไม่
    if (!token || temp === undefined || ph === undefined) {
        return res.status(400).json({ error: 'ข้อมูลไม่ครบถ้วน' });
    }

    // กำหนด timestamp ปัจจุบันในเขตเวลาที่ต้องการ (เช่น Asia/Bangkok)
    const currentTimestamp = moment().tz('Asia/Bangkok').format('YYYY-MM-DD HH:mm:ss');

    dbConnection.query('SELECT id, update_status, new_temp FROM createbtn WHERE token = $1', [token])
        .then(result => {
            if (result.rows.length > 0) {
                const boardId = result.rows[0].id;
                const updateStatus = result.rows[0].update_status;
                const newTemp = result.rows[0].new_temp; // ดึงค่า new_temp ด้วย

                // อัปเดต temp และ ph ใน createbtn (ไม่อัปเดต update_status)
                const updateCreateBtnQuery = dbConnection.query(
                    'UPDATE createbtn SET temp = $1, ph = $2 WHERE id = $3',
                    [temp, ph, boardId]
                );

                // แทรกข้อมูลลงใน sensor_data ทันทีทุกวินาที
                const insertSensorDataQuery = dbConnection.query(
                    'INSERT INTO sensor_data (temp, ph, token, timestamp) VALUES ($1, $2, $3, $4)',
                    [temp, ph, token, currentTimestamp]
                );

                return Promise.all([updateCreateBtnQuery, insertSensorDataQuery, updateStatus, newTemp]);
            } else {
                return Promise.reject({ status: 400, message: 'Token ไม่ถูกต้อง' });
            }
        })
        .then(results => {
            const updateStatus = results[2];
            const newTemp = results[3]; // รับค่า new_temp

            res.status(200).json({
                message: 'อัปเดตข้อมูลและบันทึกข้อมูลเซ็นเซอร์สำเร็จ',
                update_status: updateStatus,
                new_temp: newTemp // ส่ง new_temp กลับไปด้วย
            });
        })
        .catch(err => {
            if (err.status) {
                res.status(err.status).send(err.message);
            } else {
                console.error('เกิดข้อผิดพลาดในการดำเนินการคิวรี', err.stack);
                res.status(500).send('เกิดข้อผิดพลาดในการอัปเดตหรือแทรกข้อมูล');
            }
        });
});


// api update ค่าสถานะ จาก 1 เป็น 0 
app.post('/api/updateStatus', (req, res) => {
    const { token, updateStatus } = req.body;

    // ตรวจสอบข้อมูลที่ได้รับ
    if (!token || updateStatus === undefined) {
        return res.status(400).json({ error: 'ข้อมูลไม่ครบถ้วน' });
    }

    // อัปเดตค่า update_status ในฐานข้อมูล
    dbConnection.query('UPDATE createbtn SET update_status = $1 WHERE token = $2', [updateStatus, token])
        .then(() => {
            res.status(200).json({ message: 'อัปเดตสถานะสำเร็จ' });
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการอัปเดตสถานะ:', err);
            res.status(500).send('ไม่สามารถอัปเดตสถานะได้');
        });
});

// API ปรับค่าฝั่งทาง ESP32
app.post('/api/sendStatus', (req, res) => {
    const { token, sendTemp } = req.body;
    console.log(req.body);

    if (!token || sendTemp === undefined) {
        return res.status(400).json({ error: 'ไม่พบ token หรือ sendTemp' });
    }

    // Update the new_temp column in the 'createbtn' table
    dbConnection.query('UPDATE createbtn SET new_temp = $1 WHERE token = $2 RETURNING *', [sendTemp, token])
        .then(result => {
            if (result.rows.length === 0) {
                // Token not found
                return res.status(404).json({ error: 'ไม่พบ Token' });
            }
            // Return the updated row
            res.status(200).json(result.rows[0]);
        })
        .catch(err => {
            console.error('Error updating temperature:', err);
            res.status(500).json({ error: 'Failed to update temperature' });
        });
});

// แสดงกราฟและตาราง
app.get('/getHourlyData', async (req, res) => {
    const { token, date } = req.query; // รับทั้ง token และ date จาก query parameter
    const selectedDateStart = moment(date).tz('Asia/Bangkok').startOf('day').format('YYYY-MM-DD HH:mm:ss'); // 00:00 ของวันที่เลือก
    const selectedDateEnd = moment(date).tz('Asia/Bangkok').endOf('day').format('YYYY-MM-DD HH:mm:ss'); // 23:59 ของวันที่เลือก

    try {
        const result = await dbConnection.query(`
            SELECT 
                TO_CHAR(TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'YYYY-MM-DD HH24:MI:SS') AS timestamp, 
                temp, 
                ph 
            FROM sensor_data 
            WHERE token = $1
            AND TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' BETWEEN $2::timestamp AND $3::timestamp
            ORDER BY TO_TIMESTAMP(timestamp, 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'UTC' ASC
        `, [token, selectedDateStart, selectedDateEnd]);

        res.json(result.rows); // ส่งผลลัพธ์กลับในรูปแบบ JSON
    } catch (error) {
        console.error('Error fetching hourly data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// เริ่มเซิร์ฟเวอร์ HTTP
server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});