const { Pool } = require('pg');

const dbConnection = new Pool({
  host: '20.2.211.25',
  user: 'lcmpj',
  password: '0656076916lcm',
  database: 'LCM',
  port: 5432, // พอร์ตดีฟอลต์ของ PostgreSQL
});

module.exports = dbConnection;
