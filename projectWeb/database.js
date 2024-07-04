const { Pool } = require('pg');

const dbConnection = new Pool({
  host: 'localhost',
  user: 'postgres',
  password: '0000',
  database: 'postgres',
  port: 5432, // พอร์ตดีฟอลต์ของ PostgreSQL
});

module.exports = dbConnection;
