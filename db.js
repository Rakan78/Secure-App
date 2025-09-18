const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: postgres,
  host: db,
  database: korean-db,
  password: korea123,
  port: 5432,
});

pool.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.error('Connection error', err.stack));

module.exports = pool;
