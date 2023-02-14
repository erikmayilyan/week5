import mysql from "mysql2"
import dotenv from "dotenv"
dotenv.config()

const pool = mysql
  .createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT || 3306,
  })
  .promise()

export async function createUser({email, password, displayName}) {
  const [results] = await pool.query(
    `INSERT INTO users (email, password, displayName) VALUES (?, ?, ?)`,
    [email, password, displayName]
  )
  return results
}

export async function getUserWithEmail(email) {
  const [results] = await pool.query(
    `SELECT * FROM users WHERE email = ?`,
    [email]
  )
  return results
}

export async function updateUserDisplayName(id, displayName) {
  const [results] = await pool.query(
    `UPDATE users SET displayName = ? WHERE id = ?`,
    [displayName, id]
  )
  return results
}

export async function updateUserProfileImage(id, profileImage) {
  const [results] = await pool.query(
    `UPDATE users SET profileImage = ? WHERE id = ?`,
    [profileImage, id]
  )
  return results
}
