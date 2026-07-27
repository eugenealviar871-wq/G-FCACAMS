const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const bcrypt = require('bcryptjs');
const path = require('path');
const { nanoid } = require('nanoid');

const DATA_DIR = path.join(__dirname, '..', 'data');
const adapter = new FileSync(path.join(DATA_DIR, 'users.json'));
const db = low(adapter);

// Clean up duplicates: keep only users that are NOT admin@local.test, plus one admin
const existingUsers = db.get('users').value() || [];
const cleanedUsers = existingUsers.filter(user => user.email !== 'admin@local.test');

// Hash password "admin123"
const saltRounds = 10;
const hashedPassword = bcrypt.hashSync('admin123', saltRounds);

// Add a single admin user
const adminUser = {
  id: nanoid(),
  name: 'Administrator',
  email: 'admin@local.test',
  pass: hashedPassword,
  role: 'admin',
  createdAt: new Date().toISOString()
};
cleanedUsers.push(adminUser);

// Write back to the database
db.set('users', cleanedUsers).write();

console.log('Successfully fixed admin user!');
console.log('Admin credentials:');
console.log('  Email: admin@local.test');
console.log('  Password: admin123');
console.log('  Role: admin');
