const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '30d',
  });
};

const loginStudent = async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE email = ? OR phone = ?', [email, email]);
    
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const student = rows[0];

    // Check if soft deleted
    if (student.deleted_at !== null) {
      return res.status(401).json({ message: 'Student account is disabled or deleted' });
    }
    
    // Check password
    if (student.password && await bcrypt.compare(password, student.password)) {
      res.json({
        id: student.id,
        name: student.name,
        email: student.email,
        role: 'STUDENT',
        token: generateToken(student.id, 'STUDENT'),
        is_first_login: student.is_first_login === 1
      });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const studentId = req.user.id;

  try {
    const [rows] = await pool.query('SELECT password FROM students WHERE id = ?', [studentId]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const student = rows[0];

    // Verify current password
    if (!student.password || !(await bcrypt.compare(currentPassword, student.password))) {
      return res.status(401).json({ success: false, message: 'Invalid current password' });
    }

    const { encrypt } = require('../utils/crypto');
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    const encryptedPassword = encrypt(newPassword);

    await pool.query(
      'UPDATE students SET password = ?, encrypted_password = ?, is_first_login = FALSE WHERE id = ?',
      [hashedPassword, encryptedPassword, studentId]
    );

    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { loginStudent, changePassword };
