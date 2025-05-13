const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('./models/user');
const connectDB = require('./db');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'your_jwt_secret_key';

// Connect to the database
connectDB();

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '/'))); // Serve static files from the root directory

// Routes for serving HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html')); // Serve login page
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html')); // Serve signup page
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html')); // Ensure this path points to your login page
});


app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot_password.html')); // Serve forgot password page
});

// Handle signup and login routes
// Signup route (for saving user details to MongoDB)
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  
  try {
    // Check if the email already exists
    console.log('got here')
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'Email already exists' });

    // Hash the password
    // const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds
    // console.log('Hashed password:', hashedPassword);
    // Create a new user with hashed password
   const newuser =  await User.create({ username, email, password })
    // Save user to the database
    // await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});


// Login route
// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Sending password:', password);


  try {
    const user = await User.findOne({ username }); // Find user by username
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Log the retrieved user (for debugging)


    // Use the comparePassword method to check the password
    const isMatch = await user.comparePassword(password);
    console.log(isMatch)

    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Create a JWT token
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    // Log the token for debugging
    console.log('Generated token:', token);

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Forgot password route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '15m' });

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'your_email@gmail.com',
        pass: 'your_email_password',
      },
    });

    const mailOptions = {
      from: 'your_email@gmail.com',
      to: email,
      subject: 'Password Reset',
      html: `<p>Click <a href="http://localhost:5000/reset-password/${resetToken}">here</a> to reset your password.</p>`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Reset password route
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ message: 'User not found' });

    user.password = newPassword; // Password will be hashed in the User model
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
