const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Define the User schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true, // Ensure unique usernames
    minlength: 3,
    maxlength: 30,
  },
  email: {
    type: String,
    required: true,
    // unique: true, // Ensure unique email
    // match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, // Simple email validation
  },
  password: {
    type: String,
    required: true,
    minlength: 6, // Minimum password length
  },
  // Add other fields as needed, like `role`, `isActive`, etc.
});

// Middleware to hash the password before saving to the database
userSchema.pre('save', async function (next) {
  try {
    // if (!this.isModified('password')) return next();

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(this.password, 10); // 10 is the salt rounds
    console.log('hashedPassword from db:',hashedPassword);
    this.password = hashedPassword;
    // console.log('saving pas:',this.password)
    next();
  } catch (err) {
    console.log('error :',err)
    next(err); // Pass error to the next middleware
  }
});

// Method to compare password during login
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
  // return password === this.password
};

// Create the User model based on the schema
const User = mongoose.model('User', userSchema);

module.exports = User;
