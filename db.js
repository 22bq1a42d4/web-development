const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect('mongodb://127.0.0.1:27017/project_db', {
      // No need for deprecated options
    });
    console.log('MongoDB connected to project_db');
  } catch (err) {
    console.error('Database connection failed', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;
