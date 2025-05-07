// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/schedule-app')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

const scheduleSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  Sunday: { 
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Monday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Tuesday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Wednesday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Thursday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Friday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  },
  Saturday: {
    startTime: { type: String, required: true },
    endTime: { type: String, required: true }
  }
});

const timeOffSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    required: true,
    enum: ['vacation', 'dayOff', 'sickLeave', 'other']
  },
  startDate: { type: String, required: true },
  endDate: { type: String, required: true },
  description: { type: String },
  status: { 
    type: String, 
    default: 'pending',
    enum: ['pending', 'approved', 'rejected'] 
  },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Schedule = mongoose.model('Schedule', scheduleSchema);
const TimeOff = mongoose.model('TimeOff', timeOffSchema);

// Auth Middleware
const authenticate = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Validation Middleware
const validateTimeFormat = (time) => {
    // Check for invalid inputs
    if (!time || typeof time !== 'string') {
      return false;
    }
  
    const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
    return timeRegex.test(time.trim());
};
  
const validateDateFormat = (date) => {
    // Check for invalid inputs
    if (!date || typeof date !== 'string') {
      return false;
    }
  
    // Check format (YYYY-MM-DD)
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(date.trim())) {
      return false;
    }
  
    // Semantic validation
    const [year, month, day] = date.split('-').map(Number);
    const parsedDate = new Date(year, month - 1, day); // Months are 0-based in JS
  
    // Check if the date is valid and matches input (handles invalid days/months)
    return (
      parsedDate.getFullYear() === year &&
      parsedDate.getMonth() === month - 1 &&
      parsedDate.getDate() === day
    );
};


// Routes

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Create default schedule for new user
    const defaultSchedule = new Schedule({
      userId: user._id,
      Sunday: { startTime: '09:00', endTime: '17:30' },
      Monday: { startTime: '09:00', endTime: '17:30' },
      Tuesday: { startTime: '09:00', endTime: '17:30' },
      Wednesday: { startTime: '09:00', endTime: '17:30' },
      Thursday: { startTime: '09:00', endTime: '17:30' },
      Friday: { startTime: '09:00', endTime: '17:30' },
      Saturday: { startTime: '09:00', endTime: '17:30' }
    });
    
    await defaultSchedule.save();
    
    // Create JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    
    res.status(201).json({ 
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validation
    if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ 
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Schedule Routes
app.get('/api/schedule', authenticate, async (req, res) => {
  try {
    const schedule = await Schedule.findOne({ userId: req.user.id });
    
    if (!schedule) {
      // Create default schedule if none exists
      const defaultSchedule = new Schedule({
        userId: req.user.id,
        Sunday: { startTime: '09:00', endTime: '17:30' },
        Monday: { startTime: '09:00', endTime: '17:30' },
        Tuesday: { startTime: '09:00', endTime: '17:30' },
        Wednesday: { startTime: '09:00', endTime: '17:30' },
        Thursday: { startTime: '09:00', endTime: '17:30' },
        Friday: { startTime: '09:00', endTime: '17:30' },
        Saturday: { startTime: '09:00', endTime: '17:30' }
      });
      
      await defaultSchedule.save();
      return res.json(defaultSchedule);
    }
    
    res.json(schedule);
  } catch (error) {
    console.error('Get schedule error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/schedule', authenticate, async (req, res) => {
  try {
    const updatedSchedule = req.body;
    
    // Validate time format
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    
    for (const day of days) {
      if (updatedSchedule[day]) {
        const { startTime, endTime } = updatedSchedule[day];
        
        if (startTime && !validateTimeFormat(startTime)) {
          return res.status(400).json({ message: `Invalid start time format for ${day}` });
        }
        
        if (endTime && !validateTimeFormat(endTime)) {
          return res.status(400).json({ message: `Invalid end time format for ${day}` });
        }
      }
    }
    
    // Update schedule
    const schedule = await Schedule.findOneAndUpdate(
      { userId: req.user.id },
      { $set: updatedSchedule },
      { new: true, runValidators: true }
    );
    
    if (!schedule) {
      return res.status(404).json({ message: 'Schedule not found' });
    }
    
    res.json({ message: 'Schedule updated successfully', schedule });
  } catch (error) {
    console.error('Update schedule error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Time Off Routes
app.get('/api/timeoff', authenticate, async (req, res) => {
  try {
    const timeOffs = await TimeOff.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(timeOffs);
  } catch (error) {
    console.error('Get time off error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/timeoff', authenticate, async (req, res) => {
  try {
    const { type, startDate, endDate, description } = req.body;
    
    // Validation
    if (!type || !startDate) {
      return res.status(400).json({ message: 'Type and start date are required' });
    }
    
    if (!validateDateFormat(startDate)) {
      return res.status(400).json({ message: 'Invalid start date format. Use YYYY-MM-DD' });
    }
    
    let finalEndDate = endDate;
    
    // Handle dayOff type (single day)
    if (type === 'dayOff') {
      finalEndDate = startDate; // For dayOff, end date is same as start date
    } else {
      // For vacation and other types, validate end date
      if (!finalEndDate) {
        return res.status(400).json({ message: 'End date is required for vacation' });
      }
      
      if (!validateDateFormat(finalEndDate)) {
        return res.status(400).json({ message: 'Invalid end date format. Use YYYY-MM-DD' });
      }
      
      if (new Date(startDate) > new Date(finalEndDate)) {
        return res.status(400).json({ message: 'End date must be after start date' });
      }
    }
    
    // Create new time off entry
    const timeOff = new TimeOff({
      userId: req.user.id,
      type,
      startDate,
      endDate: finalEndDate,
      description
    });
    
    await timeOff.save();
    
    res.status(201).json({ message: 'Time off request created successfully', timeOff });
  } catch (error) {
    console.error('Create time off error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/timeoff/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { type, startDate, endDate, description } = req.body;
    
    // Validation
    if (!type || !startDate) {
      return res.status(400).json({ message: 'Type and start date are required' });
    }
    
    if (!validateDateFormat(startDate)) {
      return res.status(400).json({ message: 'Invalid start date format. Use YYYY-MM-DD' });
    }
    
    let finalEndDate = endDate;
    
    // Handle dayOff type (single day)
    if (type === 'dayOff') {
      finalEndDate = startDate; // For dayOff, end date is same as start date
    } else {
      // For vacation and other types, validate end date
      if (!finalEndDate) {
        return res.status(400).json({ message: 'End date is required for vacation' });
      }
      
      if (!validateDateFormat(finalEndDate)) {
        return res.status(400).json({ message: 'Invalid end date format. Use YYYY-MM-DD' });
      }
      
      if (new Date(startDate) > new Date(finalEndDate)) {
        return res.status(400).json({ message: 'End date must be after start date' });
      }
    }
    
    // Find and update time off
    const timeOff = await TimeOff.findOneAndUpdate(
      { _id: id, userId: req.user.id },
      { type, startDate, endDate: finalEndDate, description },
      { new: true, runValidators: true }
    );
    
    if (!timeOff) {
      return res.status(404).json({ message: 'Time off request not found' });
    }
    
    res.json({ message: 'Time off request updated successfully', timeOff });
  } catch (error) {
    console.error('Update time off error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/timeoff/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Find and delete time off
    const timeOff = await TimeOff.findOneAndDelete({ _id: id, userId: req.user.id });
    
    if (!timeOff) {
      return res.status(404).json({ message: 'Time off request not found' });
    }
    
    res.json({ message: 'Time off request deleted successfully' });
  } catch (error) {
    console.error('Delete time off error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});