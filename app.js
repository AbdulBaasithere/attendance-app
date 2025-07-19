require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Attendance = require('./models/attendance');

const app = express();
const PORT = process.env.PORT || 3000;
const FULL_DAY_MS = 8 * 60 * 60 * 1000;
const HALF_DAY_MS = 4 * 60 * 60 * 1000;

const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'eventlog.txt');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);

const logEvent = async (type, msg, data = {}) => {
  const entry = `[${new Date().toISOString()}] [${type}] ${msg} - ${JSON.stringify(data)}\n`;
  fs.promises.appendFile(LOG_FILE, entry).catch(console.error);
  console.log('EVENT LOG:', entry);
};

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logEvent('DB_CONNECT', 'Connected to MongoDB'))
  .catch(err => console.error('MongoDB Error:', err));

const requestLogger = (req, _, next) => {
  logEvent('HTTP', `${req.method} ${req.url}`, req.method === 'POST' ? req.body : {});
  next();
};

const userSchema = new mongoose.Schema({
    userId: { type: Number, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);



const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Auth required' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(404).json({ message: 'User not found' });
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

app.use(express.json(), express.urlencoded({ extended: true }), requestLogger);
app.use(express.static(path.join(__dirname, 'public')));


app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (await User.findOne({ username })) return res.status(409).json({ message: 'User exists' });
    const user = new User({ username, password: await bcrypt.hash(password, 10) });
    await user.save();
    logEvent('SIGNUP', `User ${username} created.`);
    res.status(201).json({ message: 'Registered' });
  } catch (err) {
    logEvent('SIGNUP_ERROR', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logEvent('LOGIN', `User ${username} logged in.`);
    res.json({ message: 'Logged in', token });
  } catch (err) {
    logEvent('LOGIN_ERROR', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/clock-in', auth, async (req, res) => {
  try {
    if (await Attendance.findOne({ userId: req.user._id, clockOutTime: null })) return res.status(409).json({ message: 'Already clocked in' });
    const clockInTime = new Date();
    await Attendance.create({ userId: req.user._id, name: req.user.username, clockInTime, status: 'Clocked In' });
    logEvent('CLOCK_IN', `User ${req.user.username} clocked in.`);
    res.json({ message: `Clocked in at ${clockInTime.toLocaleTimeString()}` });
  } catch (err) {
    logEvent('CLOCK_IN_ERR', err.message);
    res.status(500).json({ message: 'Clock-in error' });
  }
});

app.post('/clock-out', auth, async (req, res) => {
  try {
    const record = await Attendance.findOne({ userId: req.user._id, clockOutTime: null });
    if (!record) return res.status(404).json({ message: 'Not clocked in' });

    const clockOutTime = new Date();
    const duration = clockOutTime - record.clockInTime;
    record.set({
      clockOutTime,
      durationMs: duration,
      durationHours: (duration / 3600000).toFixed(2),
      status: duration >= FULL_DAY_MS ? 'Full Day' : duration >= HALF_DAY_MS ? 'Half Day' : 'Less than Half Day',
      timestamp: new Date().toISOString()
    });
    await record.save();
    logEvent('CLOCK_OUT', `User ${req.user.username} clocked out.`);
    res.json({ message: 'Clocked out', record });
  } catch (err) {
    logEvent('CLOCK_OUT_ERR', err.message);
    res.status(500).json({ message: 'Clock-out error' });
  }
});

app.get('/admin/attendance-records', authMiddleware, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied. Admin role required.' });
        }
        
        await eventLogger('ADMIN_ATTENDANCE_FETCH', 'Admin requested all attendance records.');
        const records = await Attendance.find({}).populate('userId', 'username');
        res.status(200).json(records);
    } catch (err) {
        await eventLogger('ADMIN_ATTENDANCE_FETCH_ERROR', 'Error fetching all attendance records', { error: err.message });
        res.status(500).json({ message: 'Server error while fetching records.' });
    }
});

app.get('/attendance-records', auth, async (req, res) => {
  try {
    const records = await Attendance.find({ userId: req.user._id });
    res.json(records);
  } catch (err) {
    logEvent('FETCH_ERR', err.message);
    res.status(500).json({ message: 'Fetch error' });
  }
});

app.get('/currently-clocked-in', auth, async (_, res) => {
  try {
    const clockedInUsers = await Attendance.find({ clockOutTime: null });
    res.json(clockedInUsers);
  } catch (err) {
    logEvent('FETCH_CLOCKEDIN_ERR', err.message);
    res.status(500).json({ message: 'Fetch error' });
  }
});

app.listen(PORT, () => logEvent('SERVER_START', `Running on http://localhost:${PORT}`));
