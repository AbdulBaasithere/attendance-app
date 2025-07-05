require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Attendance = require('./models/attendance');

const app = express();
const PORT = process.env.PORT || 3000;

const FULL_DAY_THRESHOLD_MS = 8 * 60 * 60 * 1000; 
const HALF_DAY_THRESHOLD_MS = 4 * 60 * 60 * 1000; 

// --- Logging Setup ---
const LOG_DIRECTORY = path.join(__dirname, 'logs');
const ATTENDANCE_LOG_FILE = path.join(LOG_DIRECTORY, 'eventlog.txt');

if (!fs.existsSync(LOG_DIRECTORY)) {
    fs.mkdirSync(LOG_DIRECTORY);
}

// --- Event Logger ---
const eventLogger = async (eventType, message, data = {}) => {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${eventType.toUpperCase()}] ${message} - Data: ${JSON.stringify(data)}\n`;

    try {
        if (!fs.existsSync(LOG_DIRECTORY)) {
            await fsPromises.mkdir(LOG_DIRECTORY);
        }
        await fsPromises.appendFile(ATTENDANCE_LOG_FILE, logEntry);
    } catch (err) {
        console.error('Logging error:', err);
    }

    console.log(`EVENT LOG: ${logEntry}`);
};

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB Atlas');
    eventLogger('DB_CONNECT', 'MongoDB Atlas Connection Successful');
}).catch(err => {
    console.error('MongoDB Connection error: ', err);
});

// --- Middleware ---
const requestLoggerMiddleware = (req, res, next) => {
    eventLogger('HTTP_REQUEST', `Incoming request: ${req.method} ${req.url}`, {
        ip: req.ip,
        body: ['POST', 'PUT'].includes(req.method) ? req.body : undefined
    });
    next();
};

const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestLoggerMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

// --- User Schema ---
const userSchema = new mongoose.Schema({
    userId: { type: Number, unique : true},
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// --- Routes ---
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const existing = await User.findOne({ username });
        if (existing) {
            await eventLogger('SIGNUP_FAILED', `Signup failed for user ${username}. Reason: User already exists.`);
            return res.status(409).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        await eventLogger('SIGNUP_SUCCESS', `User ${username} registered successfully.`);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        await eventLogger('SIGNUP_ERROR', `Server error during signup for user ${username}`, { error: err.message });
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            await eventLogger('LOGIN_FAILED', `Login failed for user ${username}. Reason: User not found.`);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            await eventLogger('LOGIN_FAILED', `Login failed for user ${username}. Reason: Invalid password.`);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role || 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        await eventLogger('LOGIN_SUCCESS', `User ${username} logged in successfully.`);
        res.json({ message: 'Login successful', token });
    } catch (err) {
        await eventLogger('LOGIN_ERROR', `Server error during login for user ${username}`, { error: err.message });
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/user-info', authMiddleware, (req, res) => {
    res.json({ 
        username: req.user.username,
        role: req.user.role
    });
});

app.post('/logout', (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup-page', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

app.post('/clock-in', authMiddleware, async (req, res) => {
    const { user } = req;

    try {
        const existingRecord = await Attendance.findOne({ userId: user._id, clockOutTime: null });
        if (existingRecord) {
            await eventLogger('CLOCK_IN_FAILED', `User ${user.username} tried to clock in but is already clocked in.`);
            return res.status(409).json({ message: 'You are already clocked in.' });
        }

        const clockInTime = new Date();
        const newRecord = new Attendance({
            userId: user._id,
            name: user.username,
            clockInTime,
            status: 'Clocked In'
        });

        await newRecord.save();
        await eventLogger('CLOCK_IN_SUCCESS', `User ${user.username} clocked in at ${clockInTime.toISOString()}`, { userId: user._id, name: user.username, clockInTime });
        res.status(200).json({ message: `Successfully clocked in at ${clockInTime.toLocaleTimeString()}` });
    } catch (err) {
        await eventLogger('CLOCK_IN_ERROR', `Error during clock-in for user ${user.username}`, { error: err.message });
        res.status(500).json({ message: 'Server error during clock-in.' });
    }
});

app.post('/clock-out', authMiddleware, async (req, res) => {
    const { user } = req;

    try {
        const record = await Attendance.findOne({ userId: user._id, clockOutTime: null });
        if (!record) {
            await eventLogger('CLOCK_OUT_FAILED', `User ${user.username} tried to clock out but was not clocked in.`);
            return res.status(404).json({ message: 'You are not currently clocked in.' });
        }

        const clockOutTime = new Date();
        const durationMs = clockOutTime.getTime() - record.clockInTime.getTime();

        let status = 'Pending';
        if (durationMs >= FULL_DAY_THRESHOLD_MS) {
            status = 'Full Day';
        } else if (durationMs >= HALF_DAY_THRESHOLD_MS) {
            status = 'Half Day';
        } else {
            status = 'Less than Half Day';
        }

        record.clockOutTime = clockOutTime;
        record.durationMs = durationMs;
        record.durationHours = (durationMs / (1000 * 60 * 60)).toFixed(2);
        record.status = status;
        record.timestamp = new Date().toISOString();

        await record.save();
        await eventLogger('CLOCK_OUT_SUCCESS', `User ${user.username} clocked out. Status: ${status}`, record.toObject());

        res.status(200).json({
            message: `Successfully clocked out. Duration: ${record.durationHours} hours. Status: ${status}`,
            record
        });
    } catch (err) {
        await eventLogger('CLOCK_OUT_ERROR', `Error during clock-out for user ${user.username}`, { error: err.message });
        res.status(500).json({ message: 'Server error during clock-out.' });
    }
});

app.get('/attendance-records', authMiddleware, async (req, res) => {
    try {
        await eventLogger('ATTENDANCE_FETCH', 'All attendance records requested.');
        const records = await Attendance.find({ userId: req.user._id });
        res.status(200).json(records);
    } catch (err) {
        await eventLogger('ATTENDANCE_FETCH_ERROR', 'Error fetching attendance records', { error: err.message });
        res.status(500).json({ message: 'Server error while fetching records.' });
    }
});

app.get('/currently-clocked-in', authMiddleware, async (req, res) => {
    try {
        await eventLogger('CURRENT_CLOCK_IN_FETCH', 'Currently clocked-in users requested.');
        const clockedInUsers = await Attendance.find({ clockOutTime: null });
        res.status(200).json(clockedInUsers);
    } catch (err) {
        await eventLogger('CURRENT_CLOCK_IN_FETCH_ERROR', 'Error fetching currently clocked-in users', { error: err.message });
        res.status(500).json({ message: 'Server error while fetching currently clocked-in users.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    eventLogger('SERVER_START', `Server started on port ${PORT}`);
});
