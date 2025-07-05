
const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
    id: String,
    name: String,
    clockInTime: Date,
    clockOutTime: Date,
    durationMs: Number,
    durationHours: String,
    status: String,
    timestamp: String
});

module.exports = mongoose.model('Attendance', attendanceSchema);
