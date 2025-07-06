
const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: String,
    clockInTime: Date,
    clockOutTime: Date,
    durationMs: Number,
    durationHours: String,
    status: { type: String, required: true },
    note: { type: String },
    timestamp: String
});

module.exports = mongoose.model('Attendance', attendanceSchema);
