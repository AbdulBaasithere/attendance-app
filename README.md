# Attendance System

This is a simple attendance system built with Node.js, Express, and MongoDB.

## Prerequisites

- Node.js
- MongoDB

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/attendance-system.git
   ```
2. Install the dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the root directory and add the following environment variables:
   ```
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   PORT=3000
   ```

## Running the Application

- **Development:**
  ```bash
  npm run dev
  ```
- **Production:**
  ```bash
  npm start
  ```

## API Endpoints

- `POST /signup` - Register a new user.
- `POST /login` - Log in an existing user.
- `POST /logout` - Log out the current user.
- `POST /clock-in` - Clock in the current user.
- `POST /clock-out` - Clock out the current user.
- `GET /attendance-records` - Get all attendance records for the current user.
- `GET /currently-clocked-in` - Get all currently clocked-in users.
