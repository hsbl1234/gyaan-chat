const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const secret = 'your_jwt_secret';
const app = express();
const port = 3000;
const dbPath = path.join(__dirname, 'main.db');
const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variable for JWT secret
 
let db; // Database instance
async function initializeDatabase() {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
 
        // Execute schema creation commands
        await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullName TEXT,
            email TEXT UNIQUE,
            password TEXT,
            otp INTEGER,
            otp_expiry INTEGER,
            verification BOOLEAN DEFAULT FALSE,
            resetToken TEXT,
            resetTokenExpiry INTEGER
        );
        
            
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                isGroup BOOLEAN DEFAULT FALSE,
                createdAt INTEGER,
                updatedAt INTEGER,
                createdBy INTEGER,
                FOREIGN KEY (createdBy) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chatId INTEGER,
                userId INTEGER,
                message TEXT,
                timestamp INTEGER,
                FOREIGN KEY (chatId) REFERENCES chats (id),
                FOREIGN KEY (userId) REFERENCES users (id)
            );
            
            CREATE TABLE IF NOT EXISTS chatParticipants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chatId INTEGER,
                userId INTEGER,
                joinedAt INTEGER,
                FOREIGN KEY (chatId) REFERENCES chats (id),
                FOREIGN KEY (userId) REFERENCES users (id),
                UNIQUE(chatId, userId)
            );
            
            CREATE TABLE IF NOT EXISTS userStatus (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId INTEGER,
                status TEXT,
                lastUpdated INTEGER,
                FOREIGN KEY (userId) REFERENCES users (id)
            );
        `);
 
        console.log('Database initialized');
    } catch (error) {
        console.error('Failed to initialize the database', error);
        process.exit(1); // Exit the process if database initialization fails
    }
}


initializeDatabase();
 
app.use(express.static(path.join(__dirname, 'public')));
app.use('/login', express.static(path.join(__dirname, 'public', 'login.html')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup.html')));
app.use('/verify/otp', express.static(path.join(__dirname, 'public', 'verify.html')));
app.use('/dashboard/:id', express.static(path.join(__dirname, 'public', 'dashboard.html')));
app.use(bodyParser.json());
app.use(cors());
app.use(express.json());
 
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'hsbl480085@gmail.com',
        pass: 'lwqz khjb nwzg cyoj'
    }
});
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
 
    if (token == null) return res.sendStatus(401);
 
    jwt.verify(token, secret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
// User signup
app.post('/signup', async (req, res) => {
    const { fullName, Email, Password } = req.body;
 
    if (!fullName || !Email || !Password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
 
    try {
        const existingUser = await db.get('SELECT * FROM users WHERE Email = ?', [Email]);
 
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }
 
        const hashedPassword = await bcrypt.hash(Password, 10);
        const otp = crypto.randomInt(100000, 999999); // Generate 6-digit OTP
 
        const result = await db.run('INSERT INTO users (fullName, Email, Password, otp, otp_expiry, verification) VALUES (?, ?, ?, ?, ?, ?)', [
            fullName,
            Email,
            hashedPassword,
            otp,
            Date.now() + 15 * 60 * 1000, // OTP expires in 15 minutes
            false
        ]);
 
        const userId = result.lastID;
 
        await transporter.sendMail({
            from: 'no-reply@gyan.com',
            to: Email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`
        });
 
        // Send userId in the response for redirection
        res.json({ userId });
    } catch (error) {
        console.error('Signup failed', error);
        res.status(500).json({ error: 'Signup failed' });
    }
});
 
// OTP verification
app.post('/verify/otp', async (req, res) => {
    const { otp } = req.body;
 
    if (!otp) {
        return res.status(400).json({ error: 'OTP is required' });
    }
 
    try {
        const user = await db.get('SELECT * FROM users WHERE otp = ? AND otp_expiry > ? ', [otp, Date.now()]);
 
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
 
        await db.run('UPDATE users SET verification = true WHERE id = ?', [user.id]);
 
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ message: 'OTP verified successfully!', token });
    } catch (error) {
        console.error('OTP verification failed', error);
        res.status(500).json({ error: 'OTP verification failed' });
    }
});
 
// User login
app.post('/login', async (req, res) => {
    const { Email, Password } = req.body;
 
    if (!Email || !Password) {
        return res.status(400).json({ error: 'Email and Password are required' });
    }
 
    try {
        const user = await db.get('SELECT * FROM users WHERE Email = ?', [Email]);
 
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
 
        const isPasswordMatch = await bcrypt.compare(Password, user.Password);
        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
 
        if (!user.verification) {
            const otp = crypto.randomInt(100000, 999999);
            const otpExpiry = Date.now() + 15 * 60 * 1000; // OTP expires in 15 minutes
 
            await db.run('UPDATE users SET otp = ?, otp_expiry = ?, verification = false WHERE id = ?', [otp, otpExpiry, user.id]);
 
            await transporter.sendMail({
                from: 'no-reply@gyan.com',
                to: Email,
                subject: 'Your OTP Code',
                text: `Your new OTP code is ${otp}`
            });
 
            return res.status(403).json({ error: 'Please verify your email before logging in. Check your email for a new OTP.', redirect: '/verify/signup' });
        }
 
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ user: { id: user.id, fullName: user.fullName }, token });
    } catch (error) {
        console.error('Login failed', error);
        res.status(500).json({ error: 'Login failed' });
    }
});
 
// Serve verification page
app.get('verify/${userId}', async (req, res) => {
    const userId = parseInt(req.params.id, 10);
 
    try {
        res.sendFile(path.join(__dirname, 'public', 'verify.html'));
    } catch (error) {
        console.error('Failed to serve verification page', error);
        res.status(500).json({ error: 'Failed to serve verification page' });
    }
});
 
app.post('/reset/password', async (req, res) => {
    const { email, newPassword } = req.body;
 
    if (!email || !newPassword) {
        return res.status(400).json({ error: 'Email and new password are required' });
    }
 
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const result = await db.run('UPDATE users SET Password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE Email = ?', [hashedPassword, email]);
 
        if (result.changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
 
        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        console.error('Password reset failed', error);
        res.status(500).json({ error: 'Password reset failed' });
    }
});
 
 
// Handle password reset confirmation
app.post('/confirm/reset/password', async (req, res) => {
    const { token, newPassword } = req.body;
 
    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required' });
    }
 
    try {
        const user = await db.get('SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?', [token, Date.now()]);
 
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
 
        const hashedPassword = await bcrypt.hash(newPassword, 10);
 
        await db.run('UPDATE users SET Password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?', [
            hashedPassword,
            user.id
        ]);
 
        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        console.error('Password reset confirmation failed', error);
        res.status(500).json({ error: 'Password reset confirmation failed' });
    }
});
app.post('/send/otp', async (req, res) => {
    const { email } = req.body;
 
    // Validate input
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
 
    try {
        // Check if the user exists
        const user = await db.get('SELECT * FROM users WHERE Email = ?', [email]);
 
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
 
        // Generate OTP and expiry
        const otp = crypto.randomInt(100000, 999999);
        const otpExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes expiry
 
        // Update OTP and expiry in the database
        await db.run('UPDATE users SET otp = ?, otp_expiry = ? WHERE Email = ?', [otp, otpExpiry, email]);
 
        // Send OTP email
        await transporter.sendMail({
            from: 'no-reply@gyan.com',
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`
        });
 
        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Failed to send OTP', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});
app.post('/resend/otp', async (req, res) => {
    const { userId, email } = req.body;
 
    if (!userId && !email) {
        return res.status(400).json({ error: 'Either User ID or Email is required' });
    }
 
    try {
        let user;
        if (email) {
            // Retrieve user based on email
            user = await db.get('SELECT id FROM users WHERE Email = ?', [email]);
        } else if (userId) {
            // Retrieve user based on userId
            user = await db.get('SELECT Email FROM users WHERE id = ?', [userId]);
        }
 
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
 
        const userEmail = user.Email || email; // Determine email to use
        const otp = crypto.randomInt(100000, 999999); // Generate new OTP
 
        // Update OTP and expiry in the database
        await db.run('UPDATE users SET otp = ?, otp_expiry = ? WHERE Email = ?', [
            otp,
            Date.now() + 15 * 60 * 1000, // OTP expires in 15 minutes
            userEmail
        ]);
 
        // Send OTP email
        await transporter.sendMail({
            from: 'no-reply@gyan.com',
            to: userEmail,
            subject: 'Your New OTP Code',
            text: `Your new OTP code is ${otp}`
        });
 
        res.json({ success: 'OTP has been resent to your email' });
    } catch (error) {
        console.error('Failed to resend OTP:', error);
        res.status(500).json({ error: 'Failed to resend OTP' });
    }
});
// Create a new chat
app.post('/chats', authenticateToken, async (req, res) => {
    const { name, isGroup } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Chat name is required' });
    }

    try {
        const result = await db.run('INSERT INTO chats (name, isGroup, createdAt, updatedAt, createdBy) VALUES (?, ?, ?, ?, ?)', [
            name,
            isGroup,
            Date.now(),
            Date.now(),
            req.user.id
        ]);

        const chatId = result.lastID;

        // Add the creator to the chat participants
        await db.run('INSERT INTO chatParticipants (chatId, userId, joinedAt) VALUES (?, ?, ?)', [
            chatId,
            req.user.id,
            Date.now()
        ]);

        res.json({ chatId, name, isGroup });
    } catch (error) {
        console.error('Failed to create chat', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});
// Send a message
app.post('/messages', authenticateToken, async (req, res) => {
    const { chatId, message } = req.body;

    if (!chatId || !message) {
        return res.status(400).json({ error: 'Chat ID and message are required' });
    }

    try {
        const result = await db.run('INSERT INTO messages (chatId, userId, message, timestamp) VALUES (?, ?, ?, ?)', [
            chatId,
            req.user.id,
            message,
            Date.now()
        ]);

        res.json({ messageId: result.lastID, chatId, message });
    } catch (error) {
        console.error('Failed to send message', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});
// Fetch messages for a chat
app.get('/messages/:chatId', authenticateToken, async (req, res) => {
    const { chatId } = req.params;

    try {
        const messages = await db.all('SELECT m.id, m.message, m.timestamp, u.fullName FROM messages m JOIN users u ON m.userId = u.id WHERE m.chatId = ? ORDER BY m.timestamp ASC', [chatId]);

        res.json(messages);
    } catch (error) {
        console.error('Failed to fetch messages', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});
// Get list of chats for the authenticated user
app.get('/chats', authenticateToken, async (req, res) => {
    try {
        const chats = await db.all('SELECT c.id, c.name, c.isGroup FROM chats c JOIN chatParticipants cp ON c.id = cp.chatId WHERE cp.userId = ?', [req.user.id]);

        res.json(chats);
    } catch (error) {
        console.error('Failed to get chats', error);
        res.status(500).json({ error: 'Failed to get chats' });
    }
});


// Define the search function outside of the route handler
async function searchUsersByFullName(query) {
    try {
        // Use a prepared statement to prevent SQL injection
        const result = await db.all('SELECT id, fullName FROM users WHERE fullName LIKE ?', [`%${query}%`]);
        return result;
    } catch (error) {
        console.error('Error executing search query:', error);
        throw error;
    }
}

app.get('/api/search', async (req, res) => {
    const query = req.query.query;

    if (!query) {
        return res.status(400).send('Query parameter is required.');
    }

    try {
        const users = await searchUsersByFullName(query); // Call the defined function
        res.json(users);
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/protected', authenticateToken, (req, res) => {
    res.json(req.user);
});
// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
 
 
 