require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
const app = express();
const router = express.Router();

app.use(express.json());

const secretKey = process.env.SECRET_KEY;
const port = process.env.PORT || 3000;
const path = require('path');
const usersFilePath = path.join(__dirname, 'public', 'users.txt');


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401); // If no token, return Unauthorized

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403); // If token is invalid, return Forbidden
        req.user = user;
        next();
    });
};

// Signup route
router.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    // Check if the user already exists
    const users = fs.readFileSync(usersFilePath, 'utf8').split('\n');
    const userExists = users.some(user => user.split(':')[0] === username);

    if (userExists) {
        return res.status(409).send('User already exists');
    }

    // Hash the password and save it to the file
    const hashedPassword = await bcrypt.hash(password, 10);
    fs.appendFileSync(usersFilePath, `${username}:${hashedPassword}\n`);
    
    res.status(201).send('User registered successfully');
});

// Login route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Retrieve users from the file
    const users = fs.readFileSync(usersFilePath, 'utf8').split('\n');
    const user = users.find(user => user.split(':')[0] === username);

    if (!user) {
        return res.status(400).send('Cannot find user');
    }

    const [storedUsername, storedHashedPassword] = user.split(':');

    // Verify the password
    if (await bcrypt.compare(password, storedHashedPassword)) {
        // Generate a token
        const accessToken = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        res.json({ accessToken });
    } else {
        res.status(403).send('Invalid password');
    }
});

// Protected route example
router.get('/protected', authenticateToken, (req, res) => {
    res.send(`Hello, ${req.user.username}. You have access to this protected route.`);
});

app.use('/', router);

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

module.exports = app;
