require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const router = express.Router();

app.use(express.json());

const secretKey = process.env.SECRET_KEY;

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


router.post('/login', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).send('Username is required');

    // Generate a token
    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
});

// Open route 
router.get('/', (req, res) => {
    res.send(`Hello, server is running!`);
});

// Protected GET API to respond with "Hello, {name}"
router.get('/hello', authenticateToken, (req, res) => {
    const name = req.query.name || 'World';
    res.send(`Hello, ${name}`);
});

// Protected POST API 
router.post('/hello', authenticateToken, (req, res) => {
    const name = req.body.name || 'World';
    res.send(`Hello, ${name}`);
});

app.use('/', router);

module.exports = app;
