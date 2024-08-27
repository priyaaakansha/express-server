const express = require('express');
const app = express();
const router = express.Router();

app.use(express.json());

// GET API to respond with "Hello, {name}" from query parameter
router.get('/hello', (req, res) => {
    const name = req.query.name || 'World'; // Default to 'World' if no name is provided
    res.send(`Hello, ${name}`);
});

// POST API 
router.post('/hello', (req, res) => {
    const name = req.body.name || 'World';
    res.send(`Hello, ${name}`);
});

module.exports = app;
app.use('/', router);

