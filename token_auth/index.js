const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

const AUTH0_DOMAIN = 'danylo.eu.auth0.com';
const AUTH0_CLIENT_ID = 'RhGEaZ2CjYpuHfAR7gz3BxF7Fk59Bkbh';
const AUTH0_CLIENT_SECRET = 'eui8xIPZjM8Edq3RbqhX6pWxgGfZfuzj9xDm4yKX9-LsOjnqh7CWbJGe6Z8n4J_T';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            //console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    if (req.session.access_token && req.session.refresh_token) {
        const accessToken = jwt.decode(req.session.access_token);
        const currentTime = Math.floor(Date.now() / 1000);

        if (accessToken.exp < currentTime) {
            axios.post('http://localhost:3000/api/refreshToken', {
                refresh_token: req.session.refresh_token
            })
                .then(response => {
                    req.session.access_token = response.data.access_token;
                    req.session.refresh_token = response.data.refresh_token;
                    next();
                })
                .catch(error => {
                    console.error('Token refresh failed:', error.response ? error.response.data : error.message);
                    res.status(401).send('Token refresh failed');
                });
        } else {
            next();
        }
    } else {
        next();
    }
})

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'password',
            username: login,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            scope: 'offline_access'
        });

        const { access_token, refresh_token } = response.data;
        const userId = jwt.decode(access_token).sub;

        req.session.username = userId;
        req.session.access_token = access_token;
        req.session.refresh_token = refresh_token;

        res.json({ token: req.sessionId });
    } catch (error) {
        if (error.response && error.response.data) {
            console.error('Login failed:', error.response.data);
        } else {
            console.error('Login failed:', error.message);
        }
        res.status(401).send('Login failed');
    }
});

app.post('/api/createUser', async (req, res) => {
    const {email, password} = req.body;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
            email: email,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            connection: 'Username-Password-Authentication'
        });

        res.status(201).send('User created successfully');
    } catch (error) {
        console.error('User creation failed:', error.response ? error.response.data : error.message);
        res.status(500).send('User creation failed');
    }
});

app.post('/api/refreshToken', async (req, res) => {
    const refreshToken = req.body.refresh_token;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'refresh_token',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            refresh_token: refreshToken
        });

        const { access_token, refresh_token } = response.data;

        console.log(refresh_token);
        res.json({ access_token, refresh_token });
    } catch (error) {
        console.error('Token refresh failed:', error.response ? error.response.data : error.message);
        res.status(401).send('Token refresh failed');
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
