const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH0_DOMAIN = 'danylo.eu.auth0.com';
const AUTH0_CLIENT_ID = 'RhGEaZ2CjYpuHfAR7gz3BxF7Fk59Bkbh';
const AUTH0_CLIENT_SECRET = 'eui8xIPZjM8Edq3RbqhX6pWxgGfZfuzj9xDm4yKX9-LsOjnqh7CWbJGe6Z8n4J_T';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
        } catch (e) {
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

// Get Auth0 public key for JWT verification
const getPublicKey = (header, callback) => {
    const client = jwksClient({
        jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
    });
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            callback(err);
        } else {
            const signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        }
    });
};

const cookieParser = require('cookie-parser');
app.use(cookieParser());

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.cookies.sessionId;

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
            res.cookie('sessionId', sessionId, { httpOnly: true });
        }
    } else {
        sessionId = sessions.init(res);
        res.cookie('sessionId', sessionId, { httpOnly: true });
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    if (req.session.access_token && req.session.refresh_token) {
        const accessToken = req.session.access_token;
        const refreshToken = req.session.refresh_token;

        jwt.verify(accessToken, getPublicKey, (err, decoded) => {
            if (err) {
                console.error('Invalid access token:', err);
                return res.status(401).send('Invalid access token');
            } else {
                const currentTime = Math.floor(Date.now() / 1000);

                if (decoded.exp < currentTime) {
                    // Token expired, need to refresh
                    axios.post('http://localhost:3000/api/refreshToken', {
                        refresh_token: refreshToken
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
            }
        });
    } else {
        next();
    }
});

// Main page route
app.get('/', (req, res) => {
    return res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/userinfo', (req, res) => {
    if (req.session.access_token) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/api/logout'
        });
    } else {
        return res.status(401).json({ error: 'Not authenticated' });
    }
});

// Logout route
app.get('/api/logout', (req, res) => {
    sessions.destroy(req, res);
    res.clearCookie('sessionId');
    res.redirect('/');
});

// Callback route to handle Auth0 response
app.get('/callback', async (req, res) => {
    const authorizationCode = req.query.code;

    if (!authorizationCode) {
        return res.status(400).send('Authorization code missing');
    }

    try {
        // Exchange authorization code for access token and refresh token
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'authorization_code',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            code: authorizationCode,
            redirect_uri: `http://localhost:${port}/callback`
        });

        const { access_token, refresh_token } = response.data;
        const userId = jwt.decode(access_token).sub;

        // Store tokens and user info in session
        req.session.username = userId;
        req.session.access_token = access_token;
        req.session.refresh_token = refresh_token;

        // Redirect to the main page
        res.redirect('/');
    } catch (error) {
        console.error('Error exchanging authorization code:', error.response ? error.response.data : error.message);
        res.status(500).send('Authentication failed');
    }
});

// Login route (redirect to Auth0)
app.get('/api/login', (req, res) => {
    const redirectParams = new URLSearchParams({
        response_type: 'code',
        client_id: AUTH0_CLIENT_ID,
        redirect_uri: `http://localhost:${port}/callback`,
        scope: 'openid profile email',
        state: uuid.v4()
    });

    const redirectURL = `https://${AUTH0_DOMAIN}/authorize?${redirectParams}`;
    res.json({ redirectURL });
});

// Refresh token route
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
        res.json({ access_token, refresh_token });
    } catch (error) {
        console.error('Token refresh failed:', error.response ? error.response.data : error.message);
        res.status(401).send('Token refresh failed');
    }
});

// Start server
app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
