const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const JWT_SECRET_KEY = 'SECRET';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
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
    let jwtToken = req.get(SESSION_KEY);

    if (jwtToken) {
        try {
            jwt.verify(jwtToken, JWT_SECRET_KEY);
            currentSession = sessions.get(jwtToken);
            if (!currentSession) {
                currentSession = {};
                jwtToken = sessions.init(res);
            }
        } catch (err) {
            jwtToken = sessions.init(res);
        }
    } else {
        jwtToken = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = jwtToken;

    onFinished(req, () => {
        const currentSession = req.session;
        const jwtToken = req.sessionId;
        sessions.set(jwtToken, currentSession);
    });

    next();
})

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization;

    jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
        req.user = decoded;
        next();
    });
};

app.get('/', authenticateJWT, (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            return true;
        }
        return false
    });

    if (user) {
        req.session.username = user.username;
        req.session.login = user.login;
        const jwtToken = jwt.sign({ username: user.username }, JWT_SECRET_KEY);

        res.json({ username: user.username, token: jwtToken });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
