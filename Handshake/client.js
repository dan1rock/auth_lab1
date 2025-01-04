const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require("path");

const caCertificate = fs.readFileSync(path.join(__dirname, 'ssl', 'rootCA.pem'), 'utf8');
const clientCertificate = fs.readFileSync(path.join(__dirname, 'ssl', 'client.crt'), 'utf8');
const privateKey = fs.readFileSync(path.join(__dirname, 'ssl', 'client.key'), 'utf8');
const clientRandom = crypto.randomBytes(16);

const client = net.createConnection({ port: 8080 }, () => {
    console.log('Client: Connected to server.');

    client.write(`HELLO:${clientRandom.toString('hex')}`);
});

let sessionKey;

client.on('data', async (data) => {
    const [type, payload1, payload2, payload3] = data.toString().split(':');

    if (type === 'HELLO_SERVER') {
        console.log(`Client: Received server random: ${payload1}`);
        console.log('Client: Received server public key and certificate.');

        const serverRandom = Buffer.from(payload1, 'hex');
        const serverPublicKey = payload2;
        const serverCertificate = payload3;

        const isValid = await validateCertificate(serverCertificate);

        if (!isValid) {
            console.error('Client: Server certificate validation failed!');
            client.end();
            return;
        }
        console.log('Client: Server certificate validated.');

        const premasterSecret = crypto.randomBytes(16);
        console.log(`Client: Generated premaster secret: ${premasterSecret.toString('hex')}`);

        const encryptedPremaster = crypto.publicEncrypt(serverPublicKey, premasterSecret);

        client.write(`PREMASTER:${encryptedPremaster.toString('hex')}`);

        sessionKey = crypto.createHash('sha256')
            .update(Buffer.concat([clientRandom, serverRandom, premasterSecret]))
            .digest()
            .slice(0, 16);

        console.log(`Client: Generated session key: ${sessionKey.toString('hex')}`);
    } else if (type === 'READY') {
        console.log('Client: Server is ready for secure communication.');

        const message = 'Hello, secure world!';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-cbc', sessionKey, iv);
        let encryptedMessage = cipher.update(message, 'utf8');
        encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

        client.write(`MESSAGE:${iv.toString('hex')},${encryptedMessage.toString('hex')}`);

        console.log('Client: Sent "Hello, secure world!" through secure channel.');

        client.end();
    }
});

client.on('end', () => {
    console.log('Client: Disconnected from server.');
});

const validateCertificate = (serverCertificate) => {
    return new Promise((resolve) => {
        const validationOptions = {
            host: 'localhost',
            port: 8443,
            key: privateKey,
            cert: clientCertificate,
            ca: caCertificate,
            rejectUnauthorized: true,
        };

        const validationClient = tls.connect(validationOptions, () => {
            console.log('Client: Connected to validation server on port 8443.');

            if (!validationClient.authorized) {
                console.error('Client: Validation server certificate validation failed.');
                validationClient.end();
                resolve(false);
                return;
            }

            console.log('Client: Validation server certificate is valid.');

            validationClient.write(`VALIDATE:${serverCertificate}`);
        });

        validationClient.on('data', (data) => {
            const response = data.toString();
            if (response === 'VALID') {
                console.log('Client: Server certificate validated by the validation server.');
                resolve(true);
            } else {
                console.error('Client: Server certificate rejected by the validation server.');
                resolve(false);
            }
            validationClient.end();
        });

        validationClient.on('end', () => {
            console.log('Client: Disconnected from validation server.');
        });

        validationClient.on('error', (err) => {
            console.error(`Validation Client Error: ${err.message}`);
            resolve(false);
        });
    });
}
