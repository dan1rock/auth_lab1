const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const path = require("path");

const serverCertificate = fs.readFileSync(path.join(__dirname, 'ssl', 'server.crt'), 'utf8');
const privateKey = fs.readFileSync(path.join(__dirname, 'ssl', 'server.key'), 'utf8');

const serverRandom = crypto.randomBytes(16);
let sessionKey;
let clientRandom;

const server = net.createServer((socket) => {
    console.log('Client connected.');

    socket.on('data', (data) => {
        const [type, payload] = data.toString().split(':');

        if (type === 'HELLO') {
            clientRandom = Buffer.from(payload, 'hex');
            console.log(`Server: Received client random string: ${clientRandom.toString('hex')}`);

            const publicKey = crypto.createPublicKey(privateKey).export({ type: 'pkcs1', format: 'pem' });
            socket.write(`HELLO_SERVER:${serverRandom.toString('hex')}:${publicKey}:${serverCertificate}`);
        } else if (type === 'PREMASTER') {
            const encryptedPremaster = Buffer.from(payload, 'hex');
            const premasterSecret = crypto.privateDecrypt(privateKey, encryptedPremaster);
            console.log(`Server: Received and decrypted premaster secret: ${premasterSecret.toString('hex')}`);

            sessionKey = crypto.createHash('sha256')
                .update(Buffer.concat([clientRandom, serverRandom, premasterSecret]))
                .digest()
                .slice(0, 16);

            console.log(`Server: Generated session key: ${sessionKey.toString('hex')}`);

            socket.write('READY');
        } else if (type === 'MESSAGE') {
            const [ivHex, encryptedMessageHex] = payload.split(',');
            const iv = Buffer.from(ivHex, 'hex');
            const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex'); 

            try {
                const decipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, iv);
                let decryptedMessage = decipher.update(encryptedMessage, null, 'utf8');
                decryptedMessage += decipher.final('utf8');
                console.log(`Server: Decrypted message: ${decryptedMessage}`);
            } catch (err) {
                console.error('Decryption failed:', err.message);
            }
        }
    });

    socket.on('end', () => {
        console.log('Client disconnected.');
    });
});

server.listen(8080, () => {
    console.log('Server is running on port 8080.');
});
