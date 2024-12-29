const crypto = require('crypto');
const net = require('net');
const fs = require('fs');

const caCertificate = fs.readFileSync('cert.pem', 'utf8');
const clientRandom = crypto.randomBytes(16);

const client = net.createConnection({ port: 8080 }, () => {
    console.log('Client: Connected to server.');

    client.write(`HELLO:${clientRandom.toString('hex')}`);
});

let sessionKey;

client.on('data', (data) => {
    const [type, payload1, payload2, payload3] = data.toString().split(':');

    if (type === 'HELLO_SERVER') {
        console.log(`Client: Received server random: ${payload1}`);
        console.log('Client: Received server public key and certificate.');

        const serverRandom = Buffer.from(payload1, 'hex');
        const serverPublicKey = payload2;
        const serverCertificate = payload3;

        if (serverCertificate !== caCertificate) {
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
    }
});

client.on('end', () => {
    console.log('Client: Disconnected from server.');
});
