const crypto = require('crypto');
const net = require('net');
const readline = require('readline');
const fs = require('fs');
const tls = require('tls');
const path = require("path");

if (process.argv.length < 3) {
    console.error('Usage: node node.js <node_id>');
    process.exit(1);
}

const nodeId = process.argv[2];
const port = 8000 + parseInt(nodeId);
const caCertificate = fs.readFileSync(path.join(__dirname, 'ssl', 'rootCA.pem'), 'utf8');
const privateKey = fs.readFileSync(path.join(__dirname, `ssl`, `node${nodeId}.key`), 'utf8');
const certificate = fs.readFileSync(path.join(__dirname, `ssl`, `node${nodeId}.crt`), 'utf8');

let sessionKeys = {};

const server = net.createServer((socket) => {
    console.log(`Node ${nodeId}: Received connection from ${socket.remoteAddress}:${socket.remotePort}`);

    let clientRandom;
    let serverRandom = crypto.randomBytes(16);
    let sessionKey;

    socket.on('data', (data) => {
        const [type, payload1, payload2, payload3] = data.toString().split(':');

        if (type === 'HELLO') {
            clientRandom = Buffer.from(payload1, 'hex');
            console.log(`Node ${nodeId} (Server): Received client random string: ${clientRandom.toString('hex')}`);

            const publicKey = crypto.createPublicKey(privateKey).export({ type: 'pkcs1', format: 'pem' });
            socket.write(`HELLO_SERVER:${serverRandom.toString('hex')}:${publicKey}:${certificate}`);
        } else if (type === 'PREMASTER') {
            const encryptedPremaster = Buffer.from(payload1, 'hex');
            const premasterSecret = crypto.privateDecrypt(privateKey, encryptedPremaster);
            console.log(`Node ${nodeId} (Server): Received and decrypted premaster secret: ${premasterSecret.toString('hex')}`);

            sessionKey = crypto.createHash('sha256')
                .update(Buffer.concat([clientRandom, serverRandom, premasterSecret]))
                .digest()
                .slice(0, 16);

            console.log(`Node ${nodeId} (Server): Generated session key: ${sessionKey.toString('hex')}`);
            const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
            sessionKeys[connectionId] = sessionKey;

            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-128-cbc', sessionKey, iv);
            let encryptedMessage = cipher.update(`READY`, 'utf8');
            encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

            socket.write(`MESSAGE:${iv.toString('hex')},${encryptedMessage.toString('hex')}`);
            console.log(`Node ${nodeId} (Server): Sent "READY" through secure channel.`);

        } else if (type === 'MESSAGE') {
            const [ivHex, encryptedMessageHex] = payload1.split(',');
            const iv = Buffer.from(ivHex, 'hex');
            const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex');

            try {
                const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
                const decipher = crypto.createDecipheriv('aes-128-cbc', sessionKeys[connectionId], iv);
                let decryptedMessage = decipher.update(encryptedMessage, null, 'utf8');
                decryptedMessage += decipher.final('utf8');

                if (decryptedMessage === 'READY') {
                    console.log(`Node ${nodeId} (Server): Client is ready for secure communication.`);
                } else {
                    console.log(`Node ${nodeId} (Server): Decrypted message: ${decryptedMessage}`);
                }
            } catch (err) {
                console.error(`Node ${nodeId} (Server): Decryption failed: ${err.message}`);
            }
        }
    });

    socket.on('end', () => {
        const connectionId = `${socket.remoteAddress}:${socket.remotePort}`;
        delete sessionKeys[connectionId];
        console.log(`Node ${nodeId}: Client disconnected.`);
    });
});

server.listen(port, () => {
    console.log(`Node ${nodeId}: Server is running on port ${port}.`);
});

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

const connectToNode = (targetNodeId) => {
    const targetPort = 8000 + parseInt(targetNodeId);
    const clientRandom = crypto.randomBytes(16);
    let sessionKey;

    const client = net.createConnection({ port: targetPort }, () => {
        console.log('Client: Connected to server.');

        client.write(`HELLO:${clientRandom.toString('hex')}`);
    });

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

            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-128-cbc', sessionKey, iv);
            let encryptedMessage = cipher.update(`READY`, 'utf8');
            encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

            client.write(`MESSAGE:${iv.toString('hex')},${encryptedMessage.toString('hex')}`);
            console.log(`Client: Sent "READY" through secure channel.`);
        }
        else if (type === 'MESSAGE') {
            const [ivHex, encryptedMessageHex] = payload1.split(',');
            const iv = Buffer.from(ivHex, 'hex');
            const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex');

            try {
                const decipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, iv);
                let decryptedMessage = decipher.update(encryptedMessage, null, 'utf8');
                decryptedMessage += decipher.final('utf8');

                if (decryptedMessage === 'READY') {
                    console.log('Client: Server is ready for secure communication.');
                    console.log('Type your message below or type "!end" to close the connection.');

                    const sendMessage = (message) => {
                        if (message.trim() === '!end') {
                            console.log('Client: Closing connection...');
                            rl.removeListener('line', sendMessage);
                            client.end();
                            return;
                        }

                        const iv = crypto.randomBytes(16);
                        const cipher = crypto.createCipheriv('aes-128-cbc', sessionKey, iv);
                        let encryptedMessage = cipher.update(`(node${nodeId}) ${message}`, 'utf8');
                        encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

                        client.write(`MESSAGE:${iv.toString('hex')},${encryptedMessage.toString('hex')}`);
                        console.log(`Client: Sent "${message}" through secure channel.`);
                    };

                    rl.on('line', sendMessage);
                }
            } catch (err) {
                console.error(`Client: Decryption failed: ${err.message}`);
            }
        }
    });

    client.on('end', () => {
        console.log('Client: Disconnected from server.');
        showMenu();
    });

    client.on('error', (err) => {
        console.error(`Node ${nodeId} (Client): Error: ${err.message}`);
        showMenu();
    });
};

const validateCertificate = (serverCertificate) => {
    return new Promise((resolve) => {
        const validationOptions = {
            host: 'localhost',
            port: 8443,
            key: privateKey,
            cert: certificate,
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

const showMenu = () => {
    rl.question(`Node ${nodeId}: Enter target node ID to connect to or type "!exit" to exit: \n`, (input) => {
        if (input.trim() === '!exit') {
            console.log('Exiting...');
            rl.close();
            process.exit(0);
        }

        const targetNodeId = parseInt(input.trim(), 10);

        if (isNaN(targetNodeId) || targetNodeId < 1 || targetNodeId > 3) {
            console.log('Invalid Node ID. Please enter a valid node number.');
            showMenu();
            return;
        }

        connectToNode(targetNodeId);
    });
};

showMenu();
