const tls = require('tls');
const fs = require('fs');
const path = require('path');

const rootCAPath = path.join(__dirname, 'ssl', 'rootCA.pem');

const options = {
    key: fs.readFileSync(path.join(__dirname, 'ssl', 'server.key'), 'utf8'),
    cert: fs.readFileSync(path.join(__dirname, 'ssl', 'server.crt'), 'utf8'),
    ca: [fs.readFileSync(rootCAPath, 'utf8')],
    requestCert: true,
    rejectUnauthorized: true,
};

const server = tls.createServer(options, (socket) => {
    console.log('Client connected.');

    console.log(`Client certificate authorized: ${socket.authorized}`);
    if (!socket.authorized) {
        console.error(`Authorization error: ${socket.authorizationError}`);
        socket.end('Unauthorized\n');
        return;
    }

    const cert = socket.getPeerCertificate();
    console.log('Client Certificate Details:');
    console.log(`  Subject: ${cert.subject.CN}`);
    console.log(`  Issuer: ${cert.issuer.CN}`);
    console.log(`  Valid from: ${cert.valid_from}`);
    console.log(`  Valid to: ${cert.valid_to}`);

    socket.on('data', (data) => {
        const [command, certificate] = data.toString().split(':');
        if (command === 'VALIDATE') {
            console.log('Received certificate for validation.');

            const tempCertPath = path.join(__dirname, 'temp.crt');
            fs.writeFileSync(tempCertPath, certificate);

            const exec = require('child_process').exec;
            const verifyCommand = `openssl verify -CAfile ${rootCAPath} ${tempCertPath}`;

            exec(verifyCommand, (error, stdout, stderr) => {
                fs.unlinkSync(tempCertPath);

                if (error) {
                    console.error(`Validation failed: ${stderr || stdout}`);
                    socket.write('INVALID');
                } else {
                    console.log(`Validation succeeded: ${stdout.trim()}`);
                    socket.write('VALID');
                }
                socket.end();
            });
        } else {
            console.error('Unknown command received.');
            socket.write('INVALID');
            socket.end();
        }
    });

    socket.on('end', () => {
        console.log('Client disconnected.');
    });
});

server.listen(8443, () => {
    console.log('Server running on port 8443.');
});
