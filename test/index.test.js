const tap = require('tap');
const http = require('http');
const Websocket = require('ws');
const SocketServer = require('..');
const jwt = require('jsonwebtoken');
const testMessage = {test: true};
const { hostname } = require('os');
const xsrfToken = '123e4567-e89b-12d3-a456-426655440000';
const config = {
    jwt: {
        key: 'test'
    }
};
const token = jwt.sign({
    xsrfToken,
    scopes: [{actionId: '%', objectId: '%'}]
}, config.jwt.key);
const socketServer = new SocketServer({ log: { error: tap.error } }, config);

const stop = err => {
    if (err) tap.error(err);
    tap.end();
    socketServer.stop();
    server.close();
};

function start() {
    socketServer.start(server);
    socketServer.registerPath('/test', () => true);
    socketServer.on('connection', () => socketServer.publish({path: '/test'}, testMessage));

    const socketClient = new Websocket(
        `ws://${hostname}:${server.address().port}/test?xsrf=${xsrfToken}`,
        {
            headers: {
                Authorization: 'Bearer ' + token
            }
        }
    );
    socketClient.onclose = ({code, reason}) => code >= 4000 && stop(new Error('Socket close reason: ' + reason));
    socketClient.onerror = stop;
    socketClient.onmessage = ({data}) => {
        tap.equal(data, JSON.stringify(testMessage), 'message received');
        stop();
    };
}

const server = http.createServer();
server.on('error', stop);
server.on('listening', start);
server.listen();
