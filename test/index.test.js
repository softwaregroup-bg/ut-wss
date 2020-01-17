const tap = require('tap');
const http = require('http');
const Websocket = require('ws');
const SocketServer = require('..');
const testMessage = {test: true};
const socketServer = new SocketServer({
    log: {
        error: tap.comment
    }
}, {
    jwt: {},
    disableXsrf: { ws: true },
    disablePermissionVerify: { ws: true }
});

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

    const socketClient = new Websocket(`ws://localhost:${server.address().port}/test`);
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
