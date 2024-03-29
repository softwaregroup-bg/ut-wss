'use strict';
const ws = require('ws');
const Router = require('call').Router;
const EventEmitter = require('events');
const helpers = require('./helpers');
const INTERPOLATION_REGEX = /\{([^}]*)\}/g;
async function sendMessage(socket, message) {
    if (socket.readyState === ws.OPEN) {
        // socket.auth.exp must be EPOCH in seconds but not milliseconds
        if (typeof socket.auth.exp === 'number' && socket.auth.exp * 1000 < Date.now()) {
            return socket.close(4403, 'Session expired!');
        }
        return socket.send(message);
    }
}
class SocketServer extends EventEmitter {
    constructor(utHttpServer = {}, config = {}) {
        super();
        this.router = new Router();
        this.rooms = {};
        this.wss = null;
        this.utHttpServer = utHttpServer;
        this.utHttpServerConfig = config;
        this.disableXsrf = (config.disableXsrf && config.disableXsrf.ws);
        this.disablePermissionVerify = (config.disablePermissionVerify && config.disablePermissionVerify.ws);
    }

    start(httpServerListener) {
        this.wss = new ws.Server({
            server: httpServerListener
        });
        this.wss.on('connection', (socket, req) => {
            const url = req.url.split('?').shift();
            try {
                // socket.upgradeReq not supported anymore:
                // https://github.com/websockets/ws/pull/1099
                // persist only fingerprint (for verification)
                socket.fingerprint = this.router.analyze(url).fingerprint;
            } catch (e) {
                return socket.close(4404, 'Wrong url:' + req.url);
            }

            Promise.resolve()
                .then(() => {
                    if (this.disableXsrf) return {};
                    const params = {
                        query: helpers.getTokens([req.url.replace(/[^?]+\?/ig, '')], ['&', '=']),
                        hashKey: this.utHttpServerConfig.jwt.key,
                        verifyOptions: {
                            ...this.utHttpServerConfig.jwt.verifyOptions,
                            ignoreExpiration: false
                        }
                    };
                    if (req.headers.authorization) {
                        const [scheme, token] = req.headers.authorization.split(' ');
                        if (scheme === 'Bearer') params.cookie = token;
                    } else if (req.headers.cookie) {
                        params.cookie = helpers.getTokens([req.headers.cookie], [';', '='])[this.utHttpServerConfig.jwt.cookieKey];
                    }

                    return helpers.jwtXsrfCheck(params);
                })
                .then(auth => {
                    socket.auth = auth;
                    const context = this.router.route(req.method.toLowerCase(), url);
                    if (context.isBoom) throw context;
                    if (!this.disablePermissionVerify) helpers.permissionVerify(socket, this.utHttpServerConfig.appId);
                    return context.route.verifyClient(socket);
                })
                .then(() => {
                    return this.router
                        .route(req.method.toLowerCase(), url).route
                        .handler(socket.fingerprint, socket);
                })
                .then(() => (this.emit('connection')))
                .catch((err) => {
                    this.utHttpServer.log && this.utHttpServer.log.error && this.utHttpServer.log.error(err);
                    if (!err.isBoom) return socket.close(4500, '4500');
                    socket.close(
                        4000 + parseInt(err.output.payload.statusCode), // based on https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent#Status_codes
                        (4000 + parseInt(err.output.payload.statusCode)).toString() // Send status code as reason because Firefox/Edge show 1005 only as code
                    );
                });
        });
    }

    registerPath(path, verifyClient) {
        this.router.add({
            method: 'get',
            path
        }, {
            handler: (roomId, socket) => {
                if (!this.rooms[roomId]) this.rooms[roomId] = new Set();
                this.rooms[roomId].add(socket);
                socket.on('close', () => this.rooms[roomId].delete(socket));
            },
            verifyClient: socket => {
                return typeof verifyClient === 'function' ? verifyClient(socket, socket.fingerprint) : false;
            }
        });
    }

    publish({path = '', params = {}}, message) {
        const room = this.rooms[path.replace(INTERPOLATION_REGEX, (placeholder, label) => (params[label] || placeholder))];
        if (room && room.size) {
            const formattedMessage = helpers.formatMessage(message);
            room.forEach(socket => sendMessage(socket, formattedMessage));
        }
    }

    broadcast(message) {
        const formattedMessage = helpers.formatMessage(message);
        this.wss.clients.forEach(socket => sendMessage(socket, formattedMessage));
    }

    stop() {
        this.wss && this.wss.close();
    }
}

module.exports = SocketServer;
