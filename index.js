'use strict';
const ws = require('ws');
const Router = require('call').Router;
const EventEmitter = require('events');
const helpers = require('./helpers');
const INTERPOLATION_REGEX = /\{([^}]*)\}/g;

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
        this.wss.on('connection', (socket) => {
            let cookies = (socket.upgradeReq.headers && socket.upgradeReq.headers.cookie) || '';
            let url = socket.upgradeReq.url.split('?').shift();
            let fingerprint = this.router.analyze(url).fingerprint;
            Promise.resolve()
                .then(() => (!this.disableXsrf && helpers.jwtXsrfCheck(
                    helpers.getTokens([socket.upgradeReq.url.replace(/[^?]+\?/ig, '')], ['&', '=']), // parse url string into hash object
                    helpers.getTokens([cookies], [';', '='])[this.utHttpServerConfig.jwt.cookieKey], // parse cookie string into hash object
                    this.utHttpServerConfig.jwt.key,
                    Object.assign({}, this.utHttpServerConfig.jwt.verifyOptions, {ignoreExpiration: false})
                )
                ))
                .then((p) => (new Promise((resolve, reject) => {
                    let context = this.router.route(socket.upgradeReq.method.toLowerCase(), url);
                    if (context.isBoom) {
                        throw context;
                    }
                    context.permissions = p;
                    resolve(context);
                })))
                .then((context) => {
                    if (!this.disablePermissionVerify) {
                        return helpers.permissionVerify(context, fingerprint, this.utHttpServerConfig.appId);
                    }
                    return context;
                })
                .then((context) => (context.route.verifyClient(socket)))
                .then(() => {
                    return this.router
                        .route(socket.upgradeReq.method.toLowerCase(), url).route
                        .handler(fingerprint, socket);
                })
                .then(() => (this.emit('connection')))
                .catch((err) => {
                    if (!err.isBoom) {
                        this.utHttpServer.log && this.utHttpServer.log.error && this.utHttpServer.log.error(err);
                        return socket.close(4500, '4500');
                    }
                    this.utHttpServer.log && this.utHttpServer.log.error && this.utHttpServer.log.error(err);
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
            path: path
        }, {
            handler: (roomId, socket) => {
                if (!this.rooms[roomId]) {
                    this.rooms[roomId] = new Set();
                }
                this.rooms[roomId].add(socket);
                socket.on('close', () => {
                    this.rooms[roomId].delete(socket);
                });
            },
            verifyClient: (socket) => {
                return Promise.resolve()
                    .then(() => {
                        if (verifyClient && typeof (verifyClient) === 'function') {
                            return verifyClient(socket, this.router.analyze(socket.upgradeReq.url).fingerprint);
                        }
                        return 0;
                    });
            }
        });
    }
    publish(data, message) {
        let room;
        try {
            room = this.rooms[data.path.replace(INTERPOLATION_REGEX, (placeholder, label) => (data.params[label] || placeholder))];
        } catch (e) {
            throw e;
        }
        if (room && room.size) {
            let formattedMessage = helpers.formatMessage(message);
            room.forEach(function(socket) {
                if (socket.readyState === ws.OPEN) {
                    socket.send(formattedMessage);
                }
            });
        }
    }
    broadcast(message) {
        let formattedMessage = helpers.formatMessage(message);
        this.wss.clients.forEach(function(socket) {
            socket.send(formattedMessage);
        });
    }
    stop() {
        this.wss.close();
    }
}

module.exports = SocketServer;
