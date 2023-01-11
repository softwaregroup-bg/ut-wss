const Boom = require('boom');
const jwt = require('jsonwebtoken');
const helpers = {
    formatMessage: function(msg) {
        return typeof msg === 'string' ? msg : JSON.stringify(msg);
    },
    getTokens(strs, separators) {
        if (!separators.length) {
            return {key: strs.shift().trim(), value: strs.shift().trim()};
        }
        const separator = separators.shift();
        return strs
            .map((s) => (helpers.getTokens(s.split(separator), separators)))
            .reduce((accum, c) => {
                if (!c.key) {
                    return Object.assign(accum, c);
                }
                accum[c.key] = c.value;
                return accum;
            }, {});
    },
    jwtXsrfCheck({query, cookie, hashKey, verifyOptions}) {
        return new Promise((resolve, reject) => {
            // return unauthorized if something is wrong with xsrf get query param or with cookie itself
            if (query.xsrf === '' || !cookie) return reject(Boom.unauthorized());
            jwt.verify(cookie, hashKey, verifyOptions, (err, decoded) => { // verify cookie
                // if wild error appears, mark this request as unauthorized
                if (err) return reject(Boom.unauthorized(err.name));
                // if xsrf get param is not the same as xsrfToken from the cookie, mark this request as unauthorized
                if (decoded.xsrfToken !== query.xsrf) return reject(Boom.unauthorized('Xsrf mismatch'));
                // yeah we are done, on later stage will check for correct permissions
                resolve(decoded);
            });
        });
    },
    permissionVerify(socket, appId) {
        const actions = ['%'];
        if (appId) actions.push(appId);
        const objects = ['%', socket.fingerprint];
        if (Array.isArray(socket.auth.scopes)) {
            for (let i = 0, n = socket.auth.scopes.length; i < n; i += 1) {
                const {actionId, objectId} = socket.auth.scopes[i];
                if (actions.includes(actionId) && objects.includes(objectId)) {
                    return true;
                }
            }
        }
        throw Boom.forbidden();
    }
};

module.exports = helpers;
