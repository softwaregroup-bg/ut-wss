const Boom = require('boom');
const jwt = require('jsonwebtoken');
const helpers = {
    formatMessage: function(message) {
        let msg;
        try {
            msg = typeof message === 'string' ? message : JSON.stringify(message);
        } catch (e) {
            throw e;
        }
        return msg;
    },
    getTokens(strs, separators) {
        if (!separators.length) {
            return {key: strs.shift().trim(), value: strs.shift().trim()};
        }
        let separator = separators.shift();
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
            if (query.xsrf === '' || !cookie || cookie === '') { // return unauthorized if something is wrong with xsrf get query param or with cookie itself
                return reject(Boom.unauthorized());
            }
            jwt.verify(cookie, hashKey, verifyOptions, (err, decoded) => { // verify cookie
                if (err) { // if wild error appears, mark this request as unauthorized
                    return reject(Boom.unauthorized(err.name));
                }
                if (decoded.xsrfToken !== query.xsrf) { // if xsrf get param is not the same as xsrfToken from the cookie, mark this request as unauthorized
                    return reject(Boom.unauthorized('Xsrf mismatch'));
                }
                resolve(decoded.scopes); // yeah we are done, on later stage will check for correct permissions
            });
        });
    },
    permissionVerify(ctx, roomId, appId) {
        let allowedActionList = ['%'];
        if (appId) {
            allowedActionList.push(appId);
        }
        let allowedObjectList = ['%', roomId];
        let permitCount = (ctx.permissions || [])
            .filter((v) => (
                allowedActionList.includes(v.actionId) &&
            allowedObjectList.includes(v.objectId)
            )).length;

        if (!(permitCount > 0)) {
            throw Boom.forbidden();
        }
        return ctx;
    }
};

module.exports = helpers;
