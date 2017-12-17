import { createHash, pbkdf2Sync } from 'crypto';
import { Agent, IncomingMessage, request } from 'http';
import { RequestOptions } from 'https';
import { parse as JSON5_parse } from 'json5';
import { stringify as qs_stringify } from 'querystring';

// tslint:disable-next-line:no-empty
function noop() { }

function _httpDummyCB(res: IncomingMessage) {
    res.on('data', noop);
}

function _reqStringCB(cb: (err?: Error, res?: string, httpRes?: IncomingMessage) => void) {
    return (err?: Error, res?: IncomingMessage) => {
        if (err) {
            cb(err, undefined, res);
            return;
        }

        const data: Buffer[] = [];
        res!.on('data', (chunk: Buffer) => {
            data.push(chunk);
        });
        res!.on('end', () => {
            cb(undefined, Buffer.concat(data).toString('utf8'), res);
        });
        res!.on('error', cbErr => {
            cb(cbErr, undefined, res);
        });
    };
}

export class SPRequestOptions {
    public http?: RequestOptions;
    public loginTries?: number;
    public noCookies?: boolean;
}

export class Speedport {
    public lastHeartbeat?: string = JSON.stringify([
        {
            varid: 'loginstate',
            vartype: 'status',
            varvalue: '1',
        },
    ]);
    public loginStageOneReply?: string = undefined;
    public loginStageTwoReply?: string = undefined;

    private challengev?: string = undefined;
    private sessionID?: string = undefined;
    private cookie?: string = undefined;
    private cookieHeaders?: string[];

    private _loginInProgress = false;
    private loggedIn = 0;
    private _loginCallbacks: ((err?: Error) => void)[] = [];

    private agent: Agent = new Agent({
        keepAlive: true,
        maxSockets: 3,
    });

    constructor(ip: string, private password: string, private options: RequestOptions = {}) {
        options.host = ip;
        setInterval(() => this._heartbeat(), 5000);
    }

    public request(options: SPRequestOptions, data: string | undefined,
                   cb: (err?: Error, res?: IncomingMessage) => void) {
        if (options.loginTries === undefined) {
            options.loginTries = 3;
        }

        const httpOptions = options.http || {};

        let cookie = this.cookie;
        if (cookie && httpOptions.headers && httpOptions.headers.cookie) {
            cookie += `; ${httpOptions.headers.cookie}`;
        }

        Object.assign(httpOptions, this.options, {
            headers: {
                cookie: cookie || null,
            },
        });

        const req = request(httpOptions, res => {
            if (res.statusCode === 302 && res.headers!.location!.indexOf('/html/login/index.html') > 0) {
                _httpDummyCB(res);
                if (options.loginTries! <= 0) {
                    return cb(new Error('Not logged in or 404'));
                }
                options.loginTries!--;
                return this.login(err => {
                    if (err) {
                        return cb(err);
                    }
                    return this.request(options, data, cb);
                });
            }
            if (this.cookieHeaders && !options.noCookies) {
                res.headers['set-cookie'] = this.cookieHeaders;
            }
            return cb(undefined, res);
        });

        req.on('error', cb);

        req.setTimeout(10000);

        if (data) {
            req.write(data);
        }

        req.end();
    }

    private _heartbeat() {
        this.request({
            http: {
                method: 'GET',
                path: `/data/heartbeat.json?_time=${Date.now()}&_rand=${Math.floor(Math.random() * 900 + 100)}`,
            },
        }, undefined, _reqStringCB((err?: Error, data?: string) => {
            if (err) {
                console.error('Heartbeat error', err, err.stack);
                return;
            }

            this.lastHeartbeat = data;
        }));
    }

    private _dataRequest(options: RequestOptions, data: string | undefined,
                         cb: (err?: Error, res?: IncomingMessage) => void) {
        options.headers = options.headers || {};
        options.method = options.method || 'POST';
        options.agent = this.agent;
        if (data) {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            options.headers['Content-Length'] = Buffer.byteLength(data);
        }
        const req = request(options, res => {
            return cb(undefined, res);
        });
        req.on('error', err => cb(err));
        req.setTimeout(10000);
        if (data) {
            req.write(data);
        }
        req.end();
    }

    private _loginCBMultiplexer(err?: Error) {
        this._loginInProgress = false;
        this.loggedIn = err ? 0 : Date.now();
        this._loginCallbacks.forEach(cb => cb(err));
        this._loginCallbacks = [];
    }

    /**
     * Requests the password-challenge from the router. Calls handleChallenge() on success.
     */
    private login(cb: (err?: Error) => void) {
        if ((this.loggedIn + 60000) >= Date.now()) {
            cb(undefined);
            return;
        }

        if (this._loginInProgress) {
            this._loginCallbacks.push(cb);
            return;
        }

        this._loginInProgress = true;
        this._loginCallbacks = [cb];

        cb = (err?: Error) => this._loginCBMultiplexer(err);

        this.challengev = undefined;
        this.sessionID = undefined;
        this.cookie = undefined;
        this.cookieHeaders = undefined;

        const options = {};
        Object.assign(options, this.options, {
            method: 'GET',
            path: '/html/login/index.html',
        });

        this._dataRequest(options, undefined, _reqStringCB((err?: Error, data?: string) => {
            if (err) {
                cb(err);
                return;
            }

            this.loginStageOneReply = data;

            // challengev -> will be sent as query var
            try {
                this.challengev = data!.match(/var challenge = "([^"]+)";/)![1];
            } catch (e) {
                console.error(e, e.stack);
            }
            this._sendPassword(cb);
        }));
    }

    /**
     * Sends the hashed password to the router and acquires a session ID.
     * Hashes challenge + password and send it back to speedport.
     */
    private _sendPassword(cb: (err?: Error) => void) {
        if (!this.challengev) {
            return cb(new Error('No challengeV'));
        }

        const data = qs_stringify({
            challengev: this.challengev,
            csrf_token: 'nulltoken',
            password: createHash('sha256').update(this.challengev).update(':').update(this.password).digest('hex'),
            showpw: '0',
        });

        const loginsalt = this.challengev.substr(0, 16);
        const sha256password = createHash('sha256').update(this.password).digest('hex');
        const derivedk = pbkdf2Sync(sha256password, loginsalt, 1000, 16, 'sha1').toString('hex');

        const options = {};
        Object.assign(options, this.options, {
            path: '/data/Login.json',
        });

        this._dataRequest(options, data,
            _reqStringCB((err?: Error, statusJSON?: string, res?: IncomingMessage) => {
            if (err) {
                cb(err);
                return;
            }

            this.loginStageTwoReply = statusJSON;

            try {
                const status = JSON5_parse(statusJSON!);

                // Result json uses "vartype" which is value, option or status.
                // Simply ignore this and put the other stuff into a new dict
                let loginState = 'unknown';
                for (const v of status) {
                    if (v.varid === 'login') {
                        loginState = v.varvalue;
                        break;
                    }
                }

                // are we happy?
                if (loginState !== 'success') {
                    return cb(new Error('Login was not successful'));
                }

                this.cookieHeaders = [
                    `${res!.headers['set-cookie']}`,
                    `derivedk=${derivedk}; path=/;`,
                    `challengev=${this.challengev}; path=/;`,
                ];

                this.sessionID = res!.headers['set-cookie']!.toString().match(/^.*(SessionID_R3=[^;]*);.*/)![1];
            } catch (e) {
                console.error(e, e.stack);
            }

            if (!this.sessionID) {
                return cb(new Error('Login failed'));
            }

            this.cookie = `challengev=${this.challengev}; ${this.sessionID}; derivedk=${derivedk}`;

            cb(undefined);
        }));
    }
}
