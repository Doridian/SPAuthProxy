'use strict';

const querystring = require('querystring');
const http = require('http');
const JSON5 = require('json5');
const crypto = require('crypto');

http.globalAgent.keepAlive = true;
http.globalAgent.maxSockets = 3;

function _httpDummyCB (res) {
	res.on('data', () => { });
}

function _reqDummyCB (err, res) {
	if (err) {
		console.error(err, err.stack);
		return;
	}

	_httpDummyCB(res);
}

function _reqStringCB (cb, err, res) {
	if (err) {
		cb(err, null, res);
		return;
	}

	res.setEncoding('utf8');
	let data = '';
	res.on('data', (chunk) => {
		data += chunk;
	});
	res.on('end', () => {
		cb(null, data, res);
	});
	res.on('error', (err) => {
		cb(err, null, res);
	});
}

function Speedport (ip, password, options) {
	this.options = options || {};
	this.options.host = ip;

	this.password = password;

	this.challengev = null;
	this.sessionID = null;
	this.cookie = null;
	this.cookieHeaders = null;

	this._loginInProgress = false;
	this.loggedIn = 0;
	this._loginCallbacks = [];
	this.lastRequest = 0;

	this.loginStageOneReply = null;
	this.loginStageTwoReply = null;

	this.lastHeartbeat = JSON.stringify([
		{
			vartype:"status",
			varid:"loginstate",
			varvalue:"1"
		}
	]);

	setInterval(this._heartbeat.bind(this), 5000);
}

Speedport.prototype.request = function (options, data, cb) {
	if (options.loginTries === undefined) {
		options.loginTries = 3;
	}

	if (!cb) {
		cb = data;
		data = null;
	}

	this.lastRequest = Date.now();

	const httpOptions = options.http || {};

	let cookie = this.cookie;
	if (cookie && httpOptions.headers && httpOptions.headers.cookie) {
		cookie += `; ${httpOptions.headers.cookie}`;
	}

	Object.assign(httpOptions, this.options, {
		headers: {
			cookie: this.cookie
		}
	});

	const self = this;

	const req = http.request(httpOptions, (res) => {
		if (res.statusCode == 302 && res.headers.location.indexOf('/html/login/index.html') > 0) {
			_httpDummyCB(res);
			if (options.loginTries <= 0) {
				return cb('Not logged in or 404');
			}
			options.loginTries--;
			return self.login((err) => {
				if (err) {
					return cb(err);
				}
				return self.request(options, data, cb);
			});
		}
		if (self.cookieHeaders && !options.noCookies) {
			res.headers['set-cookie'] = self.cookieHeaders;
		}
		return cb(null, res);
	});

	req.on('error', cb);

	req.setTimeout(10000);

	if (data) {
		req.write(data);
	}

	req.end();
};

Speedport.prototype._heartbeat = function () {
	const self = this;

	this.request({
		http: {
			path: `/data/heartbeat.json?_time=${Date.now()}&_rand=${Math.floor(Math.random() * 900 + 100)}`,
			method: 'GET',
			noCookies: true
		}
	}, _reqStringCB.bind(this, (err, data) => {
		if (err) {
			console.error('Heartbeat error', err, err.stack);
			return;
		}

		self.lastHeartbeat = data;
	}));
};

Speedport.prototype._dataRequest = function (options, data, cb) {
	options.headers = options.headers || {};
	options.method = options.method || 'POST';
	if (data) {
		options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
		options.headers['Content-Length'] = Buffer.byteLength(data);
	}
	const req = http.request(options, (res) => {
		return cb(null, res);
	});
	req.on('error', cb);
	req.setTimeout(10000);
	if (data) {
		req.write(data);
	}
	req.end();
};

Speedport.prototype._loginCBMultiplexer = function (err) {
	this._loginInProgress = false;
	this.loggedIn = err ? 0 : Date.now();
	this._loginCallbacks.forEach((cb) => cb(err));
	this._loginCallbacks = [];
};

/**
* Requests the password-challenge from the router. Calls handleChallenge() on success.
*/
Speedport.prototype.login = function (cb) {
	if ((this.loggedIn + 60000) >= Date.now()) {
		cb(null);
		return;
	}

	if (this._loginInProgress) {
		this._loginCallbacks.push(cb);
		return;
	}

	this._loginInProgress = true;
	this._loginCallbacks = [cb];

	cb = this._loginCBMultiplexer.bind(this);

	this.challengev = null;
	this.sessionID = null;
	this.cookie = null;
	this.cookieHeaders = null;

	const options = {};
	Object.assign(options, this.options, {
		path: '/html/login/index.html',
		method: 'GET',
	});

	const self = this;

	this._dataRequest(options, undefined, _reqStringCB.bind(this, (err, data) => {
		if (err) {
			cb(err);
			return;
		}

		self.loginStageOneReply = data;

		// challengev -> will be sent as query var
		try {
			self.challengev = data.match(/var challenge = "([^"]+)";/)[1];
		} catch(e) {
			console.error(e, e.stack);
		}
		self._sendPassword(cb);
	}));
};

/** 
* Sends the hashed password to the router and acquires a session ID.
* Hashes challenge + password and send it back to speedport. 
*/
Speedport.prototype._sendPassword = function (cb) {
	if (!this.challengev) {
		return cb('No challengeV');
	}

	const data = querystring.stringify({
		password: crypto.createHash('sha256').update(this.challengev).update(':').update(this.password).digest('hex'),
		showpw: '0',
		csrf_token: 'nulltoken',
		challengev: this.challengev,
	});

	const loginsalt = this.challengev.substr(0, 16);
	const sha256password = crypto.createHash('sha256').update(this.password).digest('hex');
	const derivedk = crypto.pbkdf2Sync(sha256password, loginsalt, 1000, 16, 'sha1').toString('hex');

	const options = {};
	Object.assign(options, this.options, {
		path: '/data/Login.json'
	});

	const self = this;

	this._dataRequest(options, data, _reqStringCB.bind(this, (err, statusJSON, res) => {
		if (err) {
			cb(err);
			return;
		}

		self.loginStageTwoReply = statusJSON;

		try {
			const status = JSON5.parse(statusJSON);

			// Result json uses "vartype" which is value, option or status.
			// Simply ignore this and put the other stuff into a new dict
			const statusDict = {};
			status.forEach((v) => {
				statusDict[v.varid] = v.varvalue;
			});

			// are we happy?
			if (statusDict['login'] != 'success') {
				return cb(statusDict);
			}

			self.cookieHeaders = `${res.headers['set-cookie']}`;
			if (typeof self.cookieHeaders != 'array') {
				self.cookieHeaders = [self.cookieHeaders];
			}
			self.cookieHeaders.push(`derivedk=${derivedk}; path=/;`);
			self.cookieHeaders.push(`challengev=${self.challengev}; path=/;`);

			const sid = res.headers['set-cookie'].toString().match(/^.*(SessionID_R3=[^;]*);.*/);
			self.sessionID = sid[1];
		} catch(e) { 
			console.error(e, e.stack);
		}

		if (!self.sessionID) {
			return cb('Login failed');
		}

		self.cookie = `challengev=${self.challengev}; ${self.sessionID}; derivedk=${derivedk}`;

		cb(null);
	}));
};

module.exports = Speedport;
