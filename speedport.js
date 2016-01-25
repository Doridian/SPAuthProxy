var _ = require('lodash');
var sjcl = require("sjcl");
var querystring = require('querystring');
var http = require('http');
var JSON5 = require('json5');
var pbkdf2 = require('pbkdf2');

http.globalAgent.keepAlive = true;
http.globalAgent.maxSockets = 3;

function _httpDummyCB (res) {
	res.on('data', function () { });
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
		cb(err);
		return;
	}

	res.setEncoding('utf8');
	var data = '';
	res.on('data', function (chunk) {
		data += chunk;
	});
	res.on('end', function () {
		cb(null, data);
	});
	res.on('error', function (err) {
		cb(err);
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

	this._lastHeartbeat = JSON.stringify([
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

	var httpOptions = options.http || {};

	var cookie = this.cookie;
	if ( cookie && httpOptions.headers && httpOptions.headers.cookie) {
		cookie += '; ' + httpOptions.headers.cookie;
	}

	_.extend(httpOptions, this.options, {
		headers: {
			cookie: this.cookie
		}
	});

	var self = this;

	var req = http.request(httpOptions, function (res) {
		if (res.statusCode == 302 && res.headers.location.indexOf('/html/login/index.html') > 0) {
			_httpDummyCB(res);
			if (options.loginTries <= 0) {
				return cb('Not logged in or 404');
			}
			options.loginTries--;
			return self.login(function (err) {
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

	req.on('error', function(err) {
		cb(err);
	});

	req.setTimeout(10000);

	if (data) {
		req.write(data);
	}

	req.end();
};

Speedport.prototype._heartbeat = function () {
	var self = this;

	this.request({
		http: {
			path: '/data/heartbeat.json?_time=' + Date.now() + '&_rand=' + Math.floor(Math.random() * 900 + 100),
			method: 'GET',
			noCookies: true
		}
	}, _reqStringCB.bind(this, function (err, data) {
		if (err) {
			console.error('Heartbeat error', err, err.stack);
			return;
		}

		self._lastHeartbeat = data;
	}));
};

Speedport.prototype.getHeartbeat = function () {
	return this._lastHeartbeat;
};

Speedport.prototype._dataRequest = function (options, data, cb) {
	options.headers = options.headers || {};
	options.method = options.method || 'POST';
	options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
	options.headers['Content-Length'] = Buffer.byteLength(data);
	var req = http.request(options, function (req) {
		return cb(null, req);
	});
	req.on('error', function(err) {
		console.error('DRE', options, err);
		cb(err);
	});
	req.setTimeout(10000);
	req.write(data);
	req.end();
};

Speedport.prototype._loginCBMultiplexer = function(err) {
	this._loginInProgress = false;
	this.loggedIn = err ? 0 : Date.now();
	this._loginCallbacks.forEach(function (cb) {
		cb(err);
	});
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

	var data = querystring.stringify({
		csrf_token: "nulltoken",
		showpw: "0",
		challengev: "null"
	});

	var options = {};
	_.extend(options, this.options, {
		path: '/data/Login.json'
	});

	var self = this;

	this._dataRequest(options, data, _reqStringCB.bind(this, function (err, data) {
		if (err) {
			cb(err);
			return;
		}

		// challengev -> will be sent as cookie 
		try {
			self.challengev = JSON5.parse(data)[1].varvalue;
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

	var data = querystring.stringify({
		password: sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(this.challengev + ":" + this.password)),
		showpw: "0",
		csrf_token: "nulltoken"
	});

	var loginsalt = this.challengev.substr(0, 16);
	var sha256password = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(this.password));
	var derivedk = pbkdf2.pbkdf2Sync(sha256password, loginsalt, 1000, 16).toString('hex');

	var options = {};
	_.assign(options, this.options, {
		path: '/data/Login.json'
	});

	var self = this;

	this._dataRequest(options, data, _reqStringCB.bind(this, function (err, statusJSON) {
		if (err) {
			cb(err);
			return;
		}

		try {
			var status = JSON5.parse(statusJSON);

			// Result json uses "vartype" which is value, option or status.
			// Simply ignore this and put the other stuff into a new dict
			var statusDict = {};
			status.forEach(function (v) {
				statusDict[v.varid] = v.varvalue;
			});

			// are we happy?
			if (statusDict['login'] != 'success') {
				return cb(statusDict);
			}

			self.cookieHeaders = "" + res.headers['set-cookie'];
			if (typeof self.cookieHeaders != "array") {
				self.cookieHeaders = [self.cookieHeaders];
			}
			self.cookieHeaders.push("derivedk=" + derivedk + "; path=/;");
			self.cookieHeaders.push("challengev=" + self.challengev + "; path=/;");

			var sid = res.headers['set-cookie'].toString().match(/^.*(SessionID_R3=[^;]*);.*/);
			self.sessionID = sid[1];
		} catch(e) { 
			console.error(e, e.stack);
		}

		if (!self.sessionID) {
			return cb('Login failed');
		}

		self.cookie = "challengev=" + self.challengev + "; " + self.sessionID + "; derivedk=" + derivedk;

		cb(null);
	}));
};

module.exports = Speedport;
