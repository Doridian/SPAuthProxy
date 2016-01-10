var _ = require('lodash');
var sjcl = require("sjcl");
var querystring = require('querystring');
var http = require('http');
var JSON5 = require('json5');
var pbkdf2 = require('pbkdf2');

http.globalAgent.keepAlive = true;
http.globalAgent.maxSockets = 3;

function _httpDummyCB(res) {
	res.on('data', function () { });
}

function Speedport (ip, password, options) {
	this.options = options || {};
	this.options.host = ip;

	this.password = password;

	this.challengev = null;
	this.sessionID = null;
	this.cookie = null;
	this.cookieHeaders = null;
}

Speedport.prototype._dataRequest = function (options, data, cb) {
	console.log('REQ ', options.path);
	options.headers = options.headers || {};
	options.method = options.method || 'POST';
	options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
	options.headers['Content-Length'] = Buffer.byteLength(data);
	var req = http.request(options, cb);
	req.write(data);
	req.end();	
};

Speedport.prototype.logout = function (cb) {
	var options = {};
	_.extend(options, this.options, {
		path: '/data/Login.json'
	});

	var data = querystring.stringify({
		csrf_token: "nulltoken",
		logout: "byby"
	});

	this._dataRequest(options, data, _httpDummyCB);

	this.challengev = null;
	this.sessionID = null;
	this.cookie = null;
	this.cookieHeaders = null;
};

/**
* Requests the password-challenge from the router. Calls handleChallenge() on success.
*/
Speedport.prototype.login = function (cb) {
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

	this._dataRequest(options, data, function(res) {
		res.setEncoding('utf8');
		var data = "";
		res.on('data', function (chunk) {
			data += chunk;
		});
		res.on('end', function () {
			// challengev -> will be sent as cookie 
			try {
				self.challengev = JSON5.parse(data)[1].varvalue;
			} catch(e) {
				console.error(e);
			}
			self._sendPassword(cb);          
		});
		res.on('error', cb);
	});
};

Speedport.prototype.request = function (options, data, cb) {
	if (!cb) {
		cb = data;
		data = null;
	}

	var cookie = this.cookie;
	if ( cookie && options.headers && options.headers.cookie) {
		cookie += '; ' + options.headers.cookie;
	}

	_.extend(options, this.options, {
		headers: {
			cookie: this.cookie
		}
	});

	var self = this;

	var req = http.request(options, function (res) {
		if (res.statusCode == 302 && res.headers.location.indexOf('/html/login/index.html') > 0) {
			return self.login(function (err) {
				if (err) {
					return cb(err);
				}
				return self.request(options, data, cb);
			});
		}
		if (self.cookieHeaders) {
			res.headers['set-cookie'] = self.cookieHeaders;
		}
		return cb(null, res);
	});

	if (data) {
		req.write(data);
	}

	req.end();
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

	this._dataRequest(options, data, function(res) {
		res.setEncoding('utf8');
		var statusJSON = "";
		res.on('data', function (chunk) {
			statusJSON += chunk;
		});
		res.on('end', function () {
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
				console.error(e);
			}

			if (!self.sessionID) {
				return cb('Login failed');
			}

			self.cookie = "challengev=" + self.challengev + "; " + self.sessionID + "; derivedk=" + derivedk;

			cb(null);
		});
		res.on('error', cb);
	});
};

module.exports = Speedport;
