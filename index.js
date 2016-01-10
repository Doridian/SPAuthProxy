var config = require('./config');

var Speedport = require('./speedport');
var http = require('http');

var sp = new Speedport(config.speedport.host, config.speedport.password);

var REQUESTID = 0;

var BADURLS = [
	'/',
	'/html',
	'/html/',
	'/html/login',
	'/html/login/',
	'/html/login/index.html',
	'/data/Login.json'
];

var listener = http.createServer(function (req, res) {
	req.setEncoding('utf8');
	//res.setEncoding('utf8');

	var hasData = false;
	var data = "";

	req.on('data', function (chunk) {
		data += chunk;
		hasData = true;
	});

	req.on('end', function () {
		var headers = req.headers;

		if(BADURLS.indexOf(req.url.replace(/\?.*$/, '').toLowerCase()) >= 0) {
			if (headers['x-requested-with'] === 'XMLHttpRequest') {
				res.writeHead(403);
				res.end();
				return;
			}
			res.writeHead(302, {
				Location: config.proxy.url + '/html/content/overview/index.html'
			});
			res.end();
			return;
		}
		
		headers['user-agent'] = 'Mozilla/5.0 (compatible; SPAuthProxy)';
		if (headers.referer) {
			headers.referer = headers.referer.replace(config.proxy.url, 'http://speedport.ip');
		}
		headers.host = 'speedport.ip';
		if (headers.origin) {
			headers.origin = headers.origin.replace(config.proxy.url, 'http://speedport.ip');
		}
		delete headers.cookie;
		delete headers.authorization;
		delete headers.connection;

		sp.request({
			path: req.url,
			method: req.method,
			headers: headers
		}, (hasData ? data : null), function (err, spres) {
			if(process.env.REQUEST_DEBUG === 'yes') {
				sp.request({
					path: '/data/heartbeat.json',
					method: 'GET'
				}, null, function (err, spres) {
					REQUESTID++;
					console.log(REQUESTID, req.url, ' = ');
					if (err) {
						console.log('SE: ' + err);
						return;
					}
					console.log('OK');
					spres.pipe(require('fs').createWriteStream('req_' + REQUESTID + '.txt'));
				});
			}
			if (err) {
				console.log(err);
				// Stuff
				res.writeHead(500);
				res.write('Internal SPAuthProxy error');
				res.end();
				return;
			}
			delete spres.connection;
			res.writeHead(spres.statusCode, spres.headers);
			spres.pipe(res);
		});
	});
});
listener.listen(config.proxy.port, config.proxy.host);
