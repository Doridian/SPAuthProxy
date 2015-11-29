var config = require('./config');

var Speedport = require('./speedport');
var http = require('http');

var sp = new Speedport(config.speedport.host, config.speedport.password);

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
		if(BADURLS.indexOf(req.url.replace(/\?.*$/, '').toLowerCase()) >= 0) {
			res.writeHead(302, {
				Location: 'http://speedport.ip/html/content/overview/index.html'
			});
			res.end();
			return;
		}

		var headers = req.headers;
		headers['user-agent'] = 'Mozilla/5.0 (compatible; SPAuthProxy)';
		headers.cookie = null;

		sp.request({
			path: req.url,
			headers: headers
		}, (hasData ? data : null), function (err, spres) {
			if (err) {
				// Stuff
				res.writeHead(500);
				res.write('Internal SPAuthProxy error');
				res.end();
				return;
			}
			res.writeHead(spres.statusCode, spres.headers);
			spres.pipe(res);
		});
	});
});
listener.listen(config.proxy.port, config.proxy.host);