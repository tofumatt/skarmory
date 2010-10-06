/*
	Copyright 2010 Matthew Riley MacPherson
	
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
	
	    http://www.apache.org/licenses/LICENSE-2.0
	
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

//      #   Skarmory -- It's Super Effective!   #
// 
//      ##    A JavaScript Twitter Library     ##
//      ##     for Appcelerator Titanium       ##
// 
//      ###            Version 0.1            ###

var Skarmory;

// Skarmory constructor
if (Skarmory == null) { Skarmory = function(instance_options) {
	var DEFAULTS = {
		accessTokenURL: 'https://api.twitter.com/oauth/access_token',
		autoAuthorize: false, // Automatically attempt to authorize user if
		                      // no access tokens exist. Can get messy.
		authorizeURL: 'https://api.twitter.com/oauth/authorize',
		requestTokenURL: 'https://api.twitter.com/oauth/request_token',
		responseFormat: 'json',
		restAPI: 'api.twitter.com/1/',
		signatureMethod: 'HMAC-SHA1', // Default to HMAC-SHA1 for Twitter
		transition: Ti.UI.iPhone.AnimationStyle.CURL_DOWN,
		useSSL: false
	},
	METHODS = { // Map of the Twitter REST API methods and their HTTP method types
		// Timeline resources
		'statuses/public_timeline':    'GET',
		'statuses/home_timeline':      'GET',
		'statuses/friends_timeline':   'GET',
		'statuses/user_timeline':      'GET',
		'statuses/mentions':           'GET',
		'statuses/retweeted_by_me':    'GET',
		'statuses/retweeted_to_me':    'GET',
		'statuses/retweets_of_me':     'GET',
		// Tweets resources
		'statuses/show/:id': 'GET',
		'statuses/update': 'POST',
		'statuses/destroy/:id': 'POST',
		'statuses/retweet/:id': 'GET',
		'statuses/retweets/:id': 'GET',
		'statuses/:id/retweeted_by': 'GET',
		'statuses/:id/retweeted_by/ids': 'GET',
		// User resources
		'users/show': 'GET',
		'users/lookup': 'GET',
		'users/search': 'GET',
		'users/suggestions': 'GET',
		'users/suggestions/twitter': 'GET',
		'users/profile_images/twitter': 'GET',
		'statuses/friends': 'GET',
		'statues/followers': 'GET',
		// Trends resources
		'trends': 'GET',
		'trends/current': 'GET',
		'trends/daily': 'GET',
		'trends/weekly': 'GET',
		// Local Trends resources
		'trends/available': 'GET',
		'trends/:woeid': 'GET',
	},
	options = DEFAULTS,
	page_change = 0,
	authorizedCallbacks,
	requestToken = '',
	requestTokenSecret = '',
	queue = [], // Queue of calls to perform -- we back these up if we aren't (yet) authorized
	view,
	webView,
	window;
	
	// Set each option passed to this instance
	for (var i in instance_options) {
		options[i] = instance_options[i];
	}
	
	// House our base OAuth properties that we'll use to
	// sign requests.
	var oauth = {
		consumerSecret: options.consumerSecret || DEFAULTS.consumerSecret,
		tokenSecret: ''
	};
	
	/*
		Authentication Methods
		
		Use these to determine whether or not this user
		is authorized and to authorize them via OAuth.
	*/
	
	// Authorize a user and run a callback when authorization succeeds/fails.
	// 
	// callbacks: {
	//     onSuccess: function() { // Run when OAuth authorization is successful },
	//     onFailure: function() { // Run when user denies app access },
	// }
	this.authorize = function(callbacks) {
		// show the authorization UI and call back the receive PIN function
		this.showAuthorizationWindow(options.authorizeURL + '?' + this.getRequestToken(options.requestTokenURL, [['oauth_callback', 'oob']]), callbacks);
	};
	
	// Return true if authorization tokens for this user are available.
	// This pretty much always returns true...
	this.isAuthorized = function() {
		return (options.accessKey && options.accessSecret);
	};
	
	// Get a request token from Twitter's API and return it.
	this.getRequestToken = function(url) {
		Ti.API.debug('Attempting to get OAuth Request Token from ' + url);
		
		oauth.tokenSecret = '';
		
		var request = {
			action: url,
			method: 'POST', // OAuth requests are always POST
			parameters: []
		};
		request.parameters.push(['oauth_consumer_key', options.consumerKey]);
		request.parameters.push(['oauth_signature_method', options.signatureMethod]);
		
		OAuth.setTimestampAndNonce(request);
		OAuth.SignatureMethod.sign(request, oauth);
		
		var httpClient = Ti.Network.createHTTPClient();
		httpClient.open('POST', url, false);
		httpClient.send(OAuth.getParameterMap(request.parameters));
		
		var responseParams = OAuth.getParameterMap(httpClient.responseText);
		requestToken = responseParams.oauth_token;
		requestTokenSecret = responseParams.oauth_token_secret;
		
		Ti.API.debug('Receieved OAuth Request Token from ' + url + "\nResponse was: " + httpClient.responseText);
		
		return httpClient.responseText;
	};
	
	// Display the Twitter OAuth authorization page inside a webView
	// and automatically grab the PIN code from a successful authorization.
	// Also provides an onFailure callback if the user denied access.
	this.showAuthorizationWindow = function(url, callbacks) {
		// Assign the callbacks to instance-available variables
		authorizedCallbacks = callbacks;
		
		window = Ti.UI.createWindow();
		view = Ti.UI.createView({
			height: 480,
			top: 0,
			transform: Ti.UI.create2DMatrix().scale(0),
			width: 320,
			zIndex: -1
		});
		window.open();

		webView = Ti.UI.createWebView({
			autoDetect: [Ti.UI.AUTODETECT_NONE],
			url: url
		});
		
		webView.addEventListener('load', _getAccessTokenFromWindow);
		view.add(webView);
		window.add(view);
		
		var animation = Ti.UI.createAnimation();
		animation.transform = Ti.UI.create2DMatrix();
		animation.duration = 500;
		view.animate(animation);
	};
	
	/*
		Twitter API Method Wrappers
		
		Provided to make API requests really JS-like. Provides methods
		that are similar in name to the API calls they relate to.
	*/
	this.timeline = function(method, args) {
		method = 'statuses/' + method;
		
		this._request(method, args);
	};
	
	this.tweets = function(method, args) {
		method = 'statuses/' + method;
		
		this._request(method, args);
	};
	
	this.user = function(method, args) {
		method = (_valueInArray(method, ['friends', 'followers'])) ? 'statuses/' + method : 'users/' + method;
		
		this._request(method, args);
	};
	
	/*
		Private API/methods
		
		Used internally by Starmory. Don't rely on these; they could change.
	*/
	this._request = function(method, args) {
		if (options.autoAuthorize && _valueInArray(null, [options.accessKey, options.accessSecret])) {
			Ti.API.debug("No access token found -- requesting one and queuing " + http_method + ' ' + url);
			
			_addToQueue(method, args);
			
			return;
		}
		
		var httpMethod = METHODS[method] || 'GET', // If not available in our known methods use GET
		params = args.params,
		// Do token replacement for the URL string
		url = ((options.useSSL) ? 'https://' : 'http://') + options.restAPI;
		
		// Do token replacement for any params found in the URL
		// i.e. /users/show/:id will replace :id and remove it
		// from the params.
		if (params) {
			for (var i in params) {
				Ti.API.debug(i + ' | ' + params[i]);
				if (method.match(':' + params[i][0])) {
					method = method.replace(':' + params[i][0], params[i][1]);
					delete params[i];
				}
			}
		}
		
		// Finish up the URL. Response format defaults to JSON;
		// it's fast to parse and the least data over the wire.
		url += method + '.' + options.responseFormat;
		
		Ti.API.info(httpMethod + ' ' + url);
		
		// Format our request according to what the OAuth library wants
		var request = {
			action: url,
			method: httpMethod,
			parameters: []
		};
		request.parameters.push(['oauth_consumer_key', options.consumerKey]);
		request.parameters.push(['oauth_signature_method', options.signatureMethod]);
		request.parameters.push(['oauth_token', options.accessKey]);
		
		for (var i in params) {
			request.parameters.push(params[i]);
		}
		
		OAuth.setTimestampAndNonce(request);
		OAuth.SignatureMethod.sign(request, oauth);
		
		var httpClient = Ti.Network.createHTTPClient(),
		parameterMap = OAuth.getParameterMap(request.parameters);
		
		// We have to add our params to the GET string if this is
		// a GET request; otherwise we just stick them into the
		// body of the POST.
		if (httpMethod == 'GET') {
			url += '?';
			if (parameterMap) {
				for (var i in parameterMap) {
					url += i + '=' + parameterMap[i] + '&';
				}
			}
			
			url = url.slice(0, -1);
			httpClient.open(httpMethod, url, false);
			httpClient.send();
		} else {
			httpClient.open(httpMethod, url, false);
			httpClient.send(parameterMap);
		}
		
		// If we got an OK (200) status then we run our success callback;
		// otherwise we run our failure one.
		if (httpClient.status == 200) {
			args.onSuccess(JSON.parse(httpClient.responseText));
		} else {
			args.onFailure(httpClient);
		}
		
		// If automatic authorization is enabled, we'll start open a
		// webView window and begin the OAuth access token nonsense.
		if (options.autoAuthorize && !this.isAuthorized()) {
			this.authorize({
				onSuccess: function() {
					alert('it worked!');
				},
				onFailure: function() {
					alert('it failed!');
				}
			});
		}
	};
	
	// Enable queuing of requests. Use this method to add
	// to this instance's internal queue.
	var _addToQueue = function(method, args) {
		queue.push([method, args]);
	};
	
	// Runs after a request token is obtained from the webView
	// launched on authorize(). Gets the access token for a
	// user and runs callbacks.
	var _getAccessTokenFromWindow = function(page) {
		var doc = Ti.XML.parseString(page.source.html),
		nodeList = doc.getElementsByTagName('div'),
		success = false;
		
		// Iterating down is usually faster, but I'm not sure what
		// Titatium outputs. TODO: See if this is a performance hit/gain.
		for (var i = nodeList.length - 1; i > 0; i--) {
			var node = nodeList.item(i),
			id = node.attributes.getNamedItem('id');
			
			if (id && id.nodeValue == 'oauth_pin') {
				Ti.API.debug('Attempting to get OAuth Access Token from ' + options.accessTokenURL);
				
				// Use the PIN from the page to get our request token.
				var pin = node.text;
				oauth.tokenSecret = requestTokenSecret;
				
				var request = {
					action: options.accessTokenURL,
					method: 'POST', // OAuth requests are always POST
					parameters: []
				};
				request.parameters.push(['oauth_token', requestToken]);
				request.parameters.push(['oauth_verifier', pin]);
				
				OAuth.setTimestampAndNonce(request);
				OAuth.SignatureMethod.sign(request, oauth);
				
				var parameterMap = OAuth.getParameterMap(request.parameters);
				for (var p in parameterMap) {
					Ti.API.debug(p + ': ' + parameterMap[p]);
				}
				
				var httpClient = Ti.Network.createHTTPClient();
				httpClient.open('POST', options.accessTokenURL, false);
				httpClient.send(parameterMap);
				
				var responseParams = OAuth.getParameterMap(httpClient.responseText);
				options.accessKey = responseParams.oauth_token;
				options.accessSecret = responseParams.oauth_token_secret;
				
				success = true;
				authorizedCallbacks.onSuccess();
				
				Ti.API.debug('Receieved OAuth Access Token from ' + options.accessTokenURL + "\nResponse was: " + httpClient.responseText);
				
				id = null;
				node = null;
				
				break;
			}
		}
		
		// Used to disable page state change on first request, so
		// we don't close the window as soon as it loads.
		if (page_change) {
			// Either the PIN was obtained or the user denied the
			// request; either way we close this window.
			page_change = 0;
			_closeAuthorizationWindow();
			if (!success) {
				authorizedCallbacks.onFailure();
			}
		} else {
			page_change = 1;
		}
	};

	// Remove the authorization window and callbacks/event
	// listeners associated with it.
	var _closeAuthorizationWindow = function() {
		try {
			webView.removeEventListener('load', _getAccessTokenFromWindow);
			window.hide();
		} catch(e) {
			Ti.API.debug('Authorization window not found or could not be removed. Maybe it was already removed? Ignoring...');
		}
	};
	
	// Iterate through this instance's internal queue and run each request.
	var _processQueue = function() {
		while ((q = queue.shift()) != null) {
			Ti.API.debug('Processing item in queue: ' + q[0]);
			this._request(q[0], q[1]);
		}
		
		Ti.API.debug('Queue processed.');
	};
	
	// Utility function to emulate an in_array() check.
	var _valueInArray = function(value, array) {
		var i = array.length;
		
		while (i--) {
			if (array[i] === value) {
				return true;
			}
		}
		
		return false;
	};
}};

// Utility function for making a single request to
// the REST API. Requires valid OAuth credentials
// to be passed into args.options.
Skarmory.request = function(method, args) {
	var options = (args.options) ? args.options : {},
	instance = new Skarmory(options);
	
	delete args.options;
	
	instance._request(method, args);
};

// Skarmory Static Public Methods
Skarmory.setDefaults = function(options) {
	for (var i in options) {
		this.DEFAULTS = options.i
	}
};

// Skarmory.demo = function(tweet_text) {
// 	var s = new Skarmory({
// 		consumerKey: FALCON_CONFIG['consumer_key'],
// 		consumerSecret: FALCON_CONFIG['consumer_secret']
// 	});
// 	// s._request('statuses/update', [['status', "Hello worlds"]], {
// 	//	onSuccess: function(response) {
// 	//		alert(JSON.parse(response.responseText).message);
// 	//	}
// 	// });
// 	s._request('statuses/show/:id', {
// 		params: [['id', 26202194952]],
// 		onSuccess: function(response) {
// 			// alert(JSON.parse(response.responseText).text);
// 		}
// 	});
// }
