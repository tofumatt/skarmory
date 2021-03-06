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
		closeTransition: Ti.UI.iPhone.AnimationStyle.CURL_UP,
		openTransition: Ti.UI.iPhone.AnimationStyle.CURL_DOWN,
		requestTokenURL: 'https://api.twitter.com/oauth/request_token',
		responseFormat: 'json',
		restAPI: 'api.twitter.com/1/',
		signatureMethod: 'HMAC-SHA1', // Default to HMAC-SHA1 for Twitter
		useSSL: false
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
		tokenSecret: options.accessSecret || ''
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
			height: Titanium.Platform.displayCaps.platformHeight, // 480,
			top: 0,
			transform: Ti.UI.create2DMatrix().scale(0),
			width: Titanium.Platform.displayCaps.platformWidth, // 320,
			zIndex: -1
		});
		window.open({transition: options.openTransition});

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
		
		All params listed in JSDoc format in this section are to be
		provided in the params property of args (unless there's a single,
		required argument which is available as the first argument with
		the args object being second).
		
		i.e. since_id and count are listed as params for home_timeline().
		Use them as such:
		    skarymoryInstance.home_timeline({
		        params: [['since_id', 50], ['count', 12]]
		    })
		
		For methods that have a single, required parameter, you can
		supply that param as the first argument to the method, with
		the args object functioning as expected, just as the second
		param.
		
		i.e. status is required by update(). Use like this:
		    skarmoryInstance.update('I love tweeting!', {
		        params: [['in_reply_to', 43]]
		    })
		
		If a method has more than one required parameter you'll have to
		just put them in the params array.
	*/
	
	/*
	 * Timeline Resources
	 */
	
	/**
	 * Get the 20 most recent, public tweets (includes retweets)
	 *
	 * The public timeline is cached every 60 seconds; don't bother requesting
	 * it more often than that.
	 *
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.public_timeline = function(args) {
		this._request('statuses/public_timeline', args);
	};
	
	/**
	 * Get the 20 most recent tweets by the authenticated user and their followers (includes retweets)
	 *
	 * This is the same timeline used by twitter.com and is what most users
	 * think of as the "default" Twitter timeline view. This method includes
	 * native retweets.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.home_timeline = function(args) {
		this._request('statuses/home_timeline', args);
	};
	
	/**
	 * Get the 20 most recent tweets by the authenticated user and their followers (retweets-optional)
	 *
	 * This is the same timeline used by twitter.com and is what most users
	 * think of as the "default" Twitter timeline view. This method includes
	 * native retweets.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_rts      Include retweets in the results
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.friends_timeline = function(args) {
		this._request('statuses/friends_timeline', args);
	};
	
	/**
	 * Get the 20 most recent tweets posted by a user (retweets-optional)
	 *
	 * By default, returns a list of tweets from the authenticating user,
	 * but any user's timeline can be obtained by using user_id/screen_name.
	 * This is typically what a user profile timeline looks like.
	 *
	 * @param {Number}  user_id          Get the timeline of the user with this id
	 * @param {Number}  screen_name      Get the timeline of the user with this screen name
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_rts      Include retweets in the results
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.user_timeline = function(args) {
		this._request('statuses/user_timeline', args);
	};
	
	/**
	 * Get the 20 most recent mentions for the authenticated user
	 *
	 * If you want to include retweets, be sure to set the include_rts params.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_rts      Include retweets in the results
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.mentions = function(args) {
		this._request('statuses/mentions', args);
	};
	
	/**
	 * Get the 20 most recent retweets by authenticated user
	 *
	 * Returns tweets that the authenticated user has retweeted.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweeted_by_me = function(args) {
		this._request('statuses/retweeted_by_me', args);
	};
	
	/**
	 * Get the 20 most recent retweets posted by the authenticated user's followers
	 *
	 * Returns tweets that the authenticated user's followers have retweeted.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweeted_to_me = function(args) {
		this._request('statuses/retweeted_to_me', args);
	};
	
	/**
	 * Get the 20 most recent retweets of authenticated user by other users
	 *
	 * Returns retweets of the authenticated user by other users.
	 *
	 * @param {Number}  since_id         Only get tweets with a since_id greater than this value
	 * @param {Number}  max_id           Only get tweets with a since_id less than this value
	 * @param {Number}  count            Get a specified number of tweets (max 200)
	 * @param {Number}  page             Page of tweets to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweets_of_me = function(args) {
		this._request('statuses/retweets_of_me', args);
	};
	
	/* ************************************************************* */
	
	/*
	 * Tweets Resources
	 */
	
	/**
	 * Get a tweet by ID
	 *
	 * @param {Number}  id               ID of tweet to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.status = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/show/:id', args);
	};
	
	/**
	 * Post a new tweet
	 *
	 * Post a new tweet with the text in `status` parameter. Tweet must be 140
	 * characters or less, or the posting will fail.
	 *
	 * @param {String}   status                Tweet content -- 140 characters or less!
	 * @param {Number}   in_reply_to_status_id ID this status is in reply to
	 * @param {Number}   lat                   Latitude related to this tweet (i.e. where it was made)
	 * @param {Number}   long                  Longitude related to this tweet (i.e. where it was made)
	 * @param {Number}   place_id              ID of a place (get this ID from reverse_geocode())
	 * @param {Boolean}  display_coordinates   Set to true to put a pin on the exact location of this tweet
	 * @param {Boolean}  trim_user             Return a tweet's user's id, not the entire user object
	 * @param {Boolean}  include_entities      Include tweet entities inside each tweet
	 * @see #reverse_geocode
	 * @author Matthew Riley MacPherson
	 */
	this.update = function(status, args) {
		args = _pushIntoParams(args, ['status', status]);
		this._request('statuses/update', args, 'POST');
	};
	
	/**
	 * Deete a tweet by ID
	 *
	 * Delete a tweet by the authenticated user.
	 *
	 * @param {Number}  id               ID of the tweet to delete
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.destroy = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/delete/:id', args, 'POST');
	};
	
	/**
	 * Retweet a tweet by ID
	 *
	 * Retweet a tweet based on id.
	 *
	 * @param {Number}  id               ID of the tweet to retweet
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweet = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/retweet/:id', args, 'POST');
	};
	
	/**
	 * Get the first 100 retweets of a given tweet
	 *
	 * Get the retweets of a tweet by id.
	 *
	 * @param {Number}  id               ID of the tweet to retweet
	 * @param {Number}  count            Get a specified number of retweets (max 100)
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweets = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/retweet/:id', args);
	};
	
	/**
	 * Get the first 100 users who retweeted a tweet
	 *
	 * Get the user objects of users who retweeted a tweet by id.
	 *
	 * @param {Number}  id               ID of the tweet to look for retweeting users of
	 * @param {Number}  count            Get a specified number of retweets (max 100)
	 * @param {Number}  page             Page of users to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweeted_by = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/:id/retweeted_by', args);
	};
	
	/**
	 * Get the first 100 user ids of users who retweeted a tweet
	 *
	 * Get the user ids of users who retweeted a tweet by id.
	 *
	 * @param {Number}  id               ID of the tweet to look for retweeting users of
	 * @param {Number}  count            Get a specified number of retweets (max 100)
	 * @param {Number}  page             Page of users to get
	 * @param {Boolean} trim_user        Return a tweet's user's id, not the entire user object
	 * @param {Boolean} include_entities Include tweet entities inside each tweet
	 * @author Matthew Riley MacPherson
	 */
	this.retweeted_by_ids = function(id, args) {
		args = _pushIntoParams(args, ['id', id]);
		this._request('statuses/:id/retweeted_by/ids', args);
	};
	
	/*
		Private API/methods
		
		Used internally by Starmory. Don't rely on these; they could change.
	*/
	this._request = function(method, args, httpMethod) {
		if (!httpMethod)
			httpMethod = 'GET';
		
		if (options.autoAuthorize && _valueInArray(null, [options.accessKey, options.accessSecret])) {
			Ti.API.debug("No access token found -- requesting one and queuing " + http_method + ' ' + url);
			
			_addToQueue(method, args, httpMethod);
			
			return;
		}
		
		var params = args.params,
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
		
		alert(httpClient.status);
		
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
					alert(httpClient.status);
				},
				onFailure: function() {
					alert(httpClient.status);
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
			window.close({transition: options.closeTransition});
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
	
	// Push a value into the params array of an argument list,
	// even if that list is currently empty/undefined.
	var _pushIntoParams = function(args, param) {
		if (args.params)
			args.params.push(param);
		else
			args.params = [param];
		
		return args;
	}
	
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
