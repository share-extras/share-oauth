/**
 * Copyright (C) 2010-2011 Share Extras contributors.
 */

/**
* Extras root namespace.
* 
* @namespace Extras
*/
if (typeof Extras == "undefined" || !Extras)
{
   var Extras = {};
}

/**
 * OAuth service helper. Allows authentication to OAuth 1.0(a) services in the 
 * client-side layer.
 * 
 * TODO Improve exception handling
 * TODO Support query-string-based authentication as well as header-based
 * 
 * @class OAuthHelper
 * @namespace Extras
 * @author Will Abson
 */
(function()
{
   /**
    * Alfresco Slingshot aliases
    */
   var $html = Alfresco.util.encodeHTML,
      $combine = Alfresco.util.combinePaths;

   /**
    * Preferences
    */
   var PREFS_BASE = "org.alfresco.share.oauth.",
       PREF_DATA = "data";

   /**
    * Dashboard OAuthHelper constructor.
    * 
    * @return {OAuthHelper} The new helper instance
    * @constructor
    */
   Extras.OAuthHelper = function OAuthHelper_constructor()
   {
      return this;
   };

   /**
    * Add class implementation
    */
   Extras.OAuthHelper.prototype =
   {
       /**
        * Object container for initialization options
        *
        * @property options
        * @type object
        */
       options:
       {
           /**
            * Unique ID for the OAuth provider, for storing token data against
            * 
            * @property providerId
            * @type string
            * @default ""
            */
           providerId: "",

           /**
            * Name of the Surf endpoint used to access the remote API protected by OAuth. Must be configured in the Surf layer.
            * 
            * @property endpointId
            * @type string
            * @default ""
            */
           endpointId: "",

           /**
            * End-point relative path to the request token path resource
            * 
            * @property requestTokenPath
            * @type string
            * @default "/oauth/request_token"
            */
           requestTokenPath: "/oauth/request_token",

           /**
            * End-point relative path to the access token path resource
            * 
            * @property accessTokenPath
            * @type string
            * @default "/oauth/access_token"
            */
           accessTokenPath: "/oauth/access_token",

           /**
            * URI to redirect the user back to after a verification code has been received. Setting to null
            * means this will not be set when calling request_token.
            * 
            * @property requestTokenCallbackUri
            * @type string
            * @default null
            */
           requestTokenCallbackUri: null,

           /**
            * Whether or not to add timestamp values to OAuth requests, rather than letting the connector add
            * these
            * 
            * @property addTimestamps
            * @type boolean
            * @default true
            */
           addTimestamps: true
       },
      
      /**
       * OAuth authentication data, received when an access token request was granted. 
       * 
       * oauth_token and oauth_token_secret are required properties but others may also be present.
       * 
       * @property authData
       * @type object
       * @default {}
       */
      authData: {},
      
      /**
       * Set multiple initialization options at once.
       * 
       * @method setOptions
       * @param obj {object} Object literal specifying a set of options
       * @return {object} returns 'this' for method chaining
       */
      setOptions: function OAuth_setOptions(obj)
      {
          this.options = YAHOO.lang.merge(this.options, obj);
          return this;
      },
      
      /**
       * Set up the OAuth helper. Connects to the user storage and populates the access token
       * and secret, if they exist.
       * 
       * @method init
       * @param obj {object}  Object literal defining two handler functions, 'successCallback' and 'failureCallback'.
       *    Each handler is another object defining 'fn' and 'scope' properties.
       */
      init: function OAuth_init(obj)
      {
          // Preferences service
          this.preferences = new Alfresco.service.Preferences();
          this.loadCredentials(obj);
      },
      
      /**
       * Boolean indicating whether or not the user has a valid OAuth token
       * 
       * @method hasToken
       * @return {boolean} True if a valid token exists, false otherwise
       */
      hasToken: function OAuth_hasToken()
      {
          // TODO check that the token is valid as well as that it just exists?
          return this.authData.oauth_token != null && this.authData.oauth_token != "" && 
              this.authData.oauth_token_secret != null && this.authData.oauth_token_secret != "";
      },
      
      /**
       * Boolean indicating whether or not the user has a valid OAuth token which has been authorized
       * 
       * @method isAuthorized
       * @return {boolean} True if a valid token exists and it has been authorized by the user
       */
      isAuthorized: function OAuth_isAuthorized()
      {
          // TODO check that the token is valid as well as that it just exists?
          return this.authData.oauth_token != null && this.authData.oauth_token != "" && 
              this.authData.oauth_token_secret != null && this.authData.oauth_token_secret != ""
              && !this.authData.oauth_callback_confirmed;
      },
      
      /**
       * Request a request token and request secret by passing the consumer key
       * 
       * @method requestToken
       * @param {object} Object literal defining sucessHandler, failureCallback, requestTokenHandler functions, to be passed
       *    to the handlers
       */
      requestToken: function OAuth_requestToken(obj)
      {
          var requestTokenUrl = this._buildUrl(this.options.requestTokenPath),
              authParams = {};
          
          // Add a callback if needed
          if (this.options.requestTokenCallbackUri != null && !authParams.oauth_callback)
          {
              authParams.oauth_callback = this.options.requestTokenCallbackUri;
          }
          
          var authStr = this._buildAuthData(authParams);
          
          var callback = 
          {
              success: this.requestTokenSuccess,
              failure: this.requestTokenFailure,
              scope: this,
              argument: {
                  successCallback: obj.successCallback,
                  failureCallback: obj.failureCallback,
                  requestTokenHandler: obj.requestTokenHandler
              }
          };
          
          YAHOO.util.Connect.initHeader("X-OAuth-Data", authStr);
          YAHOO.util.Connect.asyncRequest("POST", requestTokenUrl, callback, "");
      },
      
      /**
       * Success handler for request token
       * 
       * @method requestTokenSuccess
       * @param o {object} Server response object
       */
      requestTokenSuccess: function OAuth_requestTokenSuccess(o)
      {
          YAHOO.util.Connect.resetDefaultHeaders();
          // TODO Check resp code is 200
          var respData = this._unpackAuthData(o.responseText);

          if (respData.oauth_token && respData.oauth_token_secret)
          {
              this.authData = respData;
              
              var callbacks =  {
                  successCallback: o.argument.successCallback,
                  failureCallback: o.argument.failureCallback
              };
              
              // Call the request token handler which should forward the user to the authorization page
              var requestTokenHandler = o.argument.requestTokenHandler;
              if (requestTokenHandler && requestTokenHandler.fn && typeof (requestTokenHandler.fn) == "function")
              {
                  var me = this;
                  requestTokenHandler.fn.call(requestTokenHandler.scope, {
                      authToken: respData.oauth_token,
                      authParams: respData,
                      onComplete: function OAuth_onComplete(verifier) // The callback function should invoke this in turn when the user has input the code
                      {
                          // Call requestAccessToken with the correct scope, using a closure for 'this'
                          me.requestAccessToken.apply(me, [respData, verifier, callbacks]);
                      }
                  });
              }
          }
          else
          {
              Alfresco.util.PopupManager.displayMessage({
                  text: "Request token fail. Required parameters not sent."
              });
          }
      },
      
      /**
       * Failure handler for request token
       * 
       * @method requestTokenFailure
       * @param o {object} Server response object
       */
      requestTokenFailure: function OAuth_requestTokenFailure(o)
      {
          Alfresco.util.PopupManager.displayMessage({
              text: "Request token fail"
          });
          YAHOO.util.Connect.resetDefaultHeaders();
      },
      
      /**
       * Request a permanent access token. The temporary request token is exchanged for an access token, which
       * is then stored.
       * 
       * @method requestAccessToken
       * @param data {object} Object containing request token details, including token and secret
       * @param verifier {string} OAuth verifier code
       * @param callbacks {object} Object literal defining two handler functions, 'successCallback' and 'failureCallback'.
       */
      requestAccessToken: function OAuth_requestAccessToken(data, verifier, callbacks)
      {
          var requestTokenUrl = this._buildUrl(this.options.accessTokenPath),
              authParams = { // just select the params we need
                  oauth_token: data.oauth_token,
                  oauth_verifier: verifier,
                  oauth_token_secret: data.oauth_token_secret
              };
          
          var authStr = this._buildAuthData(authParams);

          var callback = 
          {
              success: this.requestAccessTokenSuccess,
              failure: this.requestAccessTokenFailure,
              scope: this,
              argument: {
                  successCallback: callbacks.successCallback,
                  failureCallback: callbacks.failureCallback
              }
          };
          
          YAHOO.util.Connect.initHeader("X-OAuth-Data", authStr);
          YAHOO.util.Connect.asyncRequest("POST", requestTokenUrl, callback, "");
      },
      
      /**
       * Success handler for request permanent access token
       * 
       * @method requestAccessTokenSuccess
       * @param o {object} Server response object
       */
      requestAccessTokenSuccess: function OAuth_requestAccessTokenSuccess(o)
      {
          YAHOO.util.Connect.resetDefaultHeaders();
          // TODO Check resp code is 200
          var respData = this._unpackAuthData(o.responseText);
          if (respData.oauth_token && respData.oauth_token_secret)
          {
              this.authData = respData;
              this.saveCredentials();
              
              // Call the success callback
              var successCallback = o.argument.successCallback;
              if (successCallback && successCallback.fn && typeof (successCallback.fn) == "function")
              {
                  successCallback.fn.call(successCallback.scope);
              }
          }
          else
          {
              Alfresco.util.PopupManager.displayMessage({
                  text: "Request access token fail. Required parameters not sent."
              });
          }
      },
      
      /**
       * Failure handler for request permanent access token
       * 
       * @method requestAccessTokenFailure
       * @param o {object} Server response object
       */
      requestAccessTokenFailure: function OAuth_requestAccessTokenFailure(o)
      {
          YAHOO.util.Connect.resetDefaultHeaders();
          Alfresco.util.PopupManager.displayMessage({
              text: "Request access token fail"
          });
      },
      
      /**
       * Clear the cached access credentials
       * 
       * @method clearCredentials
       */
      clearCredentials: function OAuth_clearCredentials()
      {
          this.authData = "";
      },

      /**
       * Load the access credentials from persistant user-specific storage. Currently the preferences
       * service is used as storage.
       * 
       * @method loadCredentials
       * @param obj {object}  Object literal defining two handler functions, 'successCallback' and 'failureCallback'.
       *    Each handler is another object defining 'fn' and 'scope' properties.
       */
      loadCredentials: function OAuth_saveCredentials(obj)
      {
          this.preferences.request(PREFS_BASE + this.options.providerId + "." + PREF_DATA, {
              successCallback: {
                  fn: function (p_resp) {
                      var json = p_resp.json;
                      if (json != null && json.org != null)
                      {
                          var credentials = json.org.alfresco.share.oauth[this.options.providerId].data;
                          if (credentials != null && credentials.length > 0)
                          {
                              var authData = this._unpackAuthData(credentials);
                              // Ensure both required tokens have been found
                              if (!YAHOO.lang.isUndefined(authData.oauth_token) && !YAHOO.lang.isUndefined(authData.oauth_token_secret))
                              {
                                  this.authData = authData;
                              }
                          }
                      }

                      // Call the success callback
                      var successCallback =  obj ? obj.successCallback : null;
                      if (successCallback && successCallback.fn && typeof (successCallback.fn) == "function")
                      {
                          successCallback.fn.call(successCallback.scope, this);
                      }
                  },
                  scope: this
              },
              failureCallback: {
                  fn: function (p_resp) {
                      // Call the failure callback
                      var failureCallback = obj ? obj.failureCallback : null;
                      if (failureCallback && failureCallback.fn && typeof (failureCallback.fn) == "function")
                      {
                          failureCallback.fn.call(failureCallback.scope);
                      }
                  },
                  scope: this
              }
          });
      },

      /**
       * Save the access credentials to persistant, user-specific storage. Currently the preferences
       * service is used as storage.
       * 
       * @method saveCredentials
       * @param obj {object}  Object literal defining two handler functions, 'successCallback' and 'failureCallback'.
       *    Each handler is another object defining 'fn' and 'scope' properties.
       */
      saveCredentials: function OAuth_saveCredentials(obj)
      {
          this.preferences.set(PREFS_BASE + this.options.providerId + "." + PREF_DATA, this._packAuthData(this.authData), {
              successCallback: {
                  fn: function (p_resp)
                  {
                      // Call the success callback
                      var successCallback = obj ? obj.successCallback : null;
                      if (successCallback && successCallback.fn && typeof (successCallback.fn) == "function")
                      {
                          successCallback.fn.call(successCallback.scope);
                      }
                  },
                  scope: this
              },
              failureCallback: {
                  fn: function (p_resp) {
                      // Call the failure callback
                      var failureCallback = obj ?  obj.failureCallback: null;
                      if (failureCallback && failureCallback.fn && typeof (failureCallback.fn) == "function")
                      {
                          failureCallback.fn.call(failureCallback.scope);
                      }
                  },
                  scope: this
              }
          });
      },
      
      /**
       * Make a request to the API, signing using the OAuth credentials as necessary. Should be compatible with Alfresco.util.Ajax.request()
       * 
       * @method request
       * @param obj {object} Object literal defining two handler functions, 'success' and 'failure', plus a 'scope' object.
       * The object must also define a 'url' property, indicating the url path to connect to, plus optionally a 'method' 
       * property (default is 'GET') and a 'data' property for POST requests.
       */
      request: function OAuth_request(obj)
      {
          var requestUrl = this._buildUrl(obj.url),
              authStr = this._buildAuthData();
          
          obj.method = obj.method || Alfresco.util.Ajax.GET;
          
          var objToParamString = function(o, spaceChar)
          {
              var params = "", first = true, attr;
              spaceChar = spaceChar;
              for (attr in o)
              {
                  if (o.hasOwnProperty(attr))
                  {
                      if (first)
                      {
                          first = false;
                      }
                      else
                      {
                          params += "&";
                      }
                      params += encodeURIComponent(attr) + "=" + 
                          (YAHOO.lang.isUndefined(spaceChar) ? encodeURIComponent(o[attr]) : encodeURIComponent("" + o[attr]).
                                  replace("%20", spaceChar, "g").replace(/!/g, '%21').replace(/'/g, '%27').replace(/\(/g, '%28').  
                                  replace(/\)/g, '%29').replace(/\*/g, '%2A'));
                  }
              }
              return params;
          }
          
          if (YAHOO.lang.isObject(obj.dataObj))
          {
              if (obj.method.toUpperCase() == Alfresco.util.Ajax.GET)
              {
                  requestUrl = requestUrl += (requestUrl.indexOf("?") == -1 ? "?" : "&") + objToParamString(obj.dataObj, true);
              }
              else
              {
                  var reqType = obj.requestContentType || Alfresco.util.Ajax.FORM;
                  if (!YAHOO.lang.isValue(obj.dataStr))
                  {
                      if ((new RegExp("^\s*" + Alfresco.util.Ajax.FORM)).test(reqType))
                      {
                          obj.dataStr = objToParamString(obj.dataObj, "+");
                      }
                      else if ((new RegExp("^\s*" + Alfresco.util.Ajax.JSON)).test(reqType))
                      {
                          obj.dataStr = YAHOO.lang.JSON.stringify(c.dataObj || {});
                      }
                  }
              }
          }

          var callback = 
          {
              success: function OAuth_onRequestSuccess(o) {
                  var cbObj = o;
                  var contentType = o.getResponseHeader["Content-Type"] ||
                  o.getResponseHeader["content-type"];
                  // User provided a custom successCallback
                  var json = null;
                  if ((new RegExp("^\s*" + Alfresco.util.Ajax.JSON)).test(contentType))
                  {
                      cbObj.json = Alfresco.util.parseJSON(o.responseText);
                  }
                  obj.successCallback.fn.call(obj.successCallback.scope, cbObj);
              },
              failure: function OAuth_onRequestFailure(o) {
                  obj.failureCallback.fn.call(obj.failureCallback.scope, o);
              },
              scope: obj.scope
          };

          YAHOO.util.Connect.initHeader("X-OAuth-Data", authStr);
          if (typeof obj.requestContentType != "undefined")
          {
              YAHOO.util.Connect.setDefaultPostHeader(obj.requestContentType);
              YAHOO.util.Connect.setDefaultXhrHeader(obj.requestContentType);
              YAHOO.util.Connect.initHeader("Content-Type", obj.requestContentType);
          }
          YAHOO.util.Connect.asyncRequest(obj.method, requestUrl, callback, obj.dataStr || "");
      },
      
      /**
       * Pack OAuth data into a string
       * 
       * @method _packAuthData
       * @private
       * @param data {object} Object containing OAuth data as properties
       * @param delimiter {string} Optional delimiter to use to separate properties, default is '&'
       * @param quote {string} Optional Quote character to use to enclose values, default is '' (no quoting)
       * @returns {string} String containing all property values concatenated together, delimited
       */
      _packAuthData: function OAuth__packAuthData(data, delimiter, quote)
      {
          var items = [], d, quote = quote || "";
          for (k in data)
          {
              items.push("" + k + "=" + quote + data[k] + quote);
          }
          return items.join(delimiter || "&");
      },
      
      /**
       * Unpack OAuth data from a string
       * 
       * @method _unpackAuthData
       * @private
       * @param data {string} String containing OAuth data as properties
       * @param delimiter {string} Optional delimiter to use to split properties, default is '&'
       * @returns {object} Object containing all property values
       */
      _unpackAuthData: function OAuth__unpackAuthData(text, delimiter)
      {
          var tokens = text.split("&"),
              data = {}, pair;
          for (var i = 0; i < tokens.length; i++)
          {
              pair = tokens[i].split("=");
              if (pair.length == 2)
              {
                  data[pair[0]] = pair[1];
              }
          }
          return data;
      },
      
      /**
       * Build an OAuth URL, including parameters
       * 
       * @method _buildUrl
       * @private
       * @param path {string} URL path
       * @param data {object} Object containing OAuth data as properties
       * @param delimiter {string} Optional delimiter to use to separate properties, default is '&'
       * @returns {string} Complete URL to call
       */
      _buildUrl: function OAuth__buildUrl(path, data, delimiter)
      {
          return Alfresco.constants.URL_CONTEXT + "proxy/" + this.options.endpointId + path;
      },
      
      /**
       * Build authentication data for passing to an OAuth service
       * 
       * @method _buildAuthData
       * @private
       * @param data {object} Object containing OAuth data as properties
       * @returns {string} String containing all authentication details, with a signature added
       */
      _buildAuthData: function OAuth__buildAuthData(data)
      {
          data = data || {};
          
          // Fill in any missing values
          
          // Timestamp
          if (this.options.addTimestamps)
          {
              data.oauth_timestamp = Math.floor(Date.now()/1000);
          }
          // Access token, if we have one and another token was not specified
          if (typeof data.oauth_token == "undefined" && this.authData != null && this.authData.oauth_token != null)
          {
              data.oauth_token = this.authData.oauth_token;
          }
          if (typeof data.oauth_token_secret == "undefined" && this.authData != null && this.authData.oauth_token_secret != null)
          {
              data.oauth_token_secret = this.authData.oauth_token_secret;
          }
          
          return this._packAuthData(data, ",", "\"");
      }
      
   };
})();
