/**
 * Module dependencies.
 */
var util = require("util");
var OAuth2Strategy = require("passport-oauth2");
var InternalOAuthError = require("passport-oauth2").InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Twitch authentication strategy authenticates requests by delegating to
 * Twitch using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Twitch application"s client id
 *   - `clientSecret`  your Twitch application"s client secret
 *   - `callbackURL`   URL to which Twitch will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new TwitchStrategy({
 *         clientID: "123-456-789",
 *         clientSecret: "shhh-its-a-secret"
 *         callbackURL: "https://www.example.net/auth/twitch/callback"
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 * 
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || "https://api.twitch.tv/kraken/oauth2/authorize";
    options.tokenURL = options.tokenURL || "https://id.twitch.tv/oauth2/token";
    options.customHeaders = options.customHeaders || { 'Client-Id': options.clientID };

    OAuth2Strategy.call(this, options, verify);
    this.name = "twitch";

    this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from `OAuth2Strategy`.
 */

util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Twitch.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `twitch`
 *   - `id`
 *   - `username`
 *   - `displayName`
 * 
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get("https://api.twitch.tv/helix/user", accessToken, function (err, body, res) {
        if (err) { return done(new InternalOAuthError("failed to fetch user profile", err)); }

        try {
            var json = JSON.parse(body);

            var profile = { provider: "twitch" };
            profile.id = json._id;
            profile.username = json.name;
            profile.displayName = json.display_name;
            profile.email = json.email;

            profile._raw = body;
            profile._json = json;

            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */

Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    if (typeof options.forceVerify !== "undefined") {
        params.force_verify = !!options.forceVerify;
    }
    return params;
};

/**
 * Expose `Strategy`.
 */

module.exports = Strategy;