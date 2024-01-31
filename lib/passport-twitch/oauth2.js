var util = require("util");
var OAuth2Strategy = require("passport-oauth2");
var InternalOAuthError = require("passport-oauth2").InternalOAuthError;


function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || "https://api.twitch.tv/kraken/oauth2/authorize";
    options.tokenURL = options.tokenURL || "https://id.twitch.tv/oauth2/token";
    options.customHeaders = options.customHeaders || { 'Client-Id': options.clientID };

    OAuth2Strategy.call(this, options, verify);
    this.name = "twitch";

    this._oauth2.useAuthorizationHeaderforGET(true);
}

util.inherits(Strategy, OAuth2Strategy);

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

Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    if (typeof options.forceVerify !== "undefined") {
        params.force_verify = !!options.forceVerify;
    }
    return params;
};

module.exports = Strategy;
