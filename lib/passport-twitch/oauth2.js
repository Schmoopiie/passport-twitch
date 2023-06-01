const OAuth2Strategy = require("passport-oauth2");
const InternalOAuthError = require("passport-oauth2").InternalOAuthError;

class Strategy extends OAuth2Strategy {
  /**
   * `Strategy` constructor.
   *
   * The Twitch authentication strategy authenticates requests by delegating to
   * Twitch using the OAuth 2.0 protocol.
   *
   * Applications must supply a `verify` callback which accepts an `accessToken`,
   * `refreshToken` and service-specific `profile`, and then calls the `done`
   * callback supplying a `user`, which should be set to `false` if the
   * credentials are not valid.  If an exception occurred, `err` should be set.
   *
   * Options:
   *   - `clientID`      Your Twitch application's client id
   *   - `clientSecret`  Your Twitch application's client secret
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
  constructor(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || "https://id.twitch.tv/oauth2/authorize";
    options.tokenURL = options.tokenURL || "https://id.twitch.tv/oauth2/token";

    super(options, verify);
    this.name = "twitch";
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Retrieve user profile from Twitch.
   *
   * This function constructs a normalized profile, with the following properties:
   *
   *   - `provider`           Always set to `twitch`
   *   - `id`                 Twitch user ID
   *   - `login`              Twitch username
   *   - `display_name`       Twitch display name
   *   - `email`              The user's email address
   *   - `description`        The bio that is set on the user's profile
   *   - `profile_image_url`  Twitch profile avatar
   *   - `offline_image_url`  Twitch offline image that is displayed in the player
   *   - `broadcaster_type`   Type of broadcaster (affiliate, partner, etc.)
   *   - `view_count`         How many viewers are currently watching
   *   - `created_at`         When the account was created
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api protected
   */
  async userProfile(accessToken, done) {
    try{
        const getUserData = await fetch("https://api.twitch.tv/helix/users", {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Client-Id': this._oauth2._clientId
        }
        });

        const json = await getUserData.json();
        const data = json.data[0];

        const profile = {
            provider: 'Twitch',
            id: data.id,
            login: data.login,
            displayName: data.display_name,
            email: data.email,
            description: data.description,
            profileImageUrl: data.profile_image_url,
            offlineImageUrl: data.offline_image_url,
            broadcasterType: data.broadcaster_type,
            viewCount: data.view_count,
            createdAt: data.created_at,
            _raw: getUserData.body,
            _json: json
        }

        done(null, profile);
    } catch (e) {
        done(new InternalOAuthError("failed to fetch user profile", e));
    }
  }

  /**
   * Return extra parameters to be included in the authorization request.
   *
   * @param {Object} options
   * @return {Object}
   * @api protected
   */
  authorizationParams(options) {
    const params = {};
    if (typeof options.forceVerify !== "undefined") {
      params.force_verify = !!options.forceVerify;
    }
    return params;
  }
}

module.exports = Strategy;
