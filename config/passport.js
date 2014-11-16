var _ = require('lodash');
var passport = require('passport');
var InstagramStrategy = require('passport-instagram').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GitHubStrategy = require('passport-github').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
var OAuthStrategy = require('passport-oauth').OAuthStrategy; // Tumblr
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy; // Venmo, Foursquare
var User = require('../models/User');
var secrets = require('./secrets');

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.find(id)
    .then(function(user) {
      done(null, user);
    })
    .catch(function (err) {
      done(err);
    });
});

// Sign in with Instagram.

passport.use(new InstagramStrategy(secrets.instagram, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ where: { instagram: profile.id }}).then(function (existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already an Instagram account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done();
      } else {
        return User.find(req.user.id).then(function (user) {
          user.instagram = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'instagram', accessToken: accessToken });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.picture = user.picture || profile._json.data.profile_picture;
          user.website = user.website || profile._json.data.website;

          return user.save().then(function() {
            req.flash('info', { msg: 'Instagram account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });
  } else {
    User.findOne({ where: {instagram: profile.id} }).then(function (existingUser) {
      if (existingUser) return done(null, existingUser);

      var user = new User();
      user.instagram = profile.id;
      var tokens = user.tokens;
      tokens.push({ kind: 'instagram', accessToken: accessToken });
      user.tokens = tokens;
      user.name = profile.displayName;
      // Similar to Twitter API, assigns a temporary e-mail address
      // to get on with the registration process. It can be changed later
      // to a valid e-mail address in Profile Management.
      user.email = profile.username + "@instagram.com";
      user.website = profile._json.data.website;
      user.picture = profile._json.data.profile_picture;

      return user.save().then(function () {
        done(null, user);
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Sign in using Email and Password.

passport.use(new LocalStrategy({ usernameField: 'email' }, function (email, password, done) {
  User.findOne({ where: { email: email } }).then(function(user) {
    if (!user) return done(null, false, { message: 'Email ' + email + ' not found'});
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Invalid email or password.' });
      }
    });
  })
  .catch(function (err) {
    done(err);
  });
}));

/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a <provider> id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */

// Sign in with Facebook.

passport.use(new FacebookStrategy(secrets.facebook, function (req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ where: { facebook: profile.id }}).then(function (existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done();
      } else {
        return User.find(req.user.id).then(function(user) {
          user.facebook = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'facebook', accessToken: accessToken });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.gender = user.gender || profile._json.gender;
          user.picture = user.picture || 'https://graph.facebook.com/' + profile.id + '/picture?type=large';

          return user.save().then(function () {
            req.flash('info', { msg: 'Facebook account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });
  } else {
    User.findOne({ where: { facebook: profile.id } }).then(function(existingUser) {
      if (existingUser) return done(null, existingUser);
      return User.findOne({ where: {email: profile._json.email} }).then(function(existingEmailUser) {
        if (existingEmailUser) {
          req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.' });
          done();
        } else {
          var user = new User();
          user.email = profile._json.email;
          user.facebook = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'facebook', accessToken: accessToken });
          user.tokens = tokens;
          user.name = profile.displayName;
          user.gender = profile._json.gender;
          user.picture = 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
          user.location = (profile._json.location) ? profile._json.location.name : '';

          return user.save().then(function() {
            done(null, user);
          });
        }
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Sign in with GitHub.

passport.use(new GitHubStrategy(secrets.github, function(req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ where: { github: String(profile.id) } }).then(function(existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already a GitHub account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done();
      } else {
        return User.find(req.user.id).then(function(user) {
          user.github = String(profile.id);
          var tokens = user.tokens;
          tokens.push({ kind: 'github', accessToken: accessToken });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.picture = user.picture || profile._json.avatar_url;
          user.location = user.location || profile._json.location;
          user.website = user.website || profile._json.blog;

          return user.save().then(function() {
            req.flash('info', { msg: 'GitHub account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });
  } else {
    User.findOne({ where: { github: String(profile.id) } }).then(function(existingUser) {
      if (existingUser) return done(null, existingUser);
      return User.findOne({ where: { email: profile._json.email } }).then(function(existingEmailUser) {
        if (existingEmailUser) {
          req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with GitHub manually from Account Settings.' });
          done();
        } else {
          var user = new User();
          user.email = profile._json.email;
          user.github = String(profile.id);
          var tokens = user.tokens;
          tokens.push({ kind: 'github', accessToken: accessToken });
          user.tokens = tokens;
          user.name = profile.displayName;
          user.picture = profile._json.avatar_url;
          user.location = profile._json.location;
          user.website = profile._json.blog;

          return user.save().then(function() {
            done(null, user);
          });
        }
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Sign in with Twitter.

passport.use(new TwitterStrategy(secrets.twitter, function(req, accessToken, tokenSecret, profile, done) {
  if (req.user) {
    User.findOne({ where: { twitter: profile.id } }).then(function(existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already a Twitter account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done(null);
      } else {
        return User.find(req.user.id).then(function(user) {
          user.twitter = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'twitter', accessToken: accessToken, tokenSecret: tokenSecret });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.location = user.location || profile._json.location;
          user.picture = user.picture || profile._json.profile_image_url_https;

          return user.save().then(function() {
            req.flash('info', { msg: 'Twitter account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });

  } else {
    User.findOne({ where: { twitter: profile.id } }).then(function(existingUser) {
      if (existingUser) return done(null, existingUser);
      var user = new User();
      // Twitter will not provide an email address.  Period.
      // But a person’s twitter username is guaranteed to be unique
      // so we can "fake" a twitter email address as follows:
      user.email = profile.username + "@twitter.com";
      user.twitter = profile.id;
      var tokens = user.tokens;
      tokens.push({ kind: 'twitter', accessToken: accessToken, tokenSecret: tokenSecret });
      user.tokens = tokens;
      user.name = profile.displayName;
      user.location = profile._json.location;
      user.picture = profile._json.profile_image_url_https;

      return user.save().then(function() {
        done(null, user);
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Sign in with Google.

passport.use(new GoogleStrategy(secrets.google, function(req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ where: { google: profile.id } }).then(function(existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already a Google account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done(null);
      } else {
        return User.find(req.user.id).then(function(user) {
          user.google = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'google', accessToken: accessToken });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.gender = user.gender || profile._json.gender;
          user.picture = user.picture || profile._json.picture;
          return user.save().then(function() {
            req.flash('info', { msg: 'Google account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });
  } else {
    User.findOne({ where: { google: profile.id } }).then(function(existingUser) {
      if (existingUser) return done(null, existingUser);
      return User.findOne({ where: { email: profile._json.email } }).then(function(existingEmailUser) {
        if (existingEmailUser) {
          req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Google manually from Account Settings.' });
          done(null);
        } else {
          var user = new User();
          user.email = profile._json.email;
          user.google = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'google', accessToken: accessToken });
          user.tokens = tokens;
          user.name = profile.displayName;
          user.gender = profile._json.gender;
          user.picture = profile._json.picture;
          return user.save().then(function() {
            done(null, user);
          });
        }
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Sign in with LinkedIn.

passport.use(new LinkedInStrategy(secrets.linkedin, function(req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ where: { linkedin: profile.id } }).then(function(existingUser) {
      if (existingUser) {
        req.flash('errors', { msg: 'There is already a LinkedIn account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
        done(null);
      } else {
        return User.find(req.user.id).then(function(user) {
          user.linkedin = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'linkedin', accessToken: accessToken });
          user.tokens = tokens;
          user.name = user.name || profile.displayName;
          user.location = user.location || profile._json.location.name;
          user.picture = user.picture || profile._json.pictureUrl;
          user.website = user.website || profile._json.publicProfileUrl;
          return user.save().then(function() {
            req.flash('info', { msg: 'LinkedIn account has been linked.' });
            done(null, user);
          });
        });
      }
    })
    .catch(function (err) {
      done(err);
    });
  } else {
    User.findOne({ where: { linkedin: profile.id } }).then(function(existingUser) {
      if (existingUser) return done(null, existingUser);
      User.findOne({ email: profile._json.emailAddress }).then(function(existingEmailUser) {
        if (existingEmailUser) {
          req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with LinkedIn manually from Account Settings.' });
          done(null);
        } else {
          var user = new User();
          user.linkedin = profile.id;
          var tokens = user.tokens;
          tokens.push({ kind: 'linkedin', accessToken: accessToken });
          user.tokens = tokens;
          user.email = profile._json.emailAddress;
          user.name = profile.displayName;
          user.location = profile._json.location.name;
          user.picture = profile._json.pictureUrl;
          user.website = profile._json.publicProfileUrl;
          return user.save().then(function() {
            done(null, user);
          });
        }
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
}));

// Tumblr API setup.

passport.use('tumblr', new OAuthStrategy({
    requestTokenURL: 'http://www.tumblr.com/oauth/request_token',
    accessTokenURL: 'http://www.tumblr.com/oauth/access_token',
    userAuthorizationURL: 'http://www.tumblr.com/oauth/authorize',
    consumerKey: secrets.tumblr.consumerKey,
    consumerSecret: secrets.tumblr.consumerSecret,
    callbackURL: secrets.tumblr.callbackURL,
    passReqToCallback: true
  },
  function(req, token, tokenSecret, profile, done) {
    return User.find(req.user._id).then(function(user) {
      var tokens = user.tokens;
      tokens.push({ kind: 'tumblr', accessToken: token, tokenSecret: tokenSecret });
      user.tokens = tokens;
      return user.save().then(function() {
        done(null, user);
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
));

// Foursquare API setup.

passport.use('foursquare', new OAuth2Strategy({
    authorizationURL: 'https://foursquare.com/oauth2/authorize',
    tokenURL: 'https://foursquare.com/oauth2/access_token',
    clientID: secrets.foursquare.clientId,
    clientSecret: secrets.foursquare.clientSecret,
    callbackURL: secrets.foursquare.redirectUrl,
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    User.find(req.user._id).then(function(user) {
      var tokens = user.tokens;
      tokens.push({ kind: 'foursquare', accessToken: accessToken });
      user.tokens = tokens;
      return user.save().then(function() {
        done(null, user);
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
));

// Venmo API setup.

passport.use('venmo', new OAuth2Strategy({
    authorizationURL: 'https://api.venmo.com/v1/oauth/authorize',
    tokenURL: 'https://api.venmo.com/v1/oauth/access_token',
    clientID: secrets.venmo.clientId,
    clientSecret: secrets.venmo.clientSecret,
    callbackURL: secrets.venmo.redirectUrl,
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    User.find(req.user._id).then(function(user) {
      var tokens = user.tokens;
      tokens.push({ kind: 'venmo', accessToken: accessToken });
      user.tokens = tokens;
      return user.save().then(function() {
        done(null, user);
      });
    })
    .catch(function (err) {
      done(err);
    });
  }
));

// Login Required middleware.

exports.isAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

// Authorization Required middleware.

exports.isAuthorized = function(req, res, next) {
  var provider = req.path.split('/').slice(-1)[0];

  if (_.find(req.user.tokens, { kind: provider })) {
    next();
  } else {
    res.redirect('/auth/' + provider);
  }
};
