var bcrypt = require('bcrypt-nodejs');
var crypto = require('crypto');
var Sequelize = require('sequelize');
var secrets = require('../config/secrets');
var Promise = require('bluebird');

var sequelize = new Sequelize(secrets.db, {
  storage: secrets.db_table,
  logging: false
});

var userSchema = sequelize.define('User', {
  id: {
    type: Sequelize.UUID,
    defaultValue: Sequelize.UUIDV4,
    primaryKey: true
  },
  email: {
    type: Sequelize.STRING,
    unique: true,
    set: function (v) {
      this.setDataValue('email', v.toLowerCase());
    }
  },
  password: Sequelize.STRING,
  facebook: Sequelize.STRING,
  twitter: Sequelize.STRING,
  google: Sequelize.STRING,
  github: Sequelize.STRING,
  instagram: Sequelize.STRING,
  linkedin: Sequelize.STRING,
  tokens: {
    type: Sequelize.TEXT,
    defaultValue: '[]',
    get: function () {
      var value = this.getDataValue('tokens');
      return JSON.parse(value);
    },
    set: function (value) {
      console.log('setting tokens to:', value);
      console.log('type is', (typeof value));
      console.log('stringified is', JSON.stringify(value || []));
      this.setDataValue('tokens', JSON.stringify(value || []));
    }
  },

  name: {
    type: Sequelize.STRING,
    defaultValue: ''
  },
  gender: {
    type: Sequelize.STRING,
    defaultValue: ''
  },
  location: {
    type: Sequelize.STRING,
    defaultValue: ''
  },
  website: {
    type: Sequelize.STRING,
    defaultValue: ''
  },
  picture: {
    type: Sequelize.STRING,
    defaultValue: ''
  },

  resetPasswordToken: Sequelize.STRING,
  resetPasswordExpires: Sequelize.DATE
}, {
  tableName: 'users',
  instanceMethods: {
    /**
     * Helper method for validationg user's password.
     */
    comparePassword: function(candidatePassword, cb) {
      bcrypt.compare(candidatePassword, this.getDataValue('password'), function(err, isMatch) {
        if (err) { return cb(err); }
        cb(null, isMatch);
      });
    },

    /**
     * Helper method for getting user's gravatar.
     */
    gravatar: function(size) {
      if (!size) { size = 200; }

      if (!this.getDataValue('email')) {
        return 'https://gravatar.com/avatar/?s=' + size + '&d=retro';
      }

      var md5 = crypto.createHash('md5').update(this.getDataValue('email')).digest('hex');
      return 'https://gravatar.com/avatar/' + md5 + '?s=' + size + '&d=retro';
    }
  },
  hooks: {
    beforeCreate: function(user, fn) {
      return new Promise(function(resolve) {
        bcrypt.genSalt(5, function(err, salt) {
          bcrypt.hash(user.password, salt, null, function(err, hash) {
            user.setDataValue('password', hash);
            resolve();
          });
        });
      });
    },
    beforeUpdate: function(user, fn) {
      return new Promise(function(resolve) {
        if (user._previousDataValues.password == user.password) {
          return resolve();
        }

        bcrypt.genSalt(5, function(err, salt) {
          bcrypt.hash(user.password, salt, null, function(err, hash) {
            user.setDataValue('password', hash);
            resolve();
          });
        });
      });
    }
  }
});

module.exports = userSchema;
