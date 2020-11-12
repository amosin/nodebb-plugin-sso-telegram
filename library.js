(function (module) {
	'use strict';
	/* globals module, require */

	var user = require.main.require('./src/user'),
		meta = require.main.require('./src/meta'),
		db = require.main.require('./src/database'),
		passport = require.main.require('passport'),
		passportTelegram = require('passport-telegram-official').TelegramStrategy;
		nconf = require.main.require('nconf'),
		async = require.main.require('async'),
		winston = require.main.require('winston');

	var authenticationController = require.main.require('./src/controllers/authentication');

	var constants = Object.freeze({
		'name': 'Telegram',
		'admin': {
			'route': '/plugins/sso-telegram',
			'icon': 'fa-telegram'
		}
	});

	var Telegram = {
		settings: undefined
	};

	Telegram.init = function (params, callback) {
		var hostHelpers = require.main.require('./src/routes/helpers');

		function render(req, res) {
			res.render('admin/plugins/sso-telegram', {});
		}

		params.router.get('/admin/plugins/sso-telegram', params.middleware.admin.buildHeader, render);
		params.router.get('/api/admin/plugins/sso-telegram', render);

		hostHelpers.setupPageRoute(params.router, '/deauth/telegram', params.middleware, [params.middleware.requireUser], function (req, res) {
			res.render('plugins/sso-telegram/deauth', {
				service: "Telegram",
			});
		});
		params.router.post('/deauth/telegram', [params.middleware.requireUser, params.middleware.applyCSRF], function (req, res, next) {
			Telegram.deleteUserData({
				uid: req.user.uid,
			}, function (err) {
				if (err) {
					return next(err);
				}

				res.redirect(nconf.get('relative_path') + '/me/edit');
			});
		});

		callback();
	};

	Telegram.getSettings = function (callback) {
		if (Telegram.settings) {
			return callback();
		}

		meta.settings.get('sso-telegram', function (err, settings) {
			Telegram.settings = settings;
			callback();
		});
	}

	Telegram.getStrategy = function (strategies, callback) {
		if (!Telegram.settings) {
			return Telegram.getSettings(function () {
				Telegram.getStrategy(strategies, callback);
			});
		}

		if (
			Telegram.settings !== undefined &&
			Telegram.settings.hasOwnProperty('app_id') && Telegram.settings.app_id &&
			Telegram.settings.hasOwnProperty('secret') && Telegram.settings.secret
		) {
			passport.use(new passportTelegram({
				botToken: Telegram.settings.app_id,
				callbackURL: nconf.get('url') + '/auth/telegram/callback',
				passReqToCallback: true,
				profileFields: ['id', 'emails', 'name', 'displayName'],
				enableProof: true,
			}, function (req, accessToken, refreshToken, profile, done) {
				if (req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && req.user.uid > 0) {
					// User is already logged-in, associate fb account with uid if account does not have an existing association
					user.getUserField(req.user.uid, 'fbid', function (err, fbid) {
						if (err) {
							return done(err);
						}

						if (!fbid || profile.id === fbid) {
							user.setUserField(req.user.uid, 'fbid', profile.id);
							db.setObjectField('fbid:uid', profile.id, req.user.uid);
							done(null, req.user);
						} else {
							done(new Error('[[error:sso-multiple-association]]'));
						}
					});
				} else {
					var email;
					if (profile._json.hasOwnProperty('email')) {
						email = profile._json.email;
					} else {
						email = (profile.username ? profile.username : profile.id) + '@telegram.com';
					}

					Telegram.login(profile.id, profile.displayName, email, 'https://graph.telegram.com/' + profile.id + '/picture?type=large', 
						       
						       
						       
						       , refreshToken, profile, function (err, user) {
						if (err) {
							return done(err);
						}

						// Require collection of email
						if (email.endsWith('@telegram.com')) {
							req.session.registration = req.session.registration || {};
							req.session.registration.uid = user.uid;
							req.session.registration.fbid = profile.id;
						}

						authenticationController.onSuccessfulLogin(req, user.uid, function (err) {
							done(err, !err ? user : null);
						});
					});
				}
			}));

			strategies.push({
				name: 'telegram',
				url: '/auth/telegram',
				callbackURL: '/auth/telegram/callback',
				icon: constants.admin.icon,
				scope: 'public_profile, email'
			});
		}

		callback(null, strategies);
	};

	Telegram.appendUserHashWhitelist = function (data, callback) {
		data.whitelist.push('fbid');
		return setImmediate(callback, null, data);
	};

	Telegram.getAssociation = function (data, callback) {
		user.getUserField(data.uid, 'fbid', function (err, fbId) {
			if (err) {
				return callback(err, data);
			}

			if (fbId) {
				data.associations.push({
					associated: true,
					url: 'https://telegram.com/' + fbId,
					deauthUrl: nconf.get('url') + '/deauth/telegram',
					name: constants.name,
					icon: constants.admin.icon
				});
			} else {
				data.associations.push({
					associated: false,
					url: nconf.get('url') + '/auth/telegram',
					name: constants.name,
					icon: constants.admin.icon
				});
			}

			callback(null, data);
		})
	};

	Telegram.prepareInterstitial = function (data, callback) {
		// Only execute if:
		//   - uid and fbid are set in session
		//   - email ends with "@telegram.com"
		if (data.userData.hasOwnProperty('uid') && data.userData.hasOwnProperty('fbid')) {
			user.getUserField(data.userData.uid, 'email', function (err, email) {
				if (email && email.endsWith('@telegram.com')) {
					data.interstitials.push({
						template: 'partials/sso-telegram/email.tpl',
						data: {},
						callback: Telegram.storeAdditionalData
					});
				}

				callback(null, data);
			});
		} else {
			callback(null, data);
		}
	};

	Telegram.storeAdditionalData = function (userData, data, callback) {
		async.waterfall([
			// Reset email confirm throttle
			async.apply(db.delete, 'uid:' + userData.uid + ':confirm:email:sent'),
			async.apply(user.getUserField, userData.uid, 'email'),
			function (email, next) {
				// Remove the old email from sorted set reference
				db.sortedSetRemove('email:uid', email, next);
			},
			async.apply(user.setUserField, userData.uid, 'email', data.email),
			async.apply(user.email.sendValidationEmail, userData.uid, data.email)
		], callback);
	};

	Telegram.storeTokens = function (uid, accessToken, refreshToken) {
		//JG: Actually save the useful stuff
		winston.verbose("Storing received fb access information for uid(" + uid + ") accessToken(" + accessToken + ") refreshToken(" + refreshToken + ")");
		user.setUserField(uid, 'fbaccesstoken', accessToken);
		user.setUserField(uid, 'fbrefreshtoken', refreshToken);
	};

	Telegram.login = function (fbid, name, email, picture, accessToken, refreshToken, profile, callback) {
		winston.verbose("Telegram.login fbid, name, email, picture: " + fbid + ", " + name + ", " + email + ", " + picture);

		Telegram.getUidByFbid(fbid, function (err, uid) {
			if (err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				Telegram.storeTokens(uid, accessToken, refreshToken);

				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function (uid) {
					// Save telegram-specific information to the user
					user.setUserField(uid, 'fbid', fbid);
					db.setObjectField('fbid:uid', fbid, uid);
					var autoConfirm = Telegram.settings && Telegram.settings.autoconfirm === "on" ? 1 : 0;
					user.setUserField(uid, 'email:confirmed', autoConfirm);

					if (autoConfirm) {
						db.sortedSetRemove('users:notvalidated', uid);
					}

					// Save their photo, if present
					if (picture) {
						user.setUserField(uid, 'uploadedpicture', picture);
						user.setUserField(uid, 'picture', picture);
					}

					Telegram.storeTokens(uid, accessToken, refreshToken);

					callback(null, {
						uid: uid
					});
				};

				user.getUidByEmail(email, function (err, uid) {
					if (err) {
						return callback(err);
					}

					if (!uid) {
						// Abort user creation if registration via SSO is restricted
						if (Telegram.settings.disableRegistration === 'on') {
							return callback(new Error('[[error:sso-registration-disabled, Telegram]]'));
						}

						user.create({ username: name, email: email }, function (err, uid) {
							if (err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	Telegram.getUidByFbid = function (fbid, callback) {
		db.getObjectField('fbid:uid', fbid, function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Telegram.addMenuItem = function (custom_header, callback) {
		custom_header.authentication.push({
			'route': constants.admin.route,
			'icon': constants.admin.icon,
			'name': constants.name
		});

		callback(null, custom_header);
	};

	Telegram.deleteUserData = function (data, callback) {
		var uid = data.uid;

		async.waterfall([
			async.apply(user.getUserField, uid, 'fbid'),
			function (oAuthIdToDelete, next) {
				db.deleteObjectField('fbid:uid', oAuthIdToDelete, next);
			},
			function (next) {
				db.deleteObjectField('user:' + uid, 'fbid', next);
			},
		], function (err) {
			if (err) {
				winston.error('[sso-telegram] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = Telegram;
}(module));
