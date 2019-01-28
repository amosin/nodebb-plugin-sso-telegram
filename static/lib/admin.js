define('admin/plugins/sso-telegram', ['settings'], function(Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function() {
		Settings.load('sso-telegram', $('.sso-telegram-settings'));

		$('#save').on('click', function() {
			Settings.save('sso-telegram', $('.sso-telegram-settings'), function() {
				app.alert({
					type: 'success',
					alert_id: 'sso-telegram-saved',
					title: 'Settings Saved',
					message: 'Please reload your NodeBB to apply these settings',
					clickfn: function() {
						socket.emit('admin.reload');
					}
				});
			});
		});
	};

	return ACP;
});