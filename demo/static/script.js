
(function(){
	"use strict";
	angular.module('ZapOAuth', []).
	controller('cred', function($scope, $http, $timeout){
		var s = $scope;

		s.isIn = false;
		s.canRefresh = false;

		s.getStatus = function() {
			$http.get('./status')
			.then(function(ret){
				s.isIn = true;
				s.uid = ret.data.data.uid;
				s.uname = ret.data.data.uname;
				s.canRefresh = s.uname.indexOf('google') != -1;
			}, function(){
				s.isIn = false;
				s.uid = null;
				s.uname = null;
			});
		}
		s.getStatus();

		s.signOut = function() {
			$http.get('/logout')
			.then(function(ret){
				s.getStatus();
			}, function(){
			});
		};

		s.errMsg = null;
		s.isSigningIn = false;

		s.signIn = function(key) {
			var authUrls = {
				twitter: './byway/oauth/10/twitter/auth',
				github:  './byway/oauth/20/github/auth',
				google:  './byway/oauth/20/google/auth',
				unknown: './byway/oauth/30/unknown/auth',
			};
			var authUrl = !authUrls[key]
				? authUrls.unknown : authUrls[key];
			s.isSigningIn = true;
			$http.post(authUrl, {
			}).then(function(ret){
				top.location.href = ret.data.data;
			}, function(){
				s.errMsg = key == 'unknown'
					? 'Service unknown.'
					: 'Cannot connect to remove server.';
				$timeout(function(){
					s.errMsg = null;
				}, 8e3);
			}).then(function(){
				s.isSigningIn = false;
			});
		};

		s.refreshToken = function() {
			$http.post('./refresh')
			.then(function(ret){
				console.log(ret.data);
				s.isIn = true;
			}, function(){
				s.isIn = false;
			});
		};
	});
})();
