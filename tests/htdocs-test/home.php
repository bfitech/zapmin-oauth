<?php

// @todo This sample assumes installation in the root path '/'.
//     Parameterize HTML base to fix this.

?><!doctype html>
<html>
<head>
	<base href=/>
	<title>Test OAuth Client</title>
	<script src=./bower_components/angular/angular.min.js></script>
	<script>
(function(){
	"use strict";
	angular.module('ZapOAuth', []).
	controller('cred', function($scope, $http, $timeout){
		var s = $scope;

		s.isIn = false;
		s.isRefresh = false;

		s.getStatus = function() {
			$http.get('/status')
			.then(function(ret){
				s.isIn = true;
				s.uid = ret.data.data.uid;
				s.uname = ret.data.data.uname;
				var service = ret.data.data.uname.match(/\[(.*?)\]/);
				if(service[1] == 'google')
					s.isRefresh = true;
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
				twitter: '/byway/oauth/10/twitter/auth',
				github:  '/byway/oauth/20/github/auth',
				google:  '/byway/oauth/20/google/auth',
				unknown: '/byway/oauth/30/unknown/auth',
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
			$http.post('/refresh')
			.then(function(ret){
				console.log(ret.data);
				s.isIn = true;
			}, function(){
				s.isIn = false;
			});
		};
	});
})();
	</script>
	<style>
	#wrap{
		display:flex;
		align-items:center;
		justify-content:center;
		height:90vh;
		font-family:monospace;
	}
	#box{
		height:14em;
		padding:8px 16px;
		border:1px solid rgba(0,0,0,.3);
		width:400px;
	}
	</style>
</head>
<body>
<div id=wrap ng-app=ZapOAuth ng-controller=cred>
	<div id=box>
		<div ng-show=isIn>
			<p>uid: {{uid}}</p>
			<p>uname: {{uname}}</p>
			<p>
				<button ng-click='signOut()'>
					SIGN OUT
				</button>
				<button ng-click='refreshToken()' ng-show=isRefresh>
					REFRESH TOKEN
				</button>
			</p>
		</div>
		<div ng-show=!isIn>
			<p>
				<button ng-click='signIn("twitter")'
					ng-disabled=isSigningIn>
					OAuth1.0 with Twitter
				</button>
			</p>
			<p>
				<button ng-click='signIn("github")'
					ng-disabled=isSigningIn>
					OAuth2.0 with Github
				</button>
			</p>
			<p>
				<button ng-click='signIn("google")'
					ng-disabled=isSigningIn>
					OAuth2.0 with Google
				</button>
			</p>
			<p>
				<button ng-click='signIn("whatever")'
					ng-disabled=isSigningIn>
					Unknown Service
				</button>
			</p>
		</div>
		<p ng-show=errMsg>
			<strong>ERROR:</strong> {{errMsg}}
		</p>
	</div>
</div>

