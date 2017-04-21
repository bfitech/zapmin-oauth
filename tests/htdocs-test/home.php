<?php

// ¯\_(ツ)_/¯

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
	controller('cred', function($scope, $http){
		var s = $scope;

		s.isIn = false;

		s.getStatus = function() {
			$http.get('/status')
			.then(function(ret){
				s.isIn = true;
				s.uid = ret.data.data.uid;
				s.uname = ret.data.data.uname;
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

		s.signIn10 = function() {
			s.isSigningIn = true;
			$http.post('/byway/oauth/10/twitter/auth', {
			}).then(function(ret){
				top.location.href = ret.data.data;
			}, function(){
				s.errMsg = 'Cannot connect to remove server.';
			}).then(function(){
				s.isSigningIn = false;
			});
		};

		s.signIn20 = function() {
			s.isSigningIn = true;
			$http.post('/byway/oauth/20/google/auth', {
			}).then(function(ret){
				top.location.href = ret.data.data;
			}, function(){
				s.errMsg = 'Cannot connect to remove server.';
			}).then(function(){
				s.isSigningIn = false;
			});
		};

		s.signInXX = function() {
			s.isSigningIn = true;
			$http.post('/byway/oauth/30/something/auth', {
			}).then(function(ret){
				top.location.href = ret.data.data;
			}, function(){
				s.errMsg = 'Unknown service provider.';
			}).then(function(){
				s.isSigningIn = false;
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
		height:12em;
		padding:8px;
		border:1px solid rgba(0,0,0,.3);
		width:400px;
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
			</p>
		</div>
		<div ng-show=!isIn>
			<p>
				<button ng-click='signIn10()' ng-disabled=isSigningIn>
					OAuth1.0 with Twitter
				</button>
			</p>
			<p>
				<button ng-click='signIn20()' ng-disabled=isSigningIn>
					OAuth2.0 with Google
				</button>
			</p>
			<p>
				<button ng-click='signInXX()' ng-disabled=isSigningIn>
					Unknown Service
				</button>
			</p>

			<h4 ng-show=errMsg>ERROR: {{errMsg}}</h4>
		</div>
	</div>
</div>

