###
# Copyright (C) 2014-2017 Andrey Antukh <niwi@niwi.nz>
# Copyright (C) 2014-2017 Jesús Espino Garcia <jespinog@gmail.com>
# Copyright (C) 2014-2017 David Barragán Merino <bameda@dbarragan.com>
# Copyright (C) 2014-2017 Alejandro Alonso <alejandro.alonso@kaleidos.net>
# Copyright (C) 2014-2017 Juan Francisco Alcántara <juanfran.alcantara@kaleidos.net>
# Copyright (C) 2014-2017 Xavi Julian <xavier.julian@kaleidos.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# File: openid-auth.coffee
###

OpenIDLoginButtonDirective = ($window, $params, $location, $config, $events, $confirm,
	$auth, $navUrls, $loader) ->
	# Login or registar a user with his/her openid account.
	#
	# Example:
	#	 tg-openid-login-button()
	#
	# Requirements:
	#   - ...

	INVITE_STASH_KEY = "taiga-oidc-invitation"
	INVITE_STASH_MAX_AGE_MS = 30 * 60 * 1000
	INVITATION_PATH_PREFIX = "/invitation/"

	link = ($scope, $el, $attrs) ->
		AUTH_URL = $config.get("openidAuth", null)
		AUTH_SCOPE = $config.get("openidScope", "User.Read")
		CLIENT_ID = $config.get("openidClientId", "taiga")
		$scope.openid_name = $config.get("openidName", "openid-connect")

		# The same URI on every page and on both legs: taiga-back replays `url`
		# as redirect_uri in the token exchange, and the OIDC client needs only
		# one registered redirect URI, <origin>/login. $tgNavUrls.resolve strips
		# the leading slash ("login"), so it is added back here.
		redirectURL = () -> $window.location.origin + "/" + $navUrls.resolve("login")

		# sessionStorage can throw (privacy modes, disabled storage); every
		# failure degrades to a plain login without the invitation.
		writeInviteStash = (stash) ->
			try
				$window.sessionStorage.setItem(INVITE_STASH_KEY, JSON.stringify(stash))
			catch e
				null

		# Removed before it is used, so a failed claim (revoked invite, already
		# a member) cannot wedge later logins.
		takeInviteStash = ->
			try
				raw = $window.sessionStorage.getItem(INVITE_STASH_KEY)
				$window.sessionStorage.removeItem(INVITE_STASH_KEY)
			catch e
				return null
			return null if not raw
			try
				stash = JSON.parse(raw)
			catch e
				return null
			return null if not stash or not stash.token or typeof stash.ts != "number"
			return null if Date.now() - stash.ts >= INVITE_STASH_MAX_AGE_MS
			return stash

		makeLoginOnSuccess = (invite) ->
			return (response) ->
				if invite and invite.project
					nextUrl = $navUrls.resolve("project", {project: invite.project})
				else if $params.next and $params.next != $navUrls.resolve("login")
					nextUrl = $params.next
				else
					nextUrl = $navUrls.resolve("home")

				$events.setupConnection()

				$location.search("next", null)
				$location.search("token", null)
				$location.search("state", null)
				$location.search("code", null)
				$location.path(nextUrl)

		loginOnError = (response) ->
			$location.search("state", null)
			$location.search("code", null)
			$loader.pageLoaded()

			if response.data._error_message
				$confirm.notify("light-error", response.data._error_message )
			else
				$confirm.notify("light-error", "Our Oompa Loompas have not been able to get your credentials from OpenID.") #TODO: i18n

		loginWithOpenIDAccount = ->
			code = $params.code
			accessToken = $params.access_token
			return if not (code) && not(accessToken)
			$loader.start(true)

			if code
				data = {code: code, url: redirectURL()}
			else
				data = {access_token: accessToken, url: redirectURL()}

			# invitation_token, not `token`: taiga-back core accepts the
			# invitation after any login type, plugins included.
			invite = takeInviteStash()
			data.invitation_token = invite.token if invite

			$auth.login(data, "openid").then(makeLoginOnSuccess(invite), loginOnError)

		loginWithOpenIDAccount()

		$el.on "click", ".button-auth", (event) ->
			path = $location.path() or ""
			if $params.token and path.indexOf(INVITATION_PATH_PREFIX) == 0
				writeInviteStash({
					token: $params.token
					project: ($scope.invitation and $scope.invitation.project_slug) or null
					ts: Date.now()
				})
				# taiga-front's login page sends an authenticated user home and
				# drops ?code=, so the callback would never run.
				$auth.logout() if $auth.isAuthenticated()

			url = "#{AUTH_URL}?redirect_uri=#{encodeURIComponent(redirectURL())}" +
				"&client_id=#{encodeURIComponent(CLIENT_ID)}&response_type=code" +
				"&scope=#{encodeURIComponent(AUTH_SCOPE)}"
			$window.location.href = url

		$scope.$on "$destroy", ->
			$el.off()

	return {
		link: link
		restrict: "EA"
		template: ""
	}

module = angular.module('taigaContrib.openidAuth', [])
module.directive("tgOpenidLoginButton", ["$window", '$routeParams', "$tgLocation", "$tgConfig", "$tgEvents",
	"$tgConfirm", "$tgAuth", "$tgNavUrls", "tgLoader",
	OpenIDLoginButtonDirective])
