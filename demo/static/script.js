
/* global m */
/* eslint no-undef: "error" */

const app = {
	errMsg: null,
	showErrMsg(errno) {
		this.errMsg = 'ERROR: Failed with errno: 0x0' +
			errno.toString(16) + '.';
		setTimeout(() => {
			this.errMsg = null;
			m.redraw();
		}, 8e3);
	},

	udata: null,
	udataLoaded: false,
	getUdata() {
		m.request({
			method: 'GET',
			url: './status',
		}).then(resp => {
			this.udata = resp.data;
		}).catch(() => {
			this.udata = null;
		}).finally(() => {
			this.udataLoaded = true;
		});
	},

	signIn(url) {
		m.request({
			method: 'POST',
			url: url,
		}).then(resp => {
			top.location.href = resp.data;
		}).catch(resp => {
			this.showErrMsg(resp.response.errno);
		});
	},
	signInButton(url, innerText) {
		return m('p', m('button', {
			onclick() {
				app.signIn(url);
				this.blur();
			},
		}, innerText));
	},

	fakeEmail: null,
	fakeSignIn() {
		if (this.fakeEmail === null)
			return;
		this.fakeEmail = this.fakeEmail.trim();
		if (!this.fakeEmail)
			return;
		m.request({
			method: 'GET',
			url: './fake_login/20/github',
			params: {
				email: this.fakeEmail,
			},
		}).then(resp => {
			top.location.href = resp.data;
		}).catch(resp => {
			this.showErrMsg(resp.response.errno);
		}).finally(() => {
			this.fakeEmail = null;
		});
	},
	fakeSignInBtn() {
		const self = this;
		return [
			m('input', {
				placeholder: 'you@github.example.co etc.',
				oninput() {
					self.fakeEmail = this.value;
				},
				onkeyup(ev) {
					if (ev.keyCode === 13) {
						self.fakeSignIn();
					}
				},
				value: self.fakeEmail,
			}),
			m('button', {
				onclick() {
					this.blur();
					self.fakeSignIn();
				},
			}, 'fake Github'),
		];
	},

	viewOut() {
		const btn = this.signInButton;
		return [
			m('div.real', [
				btn('./byway/oauth/10/twitter/auth',
					'OAuth1.0 with Twitter'),
				btn('./byway/oauth/20/github/auth',
					'OAuth2.0 with Github'),
				btn('./byway/oauth/20/google/auth',
					'OAuth2.0 with Google'),
				btn('./byway/oauth/30/unknown/auth',
					'Unknown Service'),
			]),
			m('hr'),
			m('div.fake', this.fakeSignInBtn()),
			m('hr'),
			m('p', m('strong', this.errMsg)),
			m('div#srv', m('a', {
				href: './services',
				download: 'services.json',
			}, 'services')),
		];
	},

	viewIn() {
		const self = this;
		return m('div', [
			m('p', 'uid:' + this.udata.uid),
			m('p', 'uname:' + this.udata.uname),
			m('hr'),
			m('p', m('button', {
				onclick() {
					m.request({
						method: 'GET',
						url: './logout',
					}).then(() => {}).catch(() => {}).finally(() => {
						self.udata = null;
					});
				},
			}, 'SIGN OUT')),
		]);
	},

	oninit() {
		this.getUdata();
	},

	view() {
		if (!this.udataLoaded)
			return [];
		if (this.udata === null)
			return this.viewOut();
		return this.viewIn();
	},
};

// root
m.mount(document.querySelector('#box'), app);
