
/* global m */
/* eslint no-undef: "error" */

const app = {
	errMsg: null,

	udata: null,
	udataLoaded: false,
	getUdata() {
		m.request({
			method: 'GET',
			url: './status',
		}).then(resp => {
			this.udata = resp.data;
		}).catch(() => {
			this.udata  = null;
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
			app.errMsg = 'ERROR: Failed with errno: x0' +
				resp.response.errno.toString(16) + '.';
			setTimeout(() => {
				app.errMsg = null;
				m.redraw();
			}, 8e3);
		});
	},

	signInButton(url, innerText) {
		return m('p', m('button', {
			onclick(ev) {
				app.signIn(url);
				ev.target.blur();
			},
		}, innerText));
	},

	viewOut() {
		const btn = this.signInButton;
		return [
			m('div', [
				btn('./byway/oauth/10/twitter/auth',
					'OAuth1.0 with Twitter'),
				btn('./byway/oauth/20/github/auth',
					'OAuth2.0 with Github'),
				btn('./byway/oauth/20/google/auth',
					'OAuth2.0 with Google'),
				btn('./byway/oauth/30/unknown/auth',
					'Unknown Service'),
			]),
			m('p', m('strong', this.errMsg)),
		];
	},

	viewIn() {
		const self = this;
		return m('div', [
			m('p', 'uid:' + this.udata.uid),
			m('p', 'uname:' + this.udata.uname),
			m('p', m('button', {
				onclick() {
					m.request({
						method: 'GET',
						url: './logout',
					}).then(() => self.getUdata());
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
}

// root
m.mount(document.querySelector('#box'), app);
