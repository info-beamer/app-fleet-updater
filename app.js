'use strict';
// The oauth2 code is partly based on 
// https://github.com/aaronpk/pkce-vanilla-js

(async () => {
const config = window.CONFIG
const STATE_PREFIX = 'fleet-updater'

function parse_query_string(qs) {
  if (qs == "") { return {} }
  const segments = qs.split("&").map(s => s.split("="))
  let parsed = {}
  segments.forEach(s => parsed[s[0]] = decodeURIComponent(s[1]).replace(/\+/g, ' '))
  return parsed
}

function random() {
  const array = new Uint32Array(16)
  window.crypto.getRandomValues(array)
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('')
}

function sha256(plain) {
  const encoder = new TextEncoder()
  const data = encoder.encode(plain)
  return window.crypto.subtle.digest('SHA-256', data)
}

// Base64-urlencodes the input string
function base64url_encode(str) {
  // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
  // btoa accepts chars only within ascii 0-255 and base64 encodes them.
  // Then convert the base64 encoded to base64url encoded
  //   (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkce_verifier_to_challenge(v) {
  const hashed = await sha256(v)
  return base64url_encode(hashed)
}

async function redirect_to_authorization() {
  const state = random()
  localStorage.setItem(`${STATE_PREFIX}:pkce_state`, state)

  // Create and store a new PKCE code_verifier (the plaintext random secret)
  const code_verifier = random()
  localStorage.setItem(`${STATE_PREFIX}:pkce_code_verifier`, code_verifier)

  // Hash and base64-urlencode the secret to use as the challenge
  const code_challenge = await pkce_verifier_to_challenge(code_verifier)

  // Build the authorization URL
  const url = config.authorization_endpoint 
      + "?response_type=code"
      + "&client_id="+encodeURIComponent(config.client_id)
      + "&state="+encodeURIComponent(state)
      + "&scope="+encodeURIComponent(config.requested_scopes)
      + "&redirect_uri="+encodeURIComponent(config.redirect_uri)
      + "&code_challenge="+encodeURIComponent(code_challenge)
      + "&code_challenge_method=S256"

  // Redirect to the authorization server
  window.location = url
}

async function handle_url_params() {
  const q = parse_query_string(window.location.search.substring(1))

  // Special case when info-beamer hosted redirected to this app.
  // If we don't have an access token, initiate authorization flow.
  if (q.source == "ib" && !localStorage.getItem(`${STATE_PREFIX}:access_token`))
    return redirect_to_authorization()

  // If there's no oauth 'state' parameter, there's nothing to do.
  if (!q.state)
    return

  if (localStorage.getItem(`${STATE_PREFIX}:pkce_state`) != q.state) {
    // If the state doesn't match the locally saved state,
    // we have to abort the flow. Someone might have started
    // it without our knowledge.
    alert("Invalid state")
  } else if (q.error) {
    // If there's an error response, print it out
    alert(q.error_description)
  } else if (q.code) {
    // Exchange the authorization code for an access token
    const resp = await Vue.http.post(config.token_endpoint, {
      grant_type: "authorization_code",
      code: q.code,
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      code_verifier: localStorage.getItem(`${STATE_PREFIX}:pkce_code_verifier`)
    })

    // Save retrieved access_token. The app can start init it with.
    localStorage.setItem(`${STATE_PREFIX}:access_token`, resp.data.access_token)
  }

  // Clean these up since we don't need them anymore
  localStorage.removeItem(`${STATE_PREFIX}:pkce_state`)
  localStorage.removeItem(`${STATE_PREFIX}:pkce_code_verifier`)
  window.history.replaceState({}, null, config.app_root)
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

const store = new Vuex.Store({
  strict: true,
  state: {
    ready: false,
    access_token: null,
    info: null,
  },
  getters: {
    is_logged_in(state) {
      return !!state.access_token
    },
    email(state) {
      return state.info ? state.info.email : '<unknown user>'
    },
  },
  mutations: {
    init(state) {
      state.access_token = localStorage.getItem(`${STATE_PREFIX}:access_token`)
    },
    set_login(state, info) {
      state.info = info
    },
    wipe(state) {
      state.access_token = null
      state.info = null
      localStorage.removeItem(`${STATE_PREFIX}:access_token`)
      window.location.href = config.app_root
    },
    ready(state) {
      state.ready = true
    },
  },
  actions: {
    async init({commit, state}) {
      commit('init')
      if (state.access_token) {
        // We have an access token? Fetch basic account
        // info. If that doesn't work, wipe the login state.
        try {
          let resp = await Vue.http.get('account')
          commit('set_login', resp.data)
        } catch (e) {
          commit('wipe')
        }
      }
      commit('ready')
    },
    async logout({commit}) {
      try {
        // kill the session. This invalidates the access_token
        // used to call this endpoint.
        await Vue.http.post('account/session/destroy')
      } catch (e) {
        // Ignore errors. Nothing do to here.
      }
      commit('wipe')
    },
  }
})

Vue.component('login-ui', {
  template: `
    <div>
      <p>
        This tool allows you to upgrade a complete fleet of info-beamer
        devices. Get started by granting access to your info-beamer account.
      </p>
      <button @click='authorize' class='btn-block'>
        Log into your account
      </button>
    </div>
  `,
  methods: {
    async authorize() {
      await redirect_to_authorization()
    },
  },
})

Vue.component('upgrader-ui', {
  template: `
    <div>
      <div>
        Logged in as <i>{{$store.getters.email}}</i>
        <button @click='logout' class='float-right'>
          Logout
        </button>
      </div>
      <hr/>
      <button disabled class='btn-block' v-if='state == "loading"'>
        Fetching account info..
      </button>
      <button @click='upgrade' class='btn-block' v-else-if='state == "ready"'>
        Begin upgrading {{upgradable.length}} devices
      </button>
      <button @click='state = "abort"' class='btn-block' v-else-if='state == "upgrading"'>
        Upgrade in progress. Click to abort.
      </button>
      <button disabled class='btn-block' v-else-if='state == "abort"'>
        Aborting..
      </button>
      <button @click='load_devices' class='btn-block' v-else-if='state == "done"'>
        Check for upgradable devices
      </button>
      <hr/>
      <div>
        Log output:
      </div>
      <textarea class='log' :value='log_string' ref='log' readonly></textarea>
    </div>
  `,
  data: () => ({
    log: [],
    upgradable: [],
    channels: {},
    state: 'loading',
  }),
  async created() {
    this.add_log("Upgrader ready")
    this.load_devices()
  },
  computed: {
    log_string() {
      return this.log.join('\n')
    }
  },
  methods: {
    async load_devices() {
      this.state = 'loading'
      this.upgradable = []
      this.add_log('Fetching device list..')

      let r = await Vue.http.get('os/channels')
      this.channels = await r.json()

      r = await Vue.http.get('device/list')
      let devices = (await r.json()).devices

      let up_to_date = 0, offline = 0, blocked = 0
      for (let device of devices) {
        if (!device.is_online) {
          offline++
        } else if (device.upgrade.blocked > 0) {
          blocked++
        } else if (
            // either newer version in current channel
            device.run.version != this.channels[device.run.channel].version ||

            // or it's testing and there's a newer stable channel version
            (device.run.channel == 'testing' && this.channels['stable'].version >= device.run.version)
        ) {
          this.upgradable.push(device)
        } else {
          up_to_date++
        }
      }
      if (offline > 0)
        this.add_log(`  ${offline}/${devices.length} devices are offline at the moment`)
      if (up_to_date > 0)
        this.add_log(`  ${up_to_date}/${devices.length} already at latest release`)
      if (blocked > 0)
        this.add_log(`  ${blocked}/${devices.length} marked to not upgrade`)
      this.add_log(`  ${this.upgradable.length}/${devices.length} can be upgraded`)

      if (this.upgradable.length > 0) {
        this.add_log('Ready for upgrade')
        this.state = 'ready'
      } else {
        this.add_log('Nothing to do. All reachable devices already up-to-date')
        this.state = 'done'
      }
    },
    async upgrade() {
      this.state = 'upgrading'
      while (this.state == 'upgrading' && this.upgradable.length > 0) {
        let device = this.upgradable.shift()
        this.add_log(`Upgrading device ${device.serial}`)
        this.add_log(`  ${device.description}`)
        let channel = device.run.channel
        if (channel == 'testing' && this.channels['stable'].version >= device.run.version) {
          // newer stable version available. switch to stable
          channel = 'stable'
        }
        this.add_log(`  Upgrading to latest release in ${channel} channel`)
        try {
          let r = await Vue.http.post(`device/${device.id}/channel`, {
            channel: device.run.channel,
          })
          let resp = await r.json()
          if (!resp.ok) {
            this.add_log(`  Cannot issue upgrade request. skipping`)
            continue
          }
        } catch (e) {
          this.add_log(`  Cannot issue upgrade request. skipping`)
          continue
        }
        this.add_log(`  Upgrade triggered. Waiting for reboot`)
        this.add_log(`  .. this usually takes 30-90 seconds`)
        let upgraded_device
        while (this.state == 'upgrading') {
          try {
            let r = await Vue.http.get(`device/${device.id}`)
            upgraded_device = await r.json()
          } catch (e) {
            this.add_log(`  Cannot fetch device info`)
            break
          }
          let now = +Date.now()/1000
          if (upgraded_device.run.restarted == device.run.restarted) {
            await sleep(15000)
            this.add_log(`  .. still waiting for reboot`)
            this.add_log(`     status: ${upgraded_device.status}`)
       // } else if (now < upgraded_device.run.restarted + 60) {
       //   await sleep(10000)
       //   this.add_log(`  .. waiting for device to run for a bit`)
          } else {
            break
          }
        }
        if (this.state == 'abort') {
          this.add_log(`  Upgrade aborted. Device will still finish its update`)
        } else if (upgraded_device.run.version == device.run.version) {
          this.add_log(`  Upgrade failed. Still running the same version`)
        } else {
          this.add_log(`  Upgrade successful. Now running ${upgraded_device.run.version}`)
        }
      }
      this.add_log(`Upgrades completed`)
      this.state = 'done'
    },
    async logout() {
      this.$store.dispatch('logout')
    },
    add_log(line) {
      this.log.push(line)
      this.$nextTick(() => {
        this.$refs.log.scrollTop = this.$refs.log.scrollHeight
      })
    }
  },
})

Vue.component('fleet-upgrader', {
  template: `
    <div class='upgrader'>
      <div class='centered'>
        <h1>Fleet Updater</h1>
      </div>
      <login-ui v-if='!$store.getters.is_logged_in'/>
      <upgrader-ui v-else/>
    </div>
  `,
})

// All info-beamer endpoints expect x-www-form-urlencoded
Vue.http.options.emulateJSON = true

// Check if there's any oauth relevant parameters in
// the current url and handle them.
await handle_url_params()

// Configure vue-resource for the info-beamer API
Vue.http.options.root = window.CONFIG.api_root
Vue.http.interceptors.push(request => {
  const api_key = store.state.access_token
  request.headers.set('Authorization', 'Bearer ' + api_key)
  return response => {
    if (response.status == 401) {
      store.commit('wipe')
    }
  }
})

// Now start the app. This will check he access token
// and fetch basic account info if possible.
await store.dispatch('init')

// Render the app
new Vue({el: '#app', store})

})()
