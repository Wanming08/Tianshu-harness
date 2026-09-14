import { after, describe, it, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import dns from 'node:dns/promises'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import undici from 'undici'
import type { PinnedLookup } from '../../../tools/net/http-fetch.js'
import { TokenStore } from '../../../auth/token-store.js'
import type { McpOAuthProvider } from '../types.js'

const testDir = mkdtempSync(join(tmpdir(), 'mcp-oauth-security-'))
process.env.RIVET_HOME = testDir
const portProbe = createServer()
await new Promise<void>(resolve => portProbe.listen(0, '127.0.0.1', resolve))
const address = portProbe.address()
assert.ok(address && typeof address !== 'string')
process.env.RIVET_OAUTH_PORT = String(address.port)
await new Promise<void>((resolve, reject) => portProbe.close(err => err ? reject(err) : resolve()))
const { getMcpAccessToken, startMcpOAuth } = await import('../connector.js')
const callbackFetch = globalThis.fetch

after(() => rmSync(testDir, { recursive: true, force: true }))

type Flow = 'exchange' | 'refresh'
let nextServerId = 0

function setup(t: TestContext, endpoint: string, resolvedAddress = '93.184.216.34') {
  const requests: Array<{ url: string; init: undici.RequestInit | undefined }> = []
  const lookup = t.mock.method(dns, 'lookup', async () => ({
    address: resolvedAddress,
    family: resolvedAddress.includes(':') ? 6 : 4,
  }))
  const respond = async (url: string | URL | Request, init?: undici.RequestInit) => {
    requests.push({ url: String(url), init })
    return new undici.Response(JSON.stringify({ access_token: 'fixture-access', expires_in: 3600 }))
  }
  // Both transports are intercepted so a regression cannot send fixture credentials.
  t.mock.method(globalThis, 'fetch', respond)
  t.mock.method(undici, 'fetch', respond)
  const provider: McpOAuthProvider = {
    id: 'fixture', name: 'Fixture', authorizeUrl: 'https://provider.example/authorize',
    tokenEndpoint: endpoint, defaultScopes: [], clientIdHelp: '',
  }
  const run = async (flow: Flow): Promise<unknown> => {
    const id = `${flow}-${++nextServerId}`
    if (flow === 'refresh') {
      new TokenStore(join(testDir, 'mcp-oauth'), id).save({
        accessToken: 'fixture-expired', refreshToken: 'fixture-refresh', expiresAt: 0,
      })
      return getMcpAccessToken(id, provider, 'fixture-client')
    }
    let callback: Promise<Response> | undefined
    t.mock.method(process.stderr, 'write', (chunk: string | Uint8Array) => {
      const text = String(chunk)
      if (text.startsWith('Open this URL to connect MCP:\n')) {
        const auth = new URL(text.trim().split('\n')[1]!)
        const redirect = new URL(auth.searchParams.get('redirect_uri')!)
        redirect.searchParams.set('state', auth.searchParams.get('state')!)
        redirect.searchParams.set('code', 'fixture-code')
        callback = callbackFetch(redirect)
      }
      return true
    })
    try { return await startMcpOAuth(id, provider, 'fixture-client') }
    finally { await callback }
  }
  return { requests, lookup, run }
}

for (const flow of ['exchange', 'refresh'] as const) {
  describe(`${flow} token endpoint security`, () => {
    for (const [endpoint, ip] of [
      ['http://localhost/token', '127.0.0.1'],
      ['http://127.0.0.1/token', '127.0.0.1'],
      ['http://[::1]/token', '::1'],
      ['http://169.254.169.254/token', '169.254.169.254'],
      ['https://provider.example/token', '10.0.0.1'],
      ['http://[::ffff:127.0.0.1]/token', '::ffff:127.0.0.1'],
    ]) {
      it(`blocks ${endpoint} resolving to ${ip} before sending credentials`, async t => {
        const fixture = setup(t, endpoint!, ip!)
        await assert.rejects(() => fixture.run(flow), /private|reserved|denied/i)
        assert.equal(fixture.requests.length, 0)
      })
    }

    it('fails closed when DNS lookup fails', async t => {
      const fixture = setup(t, 'https://unresolved.example/token')
      fixture.lookup.mock.mockImplementation(async () => { throw new Error('fixture DNS failure') })
      await assert.rejects(() => fixture.run(flow), /fixture DNS failure/)
      assert.equal(fixture.requests.length, 0)
    })

    it('applies the OAuth deadline while DNS is still pending', async t => {
      const fixture = setup(t, 'https://unresolved.example/token')
      fixture.lookup.mock.mockImplementation(() => new Promise<never>(() => {}))
      const deadline = new AbortController()
      const expired = new Error('fixture OAuth deadline')
      t.mock.method(AbortSignal, 'timeout', () => {
        queueMicrotask(() => deadline.abort(expired))
        return deadline.signal
      })
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        const outcome = await Promise.race([
          fixture.run(flow).then(() => 'unexpected success', error => error),
          new Promise(resolve => { timer = setTimeout(() => resolve('still waiting for DNS'), 500) }),
        ])
        assert.equal(outcome, expired)
        assert.equal(fixture.requests.length, 0)
      } finally { clearTimeout(timer) }
    })

    it('rejects non-HTTP endpoints before sending credentials', async t => {
      const fixture = setup(t, 'file:///tmp/oauth-token')
      await assert.rejects(() => fixture.run(flow), /protocol/i)
      assert.equal(fixture.requests.length, 0)
    })

    it('sends a form POST to a public endpoint with redirects disabled', async t => {
      const fixture = setup(t, 'https://provider.example/token')
      const value = await fixture.run(flow)
      assert.equal(flow === 'refresh' ? value : (value as { accessToken: string }).accessToken, 'fixture-access')
      assert.equal(fixture.requests.length, 1)
      const request = fixture.requests[0]!
      assert.equal(request.init?.method, 'POST')
      assert.equal(request.init?.redirect, 'error')
      const body = new URLSearchParams(String(request.init?.body))
      assert.equal(body.get('grant_type'), flow === 'refresh' ? 'refresh_token' : 'authorization_code')
      assert.equal(body.get('client_id'), 'fixture-client')
      assert.equal(body.get(flow === 'refresh' ? 'refresh_token' : 'code'), flow === 'refresh' ? 'fixture-refresh' : 'fixture-code')
    })

    it('pins the socket lookup to the checked address even when web-fetch pinning is disabled', async t => {
      const previous = process.env.RIVET_FETCH_PIN
      process.env.RIVET_FETCH_PIN = '0'
      t.after(() => {
        if (previous === undefined) delete process.env.RIVET_FETCH_PIN
        else process.env.RIVET_FETCH_PIN = previous
      })
      const fixture = setup(t, 'https://rebind.example/token')
      let agentOptions: undici.Agent.Options | undefined
      const RealAgent = undici.Agent
      t.mock.method(undici, 'Agent', function (options: undici.Agent.Options) {
        agentOptions = options
        return new RealAgent(options)
      })
      await fixture.run(flow)
      // The attacker changes DNS after preflight. The connection's resolver must
      // still return the originally checked address without resolving it again.
      fixture.lookup.mock.mockImplementation(async () => ({ address: '127.0.0.1', family: 4 }))
      const connect = agentOptions?.connect
      assert.ok(connect && typeof connect === 'object')
      const lookup = (connect as { lookup?: PinnedLookup }).lookup
      assert.equal(typeof lookup, 'function')
      const pinned = await new Promise<string>((resolve, reject) => {
        lookup!('rebind.example', {}, (err, address) => {
          if (err) reject(err)
          else resolve(address as string)
        })
      })
      assert.equal(pinned, '93.184.216.34')
      assert.equal(fixture.lookup.mock.callCount(), 1)
    })

    it('releases the pinned dispatcher when reading the token response fails', async t => {
      const fixture = setup(t, 'https://provider.example/token')
      let dispatcher: undici.Dispatcher | undefined
      t.mock.method(undici, 'fetch', async (_url: Parameters<typeof undici.fetch>[0], init?: undici.RequestInit) => {
        dispatcher = init?.dispatcher
        return new undici.Response(new ReadableStream({
          start(controller) { controller.error(new Error('fixture body failure')) },
        }))
      })
      await assert.rejects(() => fixture.run(flow), /fixture body failure/)
      assert.ok(dispatcher instanceof undici.Agent)
      assert.equal(dispatcher.destroyed, true)
    })
  })
}
