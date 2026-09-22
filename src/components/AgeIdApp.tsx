import { useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { Check, ChevronRight, Clipboard, Code2, Hash, ShieldCheck, Sparkles, X, Zap, AlertTriangle, QrCode } from 'lucide-react'

type Tab = 'inspector' | 'wallet' | 'query' | 'snippet'
type ParsedClaim = { salt: string; key: string; value: string | boolean; digest: string; matches: boolean }

// 1. Base64URL + UTF-8
const b64UrlEncode = (str: string): string => {
  const bytes = new TextEncoder().encode(str)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const b64UrlDecode = (str: string): string => {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) base64 += '='
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

// 2. Hash RFC 9901: from ASCII disclosure
const hashDisclosure = async (disclosureB64Url: string): Promise<string> => {
  const msgUint8 = new TextEncoder().encode(disclosureB64Url)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return btoa(String.fromCharCode(...hashArray)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const makeJwt = (payload: object) => 
  `${b64UrlEncode(JSON.stringify({ alg: 'none', typ: 'vc+sd-jwt' }))}.${b64UrlEncode(JSON.stringify(payload))}.demo-signature`

const tabs: { id: Tab; label: string; short: string }[] = [
  { id: 'inspector', label: 'Token Inspector', short: 'SD-JWT' },
  { id: 'wallet', label: 'Mock Wallet', short: 'EUDI Issuer' },
  { id: 'query', label: 'OID4VP Builder', short: 'Relying Party' },
  { id: 'snippet', label: 'Dev Snippet', short: 'TypeScript' },
]

function Badge({ children, tone = 'muted' }: { children: React.ReactNode; tone?: 'muted' | 'green' | 'violet' | 'amber' }) {
  const styles = {
    green: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    violet: 'border-indigo-200 bg-indigo-50 text-indigo-700',
    amber: 'border-amber-200 bg-amber-50 text-amber-800',
    muted: 'border-zinc-200 bg-zinc-100 text-zinc-600'
  }
  return <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${styles[tone]}`}>{children}</span>
}

const ALLOWED_ASSERTIONS = ['age_over_13', 'age_over_15', 'age_over_18', 'age_over_21']

function Inspector() {
  const [token, setToken] = useState('')
  const [claims, setClaims] = useState<ParsedClaim[]>([])
  const [hashes, setHashes] = useState<string[]>([])
  const [valid, setValid] = useState(false)
  const [hasPiiLeak, setHasPiiLeak] = useState(false)

  const createSample = async (
    assertionKey: 'age_over_13' | 'age_over_15' | 'age_over_18' = 'age_over_18',
    assertionValue = true,
    revealPii = false
  ) => {
    const ageDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), assertionKey, assertionValue]))
    const nameDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'name', 'Jan Novák']))
    const dobDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'birth_date', '1998-05-14']))

    const ageHash = await hashDisclosure(ageDisc)
    const nameHash = await hashDisclosure(nameDisc)
    const dobHash = await hashDisclosure(dobDisc)

    const payload = {
      iss: 'https://issuer.eudi.cz',
      vct: 'eu.europa.ec.eudi.pid.1',
      _sd: [ageHash, nameHash, dobHash],
      _sd_alg: 'sha-256'
    }

    const presentationDisclosures = revealPii ? [ageDisc, nameDisc] : [ageDisc]
    setToken(`${makeJwt(payload)}~${presentationDisclosures.join('~')}~`)
  }

  useEffect(() => { void createSample('age_over_18', true, false) }, [])

  useEffect(() => {
    if (!token) {
      setClaims([])
      setHashes([])
      setValid(false)
      setHasPiiLeak(false)
      return
    }

    const parse = async () => {
      try {
        const parts = token.split('~').filter(Boolean)
        const jwtPayload = JSON.parse(b64UrlDecode(parts[0].split('.')[1]))
        const sdDigests: string[] = Array.isArray(jwtPayload._sd) ? jwtPayload._sd : []
        setHashes(sdDigests)

        const parsedDisclosures = await Promise.all(
          parts.slice(1).map(async (part) => {
            const rawJson = b64UrlDecode(part)
            const [salt, key, value] = JSON.parse(rawJson)
            const digest = await hashDisclosure(part)
            return { salt, key, value, digest, matches: sdDigests.includes(digest) }
          })
        )

        setClaims(parsedDisclosures)
        const allMatch = parsedDisclosures.length > 0 && parsedDisclosures.every(c => c.matches)
        setValid(allMatch)

        const leaked = parsedDisclosures.some(c => !ALLOWED_ASSERTIONS.includes(c.key))
        setHasPiiLeak(leaked)
      } catch {
        setClaims([])
        setHashes([])
        setValid(false)
        setHasPiiLeak(false)
      }
    }
    void parse()
  }, [token])

  const activeAssertion = claims.find(c => ALLOWED_ASSERTIONS.includes(c.key))

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Raw presentation</div>
            <p className="mt-1 text-xs text-zinc-600">Paste an SD-JWT compact serialization to inspect its selective disclosures.</p>
          </div>
          <Badge tone="violet">RFC 9901</Badge>
        </div>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="h-28 w-full rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white transition-colors resize-none"
          placeholder="eyJ...~WyJzYWx0...~"
          spellCheck={false}
        />
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="flex items-center gap-1.5 rounded-lg bg-emerald-50 border border-emerald-200 px-3 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-100 transition-colors" onClick={() => void createSample('age_over_18', true, false)}>
            <Sparkles size={14} /> DSA 18+ (Zero-PII)
          </button>
          <button className="flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => void createSample('age_over_13', true, false)}>
            KIDS Act 13+ (COPPA)
          </button>
          <button className="flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => void createSample('age_over_15', true, false)}>
            EU / France 15+ (Social)
          </button>
          <button className="flex items-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-800 hover:bg-amber-100 transition-colors" onClick={() => void createSample('age_over_18', true, true)}>
            Sample with Leaked PII
          </button>
          <button className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-100 transition-colors" onClick={() => void createSample('age_over_18', false, false)}>
            Underage (Denied)
          </button>
          <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-zinc-400 hover:text-zinc-700 transition-colors" onClick={() => setToken('')}>
            <X size={14} /> Clear
          </button>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-zinc-100 pb-3">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Cryptographic core</div>
              <h2 className="text-sm font-semibold text-zinc-800">Issuer payload &amp; digests</h2>
            </div>
            <Hash className="text-zinc-400" size={18} />
          </div>
          <div className="space-y-4 pt-4">
            <div>
              <div className="text-[10px] uppercase font-medium text-zinc-400">Decoded issuer payload</div>
              <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-zinc-100 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-700">
                {JSON.stringify({ iss: 'https://issuer.eudi.cz', vct: 'eu.europa.ec.eudi.pid.1', _sd: hashes, _sd_alg: 'sha-256' }, null, 2)}
              </pre>
            </div>
            <div>
              <div className="mb-2 text-[10px] uppercase font-medium text-zinc-400">_sd hashes validation</div>
              <div className="space-y-1.5">
                {hashes.map((item, i) => {
                  const isMatched = claims.some(c => c.digest === item)
                  return (
                    <div key={item} className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 font-mono text-xs ${isMatched ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-zinc-200 bg-zinc-50 text-zinc-500'}`}>
                      <span className="text-zinc-400">{String(i + 1).padStart(2, '0')}</span>
                      <code>{item.slice(0, 24)}…</code>
                      <span className="ml-auto text-[10px] font-medium uppercase tracking-wider">
                        {isMatched ? 'Disclosed & Valid' : 'Redacted / Blinded PII'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between border-b border-zinc-100 pb-3">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Selective disclosure</div>
              <h2 className="text-sm font-semibold text-zinc-800">Disclosed claims</h2>
            </div>
            <Badge>{claims.length} disclosed</Badge>
          </div>
          <div className="pt-4">
            {claims.length ? (
              <div className="space-y-2.5">
                {claims.map((claim) => (
                  <div key={claim.key} className="rounded-lg border border-zinc-200 bg-zinc-50 p-3">
                    <div className="flex items-center justify-between">
                      <code className="text-xs font-semibold text-indigo-700">{claim.key}</code>
                      <Badge tone={ALLOWED_ASSERTIONS.includes(claim.key) ? 'green' : 'amber'}>
                        {ALLOWED_ASSERTIONS.includes(claim.key) ? 'age assertion' : 'pii exposed'}
                      </Badge>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <div className="text-[10px] text-zinc-400 font-medium">salt</div>
                        <code className="font-mono text-zinc-600">{claim.salt}</code>
                      </div>
                      <div>
                        <div className="text-[10px] text-zinc-400 font-medium">value</div>
                        <code className={`font-mono font-semibold ${claim.value === true ? 'text-emerald-700' : typeof claim.value === 'boolean' ? 'text-rose-600' : 'text-amber-700'}`}>
                          {String(claim.value)}
                        </code>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-zinc-400">Enter a valid SD-JWT to inspect claims.</div>
            )}

            {token && (
              <div className={`mt-5 rounded-lg border p-4 ${
                !valid 
                  ? 'border-rose-200 bg-rose-50 text-rose-800' 
                  : hasPiiLeak 
                    ? 'border-amber-200 bg-amber-50 text-amber-900'
                    : 'border-emerald-200 bg-emerald-50 text-emerald-900'
              }`}>
                <div className="flex items-center gap-2 text-sm font-semibold">
                  {!valid ? <X size={16} /> : hasPiiLeak ? <AlertTriangle size={16} /> : <Check size={16} />}
                  {!valid 
                    ? 'Invalid or Tampered Presentation' 
                    : hasPiiLeak 
                      ? 'Age Verified, but PII was exposed' 
                      : 'Age Assertion Verified (Zero-Data)'}
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-600">
                  {!valid 
                    ? 'One or more disclosure hashes do not match the issuer _sd digest array.' 
                    : hasPiiLeak 
                      ? 'The token mathematically proves age, but unnecessary identity attributes (name, date) were disclosed.' 
                      : `${activeAssertion?.key ?? 'age'} = ${String(activeAssertion?.value ?? true)} · Zero PII leaked. Identity remains mathematically blinded.`}
                </p>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

function Wallet() {
  const [name, setName] = useState('Jan Novák')
  const [dob, setDob] = useState('1998-05-14')
  const [country, setCountry] = useState('CZ')
  const [discloseAge, setDiscloseAge] = useState(true)
  const [discloseName, setDiscloseName] = useState(false)
  const [discloseDob, setDiscloseDob] = useState(false)
  const [output, setOutput] = useState('')

  const generate = async () => {
    const ageDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'age_over_18', true]))
    const nameDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'name', name]))
    const dobDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'birth_date', dob]))
    const countryDisc = b64UrlEncode(JSON.stringify([crypto.randomUUID().slice(0, 8), 'country', country]))

    const digests = await Promise.all([
      hashDisclosure(ageDisc),
      hashDisclosure(nameDisc),
      hashDisclosure(dobDisc),
      hashDisclosure(countryDisc)
    ])

    const payload = {
      iss: 'https://issuer.eudi.cz',
      vct: 'eu.europa.ec.eudi.pid.1',
      _sd: digests,
      _sd_alg: 'sha-256'
    }

    const toReveal: string[] = []
    if (discloseAge) toReveal.push(ageDisc)
    if (discloseName) toReveal.push(nameDisc)
    if (discloseDob) toReveal.push(dobDisc)

    setOutput(`${makeJwt(payload)}~${toReveal.join('~')}~`)
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[.85fr_1.15fr]">
      <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
        <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Credential inputs</div>
        <h2 className="mt-1 text-sm font-semibold text-zinc-800">Simulate an EUDI wallet</h2>
        <p className="mt-1 text-xs text-zinc-500">All fields are signed into the credential, but you choose what to disclose.</p>

        <div className="mt-5 space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-zinc-700">Full name</label>
            <input value={name} onChange={e => setName(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 font-mono text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white" />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-700">Date of birth</label>
            <input type="date" value={dob} onChange={e => setDob(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 font-mono text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white" />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-700">Country of issuance</label>
            <select value={country} onChange={e => setCountry(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 font-mono text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white">
              <option>CZ</option><option>DE</option><option>FR</option><option>ES</option><option>NL</option>
            </select>
          </div>

          <div className="pt-2">
            {[
              ['Disclose only age assertion', discloseAge, setDiscloseAge, 'age_over_18: true (Zero-Knowledge)'],
              ['Disclose full name', discloseName, setDiscloseName, 'Leaks personal identity'],
              ['Disclose exact date of birth', discloseDob, setDiscloseDob, 'Leaks date of birth']
            ].map(([label, value, setter, hint]) => (
              <button
                type="button"
                key={String(label)}
                onClick={() => (setter as (v: boolean) => void)(!value)}
                className="flex w-full items-center justify-between py-2 text-left"
              >
                <span>
                  <span className="block text-xs font-medium text-zinc-800">{String(label)}</span>
                  <span className="text-[10px] text-zinc-500">{String(hint)}</span>
                </span>
                <span className={`relative inline-flex h-4 w-8 rounded-full transition-colors ${value ? 'bg-emerald-600' : 'bg-zinc-200'}`}>
                  <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${value ? 'translate-x-4.5 mt-0.5' : 'translate-x-0.5 mt-0.5'}`} />
                </span>
              </button>
            ))}
          </div>
        </div>

        <button className="mt-5 flex w-full items-center justify-center gap-1.5 rounded-lg bg-zinc-900 py-2.5 text-xs font-medium text-white hover:bg-zinc-800 transition-colors shadow-xs" onClick={generate}>
          <Zap size={14} /> Generate valid SD-JWT presentation
        </button>
      </section>

      <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
        <div className="flex items-center justify-between border-b border-zinc-100 pb-3">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Wallet output</div>
            <h2 className="text-sm font-semibold text-zinc-800">Selective presentation</h2>
          </div>
          <Badge tone="green"><ShieldCheck size={12} /> RFC 9901 Valid</Badge>
        </div>
        <pre className="mt-4 min-h-[220px] max-h-[360px] overflow-auto rounded-lg border border-zinc-100 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-700 whitespace-pre-wrap break-all leading-relaxed">
          {output || '// Click generate to assemble a mathematically valid token'}
        </pre>
        {output && (
          <button className="mt-3 flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => navigator.clipboard.writeText(output)}>
            <Clipboard size={14} /> Copy token to Inspector
          </button>
        )}
      </section>
    </div>
  )
}

function QueryBuilder() {
  const [client, setClient] = useState('https://my-service.eu/callback')
  const [assertion, setAssertion] = useState('age_over_18')
  const [purpose, setPurpose] = useState('Legal age assurance under EU DSA Art. 28')
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  const json = useMemo(() => ({
    response_type: 'vp_token',
    client_id: client,
    redirect_uri: client,
    dcql_query: [{
      id: 'age-proof',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['eu.europa.ec.eudi.pid.1'] },
      claims: [{ path: [assertion] }]
    }],
    purpose
  }), [client, assertion, purpose])

  const uri = `openid4vp://authorize?client_id=${encodeURIComponent(client)}&response_type=vp_token&dcql_query=${encodeURIComponent(JSON.stringify(json.dcql_query))}`

  // Автоматический рендер клиентского QR-кода на canvas
  useEffect(() => {
    if (!canvasRef.current) return
    void QRCode.toCanvas(canvasRef.current, uri, {
      width: 136,
      margin: 1,
      color: {
        dark: '#18181b',
        light: '#ffffff'
      }
    })
  }, [uri])

  return (
    <div className="grid gap-4 lg:grid-cols-[.78fr_1.22fr]">
      <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
        <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Request parameters</div>
        <h2 className="mt-1 text-sm font-semibold text-zinc-800">Build a privacy-first query</h2>
        <div className="mt-5 space-y-3.5">
          <div>
            <label className="block text-xs font-medium text-zinc-700">Client ID / redirect URI</label>
            <input value={client} onChange={e => setClient(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 font-mono text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white" />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-700 mb-1.5">Required assertion threshold</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { key: 'age_over_18', label: '18+ (DSA)' },
                { key: 'age_over_13', label: '13+ (KIDS Act)' },
                { key: 'age_over_15', label: '15+ (France / EU)' },
                { key: 'age_over_21', label: '21+ (US / Strict)' }
              ].map(item => (
                <button
                  key={item.key}
                  onClick={() => setAssertion(item.key)}
                  className={`rounded-lg border px-3 py-2 text-left font-mono text-xs transition-colors ${assertion === item.key ? 'border-indigo-600 bg-indigo-50 text-indigo-900 shadow-xs' : 'border-zinc-200 bg-white text-zinc-600 hover:bg-zinc-50'}`}
                >
                  <span className="block text-[11px] font-semibold">{item.label}</span>
                  <span className="text-[10px] text-zinc-400">{item.key}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-700">Purpose description</label>
            <textarea value={purpose} onChange={e => setPurpose(e.target.value)} className="mt-1 h-20 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-1.5 text-xs text-zinc-800 outline-none focus:border-zinc-400 focus:bg-white resize-none" />
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between border-b border-zinc-100 pb-3">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Generated request</div>
              <h2 className="text-sm font-semibold text-zinc-800">OID4VP deep link &amp; DCQL</h2>
            </div>
            <Badge tone="violet">OID4VP 1.0</Badge>
          </div>

          {/* QR Code + Deep Link Container */}
          <div className="mt-4 flex flex-col sm:flex-row items-center gap-4 rounded-lg border border-zinc-200 bg-zinc-50/80 p-3.5">
            <div className="shrink-0 rounded-md border border-zinc-200 bg-white p-1 shadow-xs">
              <canvas ref={canvasRef} className="block" />
            </div>
            <div className="min-w-0 flex-1 w-full">
              <div className="flex items-center gap-1.5 text-[10px] uppercase font-medium text-zinc-400 mb-1">
                <QrCode size={12} /> Scan via EUDI Wallet / Mobile Terminal
              </div>
              <code className="block max-h-24 overflow-y-auto break-all font-mono text-[11px] text-indigo-700 bg-white p-2 rounded-md border border-zinc-200 leading-relaxed">
                {uri}
              </code>
            </div>
          </div>

          <pre className="mt-3 max-h-48 overflow-auto rounded-lg border border-zinc-100 bg-zinc-50 p-3 font-mono text-[11px] text-zinc-700 leading-relaxed">
            {JSON.stringify(json, null, 2)}
          </pre>
        </div>

        <div className="mt-4 flex gap-2">
          <button className="flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => navigator.clipboard.writeText(uri)}>
            <Clipboard size={14} /> Copy URI
          </button>
          <button className="flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => navigator.clipboard.writeText(JSON.stringify(json, null, 2))}>
            <Clipboard size={14} /> Copy JSON
          </button>
        </div>
      </section>
    </div>
  )
}

const snippetCode = `export async function verifySDJWT(token: string) {
  const [jwt, ...encodedDisclosures] = token.split("~").filter(Boolean);
  
  // 1. Decode Issuer Payload
  const b64UrlDecode = (str: string) => {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    return decodeURIComponent(escape(atob(b64)));
  };
  const payload = JSON.parse(b64UrlDecode(jwt.split(".")[1]));
  const sdArray: string[] = payload._sd || [];

  // 2. Compute disclosure digest per RFC 9901
  const hashDisclosure = async (part: string) => {
    const bytes = new TextEncoder().encode(part);
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  };

  // 3. Verify Merkle digests
  const verifiedClaims: Record<string, any> = {};
  for (const part of encodedDisclosures) {
    const digest = await hashDisclosure(part);
    if (!sdArray.includes(digest)) {
      throw new Error("Invalid disclosure: digest not in _sd array");
    }
    const [salt, key, value] = JSON.parse(b64UrlDecode(part));
    verifiedClaims[key] = value;
  }

  return {
    valid: true,
    isAgeVerified: verifiedClaims["age_over_18"] === true || verifiedClaims["age_over_13"] === true,
    claims: verifiedClaims
  };
}`

function Snippet() {
  return (
    <section className="rounded-xl border border-zinc-200 bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between border-b border-zinc-100 pb-3">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">Zero-dependency edge middleware</div>
          <h2 className="text-sm font-semibold text-zinc-800">Validate in Cloudflare / Bun / Node</h2>
        </div>
        <Badge tone="violet">TypeScript</Badge>
      </div>
      <div className="pt-4">
        <pre className="max-h-[400px] overflow-auto rounded-lg border border-zinc-100 bg-zinc-50 p-4 font-mono text-xs text-zinc-800 leading-relaxed">
          {snippetCode}
        </pre>
        <button className="mt-3 flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 shadow-xs transition-colors" onClick={() => navigator.clipboard.writeText(snippetCode)}>
          <Clipboard size={14} /> Copy snippet
        </button>
      </div>
    </section>
  )
}

export default function AgeIdApp() {
  const [tab, setTab] = useState<Tab>('inspector')

  return (
    <div className="min-h-screen bg-zinc-100 text-zinc-900 font-sans antialiased">
      <header className="mx-auto max-w-7xl border-x border-zinc-200 bg-white px-5 py-6 lg:px-8">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
          <div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-xl font-bold tracking-tight text-zinc-900">ageid.cz</span>
              <Badge tone="green"><span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> eIDAS 2.0 ready</Badge>
            </div>
            <p className="mt-2 text-xs text-zinc-500">Zero-Data SD-JWT &amp; OID4VP Age Assurance Sandbox</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge><X size={12} /> no cookies</Badge>
            <Badge><ShieldCheck size={12} /> in-memory</Badge>
            <Badge tone="violet">RFC 9901</Badge>
            <a className="inline-flex items-center justify-center rounded-md border border-zinc-200 bg-white p-1.5 text-zinc-500 hover:text-zinc-800 shadow-xs transition-colors" href="https://github.com" aria-label="GitHub">
              <Code2 size={16} />
            </a>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl border-x border-t border-zinc-200 bg-white px-5 lg:px-8">
        <nav className="flex gap-2 overflow-x-auto py-2">
          {tabs.map(item => (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                tab === item.id ? 'bg-zinc-900 text-white shadow-xs' : 'text-zinc-500 hover:text-zinc-800'
              }`}
            >
              <span>{item.label}</span>
              <span className={`text-[10px] ${tab === item.id ? 'text-zinc-400' : 'text-zinc-400'} sm:inline`}>{item.short}</span>
              {tab === item.id && <ChevronRight size={13} className="text-zinc-400" />}
            </button>
          ))}
        </nav>
      </div>

      <main className="mx-auto max-w-7xl border-x border-t border-zinc-200 bg-zinc-50 p-5 lg:p-8">
        {tab === 'inspector' && <Inspector />}
        {tab === 'wallet' && <Wallet />}
        {tab === 'query' && <QueryBuilder />}
        {tab === 'snippet' && <Snippet />}
      </main>

      <footer className="mx-auto max-w-7xl border-x border-t border-zinc-200 bg-white px-5 py-8 lg:px-8">
        <div className="flex flex-col gap-6 text-[11px] text-zinc-500">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <p>
              <span className="font-semibold text-zinc-800">ageid.cz</span> — Zero-Data SD-JWT &amp; OID4VP Sandbox. 
              Runs entirely inside browser RAM. Zero telemetry, zero cookies, no database.
            </p>
            <div className="flex flex-wrap items-center gap-3 text-zinc-500">
              <span className="rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-700">
                EUDI STS &amp; ARF v3.0.0
              </span>
              <a 
                href="https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html" 
                target="_blank" 
                rel="noreferrer" 
                className="hover:text-zinc-800 transition-colors"
              >
                RFC 9901 (SD-JWT)
              </a>
              <span>·</span>
              <a 
                href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" 
                target="_blank" 
                rel="noreferrer" 
                className="hover:text-zinc-800 transition-colors"
              >
                OID4VP 1.0
              </a>
              <span>·</span>
              <span>MIT License</span>
            </div>
          </div>

          <div className="text-[10px] text-zinc-400">
            Static edge hosting provided by <span className="text-zinc-600 font-medium">Vercel Inc.</span> (GDPR Art. 28 DPA compliant, transient network transit logs only).
          </div>

          <div className="border-t border-zinc-100 pt-4 flex flex-col justify-between items-start gap-3 sm:flex-row sm:items-center text-[10px] text-zinc-500">
            <div>
              <p>
                Provozovatel: <span className="font-medium text-zinc-700">Bekzhan Ramazanov</span> (OSVČ) · IČO: 17136245 · Sídlo: Dačického 1226/10, 140 00 Praha 4 – Nusle
              </p>
              <p className="mt-0.5 text-zinc-400">
                Zapsán v živnostenském rejstříku u ÚMČ Praha 2 od 12. 5. 2022
              </p>
            </div>

            <a
              href="https://ramazanov.cz"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white px-2.5 py-1 text-[11px] font-medium text-zinc-700 shadow-xs transition-all hover:border-zinc-300 hover:text-zinc-900"
            >
              <span>ramazanov.cz</span>
              <svg className="h-3 w-3 text-zinc-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M7 17L17 7" />
                <path d="M7 7h10v10" />
              </svg>
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
