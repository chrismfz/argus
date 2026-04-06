(function () {
  'use strict'

  function parseSearchTarget(raw) {
    const input = String(raw || '').trim()
    if (!input) return { ok: false, error: 'Enter an ASN or IP address.' }

    const asnMatch = input.match(/^AS\s*(\d+)$/i) || input.match(/^(\d+)$/)
    if (asnMatch) {
      const asn = Number(asnMatch[1])
      if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) {
        return { ok: false, error: 'ASN must be a number between 1 and 4294967295.' }
      }
      return { ok: true, kind: 'asn', value: String(asn), path: `/asn/${asn}` }
    }

    let ip = input
    if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1)

    if (isIPv4(ip) || isIPv6(ip)) {
      return { ok: true, kind: 'ip', value: ip, path: `/ip/${encodeURIComponent(ip)}` }
    }

    return { ok: false, error: 'Invalid input. Use AS12345, 12345, IPv4, or IPv6.' }
  }

  function isIPv4(ip) {
    const parts = ip.split('.')
    if (parts.length !== 4) return false
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return false
      const n = Number(p)
      if (n < 0 || n > 255) return false
    }
    return true
  }

  function isIPv6(ip) {
    if (!ip.includes(':')) return false
    if (/\s/.test(ip) || ip.includes('/')) return false
    try {
      // URL parser accepts compressed IPv6 forms and rejects malformed ones.
      const u = new URL(`http://[${ip}]/`)
      return Boolean(u && u.hostname)
    } catch {
      return false
    }
  }

  function ensureStyles() {
    if (document.getElementById('argus-nav-search-style')) return
    const style = document.createElement('style')
    style.id = 'argus-nav-search-style'
    style.textContent = `
      .argus-nav-search-mount{margin-left:auto;display:flex;align-items:center}
      .argus-nav-search{display:flex;align-items:center;gap:6px}
      .argus-nav-search input{width:220px;max-width:32vw;background:var(--bg3,#1e2535);border:1px solid var(--border,#2a3147);color:var(--text,#cdd6f4);border-radius:6px;padding:6px 9px;font-size:12px;outline:none}
      .argus-nav-search input:focus{border-color:var(--accent,#89b4fa)}
      .argus-nav-search button{background:var(--bg3,#1e2535);border:1px solid var(--border,#2a3147);color:var(--text,#cdd6f4);border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer}
      .argus-nav-search button:hover{border-color:var(--accent,#89b4fa);color:var(--accent,#89b4fa)}
      .argus-nav-search-error{font-size:11px;color:var(--red,#f38ba8);min-height:14px;margin-top:2px;text-align:right}
      @media(max-width:900px){.argus-nav-search input{width:160px;max-width:44vw}}
    `
    document.head.appendChild(style)
  }

  function mountNavSearch(mount, options) {
    if (!mount) return
    const opts = options || {}
    ensureStyles()

    mount.innerHTML = `
      <div>
        <form class="argus-nav-search" novalidate>
          <input type="text" placeholder="AS12345, 1.2.3.4, 2001:db8::1" aria-label="ASN or IP search" />
          <button type="submit">Go</button>
        </form>
        <div class="argus-nav-search-error" aria-live="polite"></div>
      </div>
    `

    const form = mount.querySelector('form')
    const input = mount.querySelector('input')
    const error = mount.querySelector('.argus-nav-search-error')

    form.addEventListener('submit', function (ev) {
      ev.preventDefault()
      const parsed = parseSearchTarget(input.value)
      if (!parsed.ok) {
        error.textContent = parsed.error
        input.setAttribute('aria-invalid', 'true')
        return
      }

      error.textContent = ''
      input.removeAttribute('aria-invalid')
      if (typeof opts.onNavigate === 'function') {
        opts.onNavigate(parsed)
        return
      }
      window.location.href = parsed.path
    })

    input.addEventListener('input', function () {
      if (error.textContent) {
        error.textContent = ''
        input.removeAttribute('aria-invalid')
      }
    })
  }

  window.argusParseSearchTarget = parseSearchTarget
  window.mountArgusNavSearch = mountNavSearch
})()
