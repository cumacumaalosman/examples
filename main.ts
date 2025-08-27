// main.ts  (Deno Deploy)
addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request))
})

const TARGET_HOST = 'https://ecsc-expat.sy:8443'

async function handle(request: Request): Promise<Response> {
  const origUrl = new URL(request.url)
  const targetUrl = new URL(TARGET_HOST)
  targetUrl.pathname = origUrl.pathname
  targetUrl.search = origUrl.search

  // استنساخ headers الأصلي مع حذف رؤوس ممنوعة مثل Host
  const headers = new Headers(request.headers)
  headers.delete('host')

  // رؤوس مفيدة فقط
  headers.set('Origin', `https://${targetUrl.hostname}`)
  headers.set('Referer', `https://${targetUrl.hostname}${origUrl.pathname}`)
  headers.set('Sec-Fetch-Site', 'same-site')
  headers.set('Sec-Fetch-Mode', 'cors')
  headers.set('Sec-Fetch-Dest', 'empty')

  console.log('Request Headers:', Object.fromEntries(headers.entries()))

  // قراءة body (نص أو ثنائي)
  let requestBody: BodyInit | null = null
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    try {
      requestBody = await request.clone().text()
    } catch {
      requestBody = await request.clone().arrayBuffer()
    }
    console.log('Request Body:', typeof requestBody === 'string' ? requestBody : '[binary]')
  }

  // التعامل مع OPTIONS (preflight)
  if (request.method === 'OPTIONS') {
    const origin = request.headers.get('Origin') || '*'
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
      }
    })
  }

  // بناء الطلب للأوريجن
  const proxiedRequest = new Request(targetUrl.toString(), {
    method: request.method,
    headers: headers,
    body: requestBody,
    redirect: 'manual'
  })

  let response: Response
  try {
    response = await fetch(proxiedRequest)
  } catch (err) {
    return new Response('Bad gateway: ' + String(err), { status: 502 })
  }

  console.log('Response Headers:', Object.fromEntries(response.headers.entries()))

  // قراءة body بأمان
  let respBody: string | ArrayBuffer
  try {
    respBody = await response.clone().text()
  } catch {
    respBody = await response.clone().arrayBuffer()
  }
  console.log('Response Body:', typeof respBody === 'string' ? (respBody as string).slice(0, 2000) : '[binary]')

  // جمع Set-Cookie الأصلية
  const originalSetCookies: string[] = []
  // محاولة API حديثة إذ وجدت
  // @ts-ignore
  if (typeof (response.headers as any).getSetCookie === 'function') {
    try {
      // @ts-ignore
      const arr = (response.headers as any).getSetCookie()
      if (Array.isArray(arr)) originalSetCookies.push(...arr)
    } catch {}
  }
  for (const [k, v] of response.headers.entries()) {
    if (k.toLowerCase() === 'set-cookie') originalSetCookies.push(v)
  }

  function sanitizeSetCookie(sc: string) {
    const parts = sc.split(';').map(p => p.trim())
    const nameValue = parts.shift() || ''
    let expires: string | null = null
    let maxAge: string | null = null

    for (const p of parts) {
      const [k, ...rest] = p.split('=')
      const key = k.trim().toLowerCase()
      if (key === 'expires') expires = `Expires=${rest.join('=')}`.trim()
      else if (key === 'max-age') maxAge = `Max-Age=${rest.join('=')}`.trim()
    }

    const out = [nameValue]
    if (expires) out.push(expires)
    if (maxAge) out.push(maxAge)
    out.push('Path=/')
    out.push('HttpOnly')
    out.push('SameSite=None')
    out.push('Secure')
    return out.join('; ')
  }

  const newHeaders = new Headers(response.headers)
  if (originalSetCookies.length > 0) {
    newHeaders.delete('set-cookie')
  }

  if (origUrl.pathname === '/secure/auth/login' && originalSetCookies.length > 0) {
    for (const sc of originalSetCookies) {
      const sanitized = sanitizeSetCookie(sc)
      newHeaders.append('Set-Cookie', sanitized)
      console.log('Rewritten Set-Cookie:', sanitized)
    }
  }

  // إعداد CORS للسماح بالـ credentials
  const requestOrigin = request.headers.get('Origin')
  if (requestOrigin) {
    newHeaders.set('Access-Control-Allow-Origin', requestOrigin)
    newHeaders.set('Access-Control-Allow-Credentials', 'true')
    newHeaders.set('Vary', 'Origin')
  } else {
    newHeaders.set('Access-Control-Allow-Origin', '*')
    newHeaders.set('Access-Control-Allow-Credentials', 'true')
  }
  newHeaders.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  newHeaders.set('Access-Control-Allow-Headers', '*')
  newHeaders.set('Access-Control-Expose-Headers', '*')

  return new Response(respBody as BodyInit, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  })
}
