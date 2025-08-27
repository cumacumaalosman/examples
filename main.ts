addEventListener('fetch', event => {
  event.respondWith(handle(event.request))
})

const TARGET_HOST = 'https://ecsc-expat.sy:8443'

async function handle(request) {
  const origUrl = new URL(request.url)
  const targetUrl = new URL(TARGET_HOST)
  targetUrl.pathname = origUrl.pathname
  targetUrl.search = origUrl.search

  // استنساخ headers الأصلي مع تعديل بسيط
  const headers = new Headers(request.headers)

  // فرض Headers المطلوبة
  headers.set('Host', targetUrl.hostname)
  headers.set('Origin', `https://${targetUrl.hostname}`)
  headers.set('Referer', `https://${targetUrl.hostname}${origUrl.pathname}`)
  headers.set('Sec-Fetch-Site', 'same-site')
  headers.set('Sec-Fetch-Mode', 'cors')
  headers.set('Sec-Fetch-Dest', 'empty')
  headers.set('Alt-Used', targetUrl.hostname)

  // تسجيل كل Request headers
  console.log('Request Headers:', Object.fromEntries(headers.entries()))

  // قراءة body (مع استنساخه)
  let requestBody = null
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    requestBody = await request.clone().text()
    console.log('Request Body:', requestBody)
  }

  // التعامل مع OPTIONS (preflight)
  if (request.method === 'OPTIONS') {
    const origin = request.headers.get('Origin') || '*'
    const allowCredentials = origin && origin !== '*' ? 'true' : 'true' // نحتفظ بالقيمة true لكن ننصّح بوجود Origin عند الاستخدام من المتصفح
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
        'Access-Control-Allow-Credentials': allowCredentials,
        'Access-Control-Max-Age': '86400'
      }
    })
  }

  // إنشاء الطلب للأوريجن مع الكوكيز
  const proxiedRequest = new Request(targetUrl.toString(), {
    method: request.method,
    headers: headers,
    body: requestBody,
    redirect: 'manual'
  })

  let response
  try {
    response = await fetch(proxiedRequest, { credentials: 'include' })
  } catch (err) {
    return new Response('Bad gateway: ' + err.toString(), { status: 502 })
  }

  // تسجيل Response headers
  console.log('Response Headers:', Object.fromEntries(response.headers.entries()))

  // قراءة body
  const respBody = await response.clone().text()
  console.log('Response Body:', respBody)

  // --- معالجة وتحويل Set-Cookie خاصة بطلب تسجيل الدخول فقط ---
  // نلتقط كل Set-Cookie من الرد الأصلي
  const originalSetCookies = []
  for (const [k, v] of response.headers.entries()) {
    if (k.toLowerCase() === 'set-cookie') originalSetCookies.push(v)
  }

  // دالة تنقية / إعادة تشكيل Set-Cookie لتقبلها المتصفحات عند الرد عبر الـ worker
  function sanitizeSetCookie(sc) {
    // نحافظ على اسم=قيمة و onExpiry (Expires, Max-Age) لكن نحذف Domain ونعيد ضبط Path و SameSite و Secure و HttpOnly
    const parts = sc.split(';').map(p => p.trim())
    const nameValue = parts.shift() // أول جزء هو name=value
    let expires = null
    let maxAge = null

    for (const p of parts) {
      const [k, ...rest] = p.split('=')
      const key = k.trim().toLowerCase()
      if (key === 'expires') expires = `Expires=${rest.join('=')}`.trim()
      else if (key === 'max-age') maxAge = `Max-Age=${rest.join('=')}`.trim()
      // نتجاهل Domain, SameSite, Secure, HttpOnly, Path من الأصل لأننا سنحددهم هنا
    }

    const out = [nameValue]
    if (expires) out.push(expires)
    if (maxAge) out.push(maxAge)
    out.push('Path=/')
    out.push('HttpOnly')
    out.push('SameSite=None') // مطلوب لخورز-سايت
    out.push('Secure') // مطلوب مع SameSite=None
    return out.join('; ')
  }

  // بناء headers للرد النهائي
  const newHeaders = new Headers(response.headers)

  // حذف أي Set-Cookie أصلية حتى لا تُمرر كما هي
  if (originalSetCookies.length > 0) {
    newHeaders.delete('set-cookie')
  }

  // إذا كان المسار هو تسجيل الدخول على الـ worker path، نعيد تشكيل الكوكيز ونضيفها للرد
  // ملاحظة: المسار الذي طلبته هو '/secure/auth/login' على نطاق worker
  if (origUrl.pathname === '/secure/auth/login' && originalSetCookies.length > 0) {
    for (const sc of originalSetCookies) {
      const sanitized = sanitizeSetCookie(sc)
      // نضيف كل كوكي على حدة
      newHeaders.append('Set-Cookie', sanitized)
      console.log('Rewritten Set-Cookie:', sanitized)
    }
  }

  // إعداد CORS بطريقة تسمح بالإرسال مع credentials من المتصفح
  const requestOrigin = request.headers.get('Origin')
  if (requestOrigin) {
    newHeaders.set('Access-Control-Allow-Origin', requestOrigin)
    newHeaders.set('Access-Control-Allow-Credentials', 'true')
    newHeaders.set('Vary', 'Origin')
  } else {
    // fallback (قد يمنع حفظ الكوكيز عندما يكون Origin غير موجود)
    newHeaders.set('Access-Control-Allow-Origin', '*')
    newHeaders.set('Access-Control-Allow-Credentials', 'true')
  }
  newHeaders.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  newHeaders.set('Access-Control-Allow-Headers', '*')
  newHeaders.set('Access-Control-Expose-Headers', '*')

  return new Response(respBody, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  })
}
