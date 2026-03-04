// Netlify Serverless Function: Google Calendar API 連携
// 環境変数:
//   GOOGLE_SERVICE_ACCOUNT_EMAIL - サービスアカウントのメール
//   GOOGLE_PRIVATE_KEY - サービスアカウントの秘密鍵 (PEM形式)
//   GOOGLE_CALENDAR_EMAIL - カレンダー操作対象のメールアドレス (例: recruit@madoguchi.inc)

const crypto = require('crypto');

// ===== JWT 作成 & アクセストークン取得 =====
function createJWT(serviceAccountEmail, privateKey, userEmail) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccountEmail,
    sub: userEmail,
    scope: 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  const encHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const input = `${encHeader}.${encPayload}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(input);
  const signature = sign.sign(privateKey, 'base64url');

  return `${input}.${signature}`;
}

async function getAccessToken(serviceAccountEmail, privateKey, userEmail) {
  const jwt = createJWT(serviceAccountEmail, privateKey, userEmail);
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || JSON.stringify(data));
  return data.access_token;
}

// ===== FreeBusy: 空き時間取得 =====
async function getFreeBusy(accessToken, emails, timeMin, timeMax) {
  const res = await fetch('https://www.googleapis.com/calendar/v3/freeBusy', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      timeMin,
      timeMax,
      timeZone: 'Asia/Tokyo',
      items: emails.map(email => ({ id: email })),
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));

  // 空き時間スロットを計算
  const result = {};
  for (const email of emails) {
    const cal = data.calendars?.[email];
    if (cal?.errors) {
      result[email] = { error: cal.errors[0]?.reason || 'unknown' };
      continue;
    }
    result[email] = {
      busy: (cal?.busy || []).map(b => ({
        start: b.start,
        end: b.end,
      })),
    };
  }
  return result;
}

// ===== 空き時間スロットを生成 =====
function generateFreeSlots(busyPeriods, dateStr, startHour, endHour, slotMinutes) {
  const slots = [];
  const busy = busyPeriods.map(b => ({
    start: new Date(b.start),
    end: new Date(b.end),
  }));

  // 指定日の営業時間内でスロットを生成
  const dayStart = new Date(`${dateStr}T${String(startHour).padStart(2,'0')}:00:00+09:00`);
  const dayEnd = new Date(`${dateStr}T${String(endHour).padStart(2,'0')}:00:00+09:00`);

  let current = new Date(dayStart);
  while (current.getTime() + slotMinutes * 60000 <= dayEnd.getTime()) {
    const slotEnd = new Date(current.getTime() + slotMinutes * 60000);

    // この時間帯がbusyと重ならないかチェック
    const isConflict = busy.some(b =>
      current < b.end && slotEnd > b.start
    );

    if (!isConflict) {
      slots.push({
        start: current.toISOString(),
        end: slotEnd.toISOString(),
        startLocal: formatJST(current),
        endLocal: formatJST(slotEnd),
        date: dateStr,
      });
    }

    // 30分刻みで進める
    current = new Date(current.getTime() + 30 * 60000);
  }

  return slots;
}

function formatJST(date) {
  return date.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

// ===== イベント作成 =====
async function createEvent(accessToken, calendarEmail, eventData) {
  const {
    summary,
    description,
    startDateTime,
    endDateTime,
    attendees = [],
    location,
    addMeet = false,
  } = eventData;

  const event = {
    summary,
    description: description || '',
    start: {
      dateTime: startDateTime,
      timeZone: 'Asia/Tokyo',
    },
    end: {
      dateTime: endDateTime,
      timeZone: 'Asia/Tokyo',
    },
    location: location || '',
    attendees: attendees.map(a => ({
      email: typeof a === 'string' ? a : a.email,
      displayName: typeof a === 'string' ? undefined : a.name,
    })),
    reminders: {
      useDefault: false,
      overrides: [
        { method: 'email', minutes: 60 },
        { method: 'popup', minutes: 15 },
      ],
    },
  };

  // Google Meet 自動生成
  if (addMeet) {
    event.conferenceData = {
      createRequest: {
        requestId: 'ats-' + Date.now(),
        conferenceSolutionKey: { type: 'hangoutsMeet' },
      },
    };
  }

  const url = `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarEmail)}/events` +
    (addMeet ? '?conferenceDataVersion=1' : '');

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(event),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));
  return data;
}

// ===== イベント一覧取得 =====
async function listEvents(accessToken, calendarEmail, timeMin, timeMax, maxResults = 50) {
  const params = new URLSearchParams({
    timeMin,
    timeMax,
    maxResults: String(maxResults),
    singleEvents: 'true',
    orderBy: 'startTime',
    timeZone: 'Asia/Tokyo',
  });

  const res = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarEmail)}/events?${params}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));

  return (data.items || []).map(ev => ({
    id: ev.id,
    summary: ev.summary || '(無題)',
    start: ev.start?.dateTime || ev.start?.date,
    end: ev.end?.dateTime || ev.end?.date,
    location: ev.location || '',
    description: ev.description || '',
    attendees: (ev.attendees || []).map(a => ({
      email: a.email,
      name: a.displayName || '',
      status: a.responseStatus || '',
    })),
    meetLink: ev.hangoutLink || ev.conferenceData?.entryPoints?.[0]?.uri || '',
    htmlLink: ev.htmlLink || '',
    status: ev.status,
  }));
}

// ===== イベント更新 =====
async function updateEvent(accessToken, calendarEmail, eventId, updates) {
  const res = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarEmail)}/events/${eventId}`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(updates),
    }
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));
  return data;
}

// ===== イベント削除 =====
async function deleteEvent(accessToken, calendarEmail, eventId) {
  const res = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarEmail)}/events/${eventId}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error?.message || 'イベント削除に失敗');
  }
  return { success: true };
}

// ===== メインハンドラー =====
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const SA_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  const CAL_EMAIL = process.env.GOOGLE_CALENDAR_EMAIL || process.env.GMAIL_USER_EMAIL;

  if (!SA_EMAIL || !PRIVATE_KEY || !CAL_EMAIL) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Google Calendar API の環境変数が設定されていません',
      }),
    };
  }

  try {
    const reqBody = JSON.parse(event.body);
    const { action } = reqBody;
    const calEmail = reqBody.calendarEmail || CAL_EMAIL;
    const accessToken = await getAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

    // ===== 空き時間取得 =====
    if (action === 'freebusy') {
      const { emails, timeMin, timeMax, slotMinutes = 45, startHour = 9, endHour = 18 } = reqBody;
      if (!emails || !timeMin || !timeMax) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'emails, timeMin, timeMax は必須です' }) };
      }

      const freeBusy = await getFreeBusy(accessToken, emails, timeMin, timeMax);

      // 全員の busy を統合して空きスロットを算出
      const allBusy = [];
      for (const email of emails) {
        if (freeBusy[email]?.busy) {
          allBusy.push(...freeBusy[email].busy);
        }
      }

      // 日付ごとにスロットを生成
      const startDate = new Date(timeMin);
      const endDate = new Date(timeMax);
      const freeSlots = [];

      for (let d = new Date(startDate); d < endDate; d.setDate(d.getDate() + 1)) {
        const dow = d.getDay();
        if (dow === 0 || dow === 6) continue; // 土日スキップ

        const dateStr = d.toISOString().slice(0, 10);
        const slots = generateFreeSlots(allBusy, dateStr, startHour, endHour, slotMinutes);
        freeSlots.push(...slots);
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, freeBusy, freeSlots }),
      };
    }

    // ===== イベント作成 =====
    if (action === 'create') {
      const result = await createEvent(accessToken, calEmail, reqBody);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          eventId: result.id,
          htmlLink: result.htmlLink,
          meetLink: result.hangoutLink || result.conferenceData?.entryPoints?.[0]?.uri || '',
          message: '面接予定をGoogleカレンダーに登録しました',
        }),
      };
    }

    // ===== イベント一覧 =====
    if (action === 'list') {
      const { timeMin, timeMax, maxResults } = reqBody;
      if (!timeMin || !timeMax) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'timeMin, timeMax は必須です' }) };
      }
      const events = await listEvents(accessToken, calEmail, timeMin, timeMax, maxResults);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, events }),
      };
    }

    // ===== イベント更新 =====
    if (action === 'update') {
      const { eventId, updates } = reqBody;
      if (!eventId) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'eventId は必須です' }) };
      }
      const result = await updateEvent(accessToken, calEmail, eventId, updates);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, eventId: result.id, message: '予定を更新しました' }),
      };
    }

    // ===== イベント削除 =====
    if (action === 'delete') {
      const { eventId } = reqBody;
      if (!eventId) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'eventId は必須です' }) };
      }
      await deleteEvent(accessToken, calEmail, eventId);
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, message: '予定を削除しました' }),
      };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: '不明なaction: ' + action }) };
  } catch (err) {
    console.error('Google Calendar function error:', err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'エラー: ' + err.message }),
    };
  }
};
