// Netlify Serverless Function: 予約リンク管理 (TimeRex風)
// 候補者向け公開API（認証不要）
// 環境変数:
//   GOOGLE_SERVICE_ACCOUNT_EMAIL - サービスアカウントのメール
//   GOOGLE_PRIVATE_KEY - サービスアカウントの秘密鍵
//   GOOGLE_CALENDAR_EMAIL - カレンダー操作対象のメールアドレス
//   SUPABASE_URL - Supabase URL
//   SUPABASE_SERVICE_ROLE_KEY - Supabase サービスロールキー

const crypto = require('crypto');

// ===== JWT 作成 & アクセストークン取得 =====
function createJWT(serviceAccountEmail, privateKey, userEmail, scope) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccountEmail,
    sub: userEmail,
    scope: scope || 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events',
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

async function getGoogleAccessToken(serviceAccountEmail, privateKey, userEmail, scope) {
  const jwt = createJWT(serviceAccountEmail, privateKey, userEmail, scope);
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

// ===== Supabase ヘルパー =====
async function supabaseQuery(url, key, path, method = 'GET', body = null, extraHeaders = {}) {
  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`,
    'Content-Type': 'application/json',
    Prefer: method === 'POST' ? 'return=representation' : 'return=representation',
    ...extraHeaders,
  };
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${url}/rest/v1/${path}`, opts);
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.message || `Supabase error ${res.status}`);
  return data;
}

// ===== トークン生成 =====
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
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
  return data;
}

// ===== 空き時間スロットを生成 =====
function generateFreeSlots(busyPeriods, dateStr, startHour, endHour, slotMinutes) {
  const slots = [];
  const busy = busyPeriods.map(b => ({
    start: new Date(b.start),
    end: new Date(b.end),
  }));

  const dayStart = new Date(`${dateStr}T${String(startHour).padStart(2, '0')}:00:00+09:00`);
  const dayEnd = new Date(`${dateStr}T${String(endHour).padStart(2, '0')}:00:00+09:00`);

  let current = new Date(dayStart);
  while (current.getTime() + slotMinutes * 60000 <= dayEnd.getTime()) {
    const slotEnd = new Date(current.getTime() + slotMinutes * 60000);
    const isConflict = busy.some(b => current < b.end && slotEnd > b.start);

    if (!isConflict) {
      slots.push({
        start: current.toISOString(),
        end: slotEnd.toISOString(),
        startLocal: formatJST(current),
        endLocal: formatJST(slotEnd),
        date: dateStr,
      });
    }

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
async function createCalendarEvent(accessToken, calendarEmail, eventData) {
  const event = {
    summary: eventData.summary,
    description: eventData.description || '',
    start: {
      dateTime: eventData.startDateTime,
      timeZone: 'Asia/Tokyo',
    },
    end: {
      dateTime: eventData.endDateTime,
      timeZone: 'Asia/Tokyo',
    },
    location: eventData.location || '',
    attendees: (eventData.attendees || []).map(a => ({
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

  if (eventData.addMeet) {
    event.conferenceData = {
      createRequest: {
        requestId: 'booking-' + Date.now(),
        conferenceSolutionKey: { type: 'hangoutsMeet' },
      },
    };
  }

  const url = `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarEmail)}/events` +
    (eventData.addMeet ? '?conferenceDataVersion=1&sendUpdates=all' : '?sendUpdates=all');

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

// ===== Gmail送信ヘルパー =====
function createRawEmail(from, to, subject, htmlBody) {
  const encodedSubject = '=?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=';
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(htmlBody).toString('base64'),
  ];
  return Buffer.from(lines.join('\r\n')).toString('base64url');
}

async function sendGmail(accessToken, from, to, subject, body) {
  const htmlBody = body.replace(/\n/g, '<br>');
  const raw = createRawEmail(from, to, subject, htmlBody);
  const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));
  return data;
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
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SA_EMAIL || !PRIVATE_KEY || !CAL_EMAIL) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Google Calendar API の環境変数が設定されていません' }),
    };
  }
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Supabase の環境変数が設定されていません' }),
    };
  }

  try {
    const reqBody = JSON.parse(event.body);
    const { action } = reqBody;

    // ===== 会議室一覧取得 (管理者用) =====
    if (action === 'list-rooms') {
      const calEmail = CAL_EMAIL;
      const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

      // Google Calendar API: CalendarList から会議室リソースを取得
      const res = await fetch('https://www.googleapis.com/calendar/v3/users/me/calendarList', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || JSON.stringify(data));

      const rooms = (data.items || [])
        .filter(cal => cal.id && cal.id.includes('@resource.calendar.google.com'))
        .map(cal => ({
          email: cal.id,
          name: cal.summary || cal.id,
          description: cal.description || '',
        }));

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, rooms }),
      };
    }

    // ===== 予約セッション作成 (管理者用) =====
    if (action === 'create-session') {
      const {
        candidateId,
        interviewerEmails,
        interviewerNames,
        slotMinutes = 45,
        startHour = 9,
        endHour = 18,
        dateRangeDays = 14,
        stage = '',
        format = 'online',
        location = '',
        addMeet = true,
        message = '',
        roomEmail = '',
        roomName = '',
      } = reqBody;

      if (!candidateId || !interviewerEmails || interviewerEmails.length === 0) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'candidateId, interviewerEmails は必須です' }),
        };
      }

      const token = generateToken();
      const expiresAt = new Date(Date.now() + dateRangeDays * 24 * 60 * 60 * 1000 + 3 * 24 * 60 * 60 * 1000).toISOString();

      const session = await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, 'booking_sessions', 'POST', {
        candidate_id: candidateId,
        token,
        interviewer_emails: interviewerEmails,
        interviewer_names: interviewerNames || [],
        slot_minutes: slotMinutes,
        start_hour: startHour,
        end_hour: endHour,
        date_range_days: dateRangeDays,
        stage,
        format,
        location,
        add_meet: addMeet,
        message,
        room_email: roomEmail || null,
        room_name: roomName || null,
        status: 'active',
        expires_at: expiresAt,
      });

      const bookingUrl = `${process.env.URL || 'https://ats.madoguchi.inc'}/book?token=${token}`;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          token,
          bookingUrl,
          sessionId: session[0]?.id,
          expiresAt,
          message: '予約リンクを作成しました',
        }),
      };
    }

    // ===== 予約セッション取得 + 空き時間 (候補者用) =====
    if (action === 'get-session') {
      const { token } = reqBody;
      if (!token) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'token は必須です' }) };
      }

      // セッション取得
      const sessions = await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?token=eq.${token}&select=*`,
      );

      if (!sessions || sessions.length === 0) {
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: '予約リンクが見つかりません。有効期限が切れた可能性があります。' }),
        };
      }

      const session = sessions[0];

      if (session.status === 'booked') {
        // 候補者名取得
        let bookedCandidateName = '';
        try {
          const cands = await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, `candidates?id=eq.${session.candidate_id}&select=name`);
          if (cands && cands.length > 0) bookedCandidateName = cands[0].name || '';
        } catch (e) { /* ignore */ }

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: true,
            status: 'booked',
            message: '面接の予約が確定しています。',
            bookedSlotStart: session.booked_slot_start,
            bookedSlotEnd: session.booked_slot_end,
            meetLink: session.meet_link || '',
            canReschedule: true,
            session: {
              stage: session.stage,
              format: session.format,
              location: session.location,
              slotMinutes: session.slot_minutes,
              interviewerNames: session.interviewer_names,
              roomName: session.room_name || '',
              roomEmail: session.room_email || '',
            },
            candidateName: bookedCandidateName,
          }),
        };
      }

      if (session.status === 'expired' || session.status === 'cancelled') {
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: false,
            status: session.status,
            message: session.status === 'expired' ? '予約リンクの有効期限が切れています。' : '予約リンクはキャンセルされました。',
          }),
        };
      }

      if (session.expires_at && new Date(session.expires_at) < new Date()) {
        // 期限切れ → ステータス更新
        await supabaseQuery(
          SUPABASE_URL, SUPABASE_KEY,
          `booking_sessions?id=eq.${session.id}`,
          'PATCH',
          { status: 'expired' },
        );
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ success: false, status: 'expired', message: '予約リンクの有効期限が切れています。' }),
        };
      }

      // 候補者情報取得
      let candidateName = '';
      try {
        const candidates = await supabaseQuery(
          SUPABASE_URL, SUPABASE_KEY,
          `candidates?id=eq.${session.candidate_id}&select=name,email,stage`,
        );
        if (candidates && candidates.length > 0) {
          candidateName = candidates[0].name || '';
        }
      } catch (e) { /* ignore */ }

      // Google Calendar FreeBusy でリアルタイム空き時間を取得
      const calEmail = CAL_EMAIL;
      const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

      const now = new Date();
      const jstNow = new Date(now.getTime() + 9 * 60 * 60 * 1000);
      const todayStr = jstNow.toISOString().slice(0, 10);

      // 明日から date_range_days 日後まで
      const startDate = new Date(jstNow);
      startDate.setDate(startDate.getDate() + 1);
      const endDate = new Date(startDate);
      endDate.setDate(endDate.getDate() + session.date_range_days);

      const timeMin = startDate.toISOString().slice(0, 10) + 'T00:00:00+09:00';
      const timeMax = endDate.toISOString().slice(0, 10) + 'T23:59:59+09:00';

      // FreeBusy: 面接官 + 会議室(あれば)を同時チェック
      const freeBusyEmails = [...session.interviewer_emails];
      if (session.room_email) freeBusyEmails.push(session.room_email);

      const freeBusyData = await getFreeBusy(accessToken, freeBusyEmails, timeMin, timeMax);

      // カレンダーエラーチェック
      const calendarErrors = [];
      for (const email of session.interviewer_emails) {
        const cal = freeBusyData.calendars?.[email];
        if (cal?.errors) {
          calendarErrors.push({
            email,
            reason: cal.errors[0]?.reason || 'unknown',
          });
        }
      }

      if (calendarErrors.length > 0) {
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: false,
            message: '面接官のカレンダーにアクセスできません。担当者にお問い合わせください。',
            calendarErrors,
          }),
        };
      }

      // 全員の busy を統合（会議室含む）
      const allBusy = [];
      for (const email of freeBusyEmails) {
        const cal = freeBusyData.calendars?.[email];
        if (cal?.busy) {
          allBusy.push(...cal.busy);
        }
      }

      // 日付ごとにスロット生成
      const freeSlots = [];
      for (let d = new Date(startDate); d < endDate; d.setDate(d.getDate() + 1)) {
        const dow = d.getDay();
        if (dow === 0 || dow === 6) continue; // 土日スキップ

        const dateStr = d.toISOString().slice(0, 10);
        const slots = generateFreeSlots(allBusy, dateStr, session.start_hour, session.end_hour, session.slot_minutes);
        freeSlots.push(...slots);
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          status: 'active',
          session: {
            stage: session.stage,
            format: session.format,
            location: session.location,
            slotMinutes: session.slot_minutes,
            message: session.message,
            interviewerNames: session.interviewer_names,
            roomName: session.room_name || '',
            roomEmail: session.room_email || '',
          },
          candidateName,
          freeSlots,
        }),
      };
    }

    // ===== 予約確定 (候補者用) =====
    if (action === 'book-slot') {
      const { token, slotStart, slotEnd, candidateName: bookingName, candidateEmail: bookingEmail } = reqBody;
      if (!token || !slotStart || !slotEnd) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'token, slotStart, slotEnd は必須です' }) };
      }

      // セッション取得
      const sessions = await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?token=eq.${token}&select=*`,
      );

      if (!sessions || sessions.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: '予約リンクが見つかりません' }) };
      }

      const session = sessions[0];

      if (session.status !== 'active') {
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: false,
            message: session.status === 'booked' ? 'この予約リンクはすでに使用されています。' : '予約リンクが無効です。',
          }),
        };
      }

      // ダブルブッキング防止: 再度FreeBusyチェック（会議室含む）
      const calEmail = CAL_EMAIL;
      const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

      const fbEmails = [...session.interviewer_emails];
      if (session.room_email) fbEmails.push(session.room_email);
      const freeBusyCheck = await getFreeBusy(accessToken, fbEmails, slotStart, slotEnd);
      let hasConflict = false;
      for (const email of fbEmails) {
        const cal = freeBusyCheck.calendars?.[email];
        if (cal?.busy && cal.busy.length > 0) {
          hasConflict = true;
          break;
        }
      }

      if (hasConflict) {
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: false,
            message: '申し訳ございません。選択された時間帯は他の予約が入りました。別の時間をお選びください。',
            conflict: true,
          }),
        };
      }

      // 候補者名取得
      let candidateInfo = { name: bookingName || '', email: bookingEmail || '' };
      try {
        const candidates = await supabaseQuery(
          SUPABASE_URL, SUPABASE_KEY,
          `candidates?id=eq.${session.candidate_id}&select=name,email`,
        );
        if (candidates && candidates.length > 0) {
          candidateInfo.name = candidateInfo.name || candidates[0].name || '';
          candidateInfo.email = candidateInfo.email || candidates[0].email || '';
        }
      } catch (e) { /* ignore */ }

      // Googleカレンダーにイベント作成
      const slotStartDate = new Date(slotStart);
      const slotEndDate = new Date(slotEnd);
      const dateStr = slotStartDate.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', month: 'numeric', day: 'numeric' });
      const timeStr = slotStartDate.toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', hour12: false });

      const attendees = [
        ...session.interviewer_emails.map(email => ({ email })),
      ];
      if (candidateInfo.email) {
        attendees.push({ email: candidateInfo.email, displayName: candidateInfo.name });
      }
      // 会議室をattendeeに追加（リソース予約）
      if (session.room_email) {
        attendees.push({ email: session.room_email });
      }

      const eventLocation = session.room_name
        ? session.room_name + (session.location ? ' (' + session.location + ')' : '')
        : (session.format === 'online' ? '' : session.location);

      const eventResult = await createCalendarEvent(accessToken, calEmail, {
        summary: `【${session.stage || '面接'}】${candidateInfo.name || '候補者'}`,
        description: `候補者: ${candidateInfo.name}\nメール: ${candidateInfo.email}\n面接ステージ: ${session.stage}\n形式: ${session.format === 'online' ? 'オンライン' : '対面'}` +
          (session.room_name ? `\n会議室: ${session.room_name}` : '') +
          `\n\n※ 予約リンクから候補者が直接予約しました`,
        startDateTime: slotStart,
        endDateTime: slotEnd,
        attendees,
        location: eventLocation,
        addMeet: session.add_meet,
      });

      const meetLink = eventResult.hangoutLink || eventResult.conferenceData?.entryPoints?.[0]?.uri || '';

      // booking_sessions を更新
      await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?id=eq.${session.id}`,
        'PATCH',
        {
          status: 'booked',
          booked_slot_start: slotStart,
          booked_slot_end: slotEnd,
          booked_at: new Date().toISOString(),
          calendar_event_id: eventResult.id,
          meet_link: meetLink,
          updated_at: new Date().toISOString(),
        },
      );

      // 候補者のステージ・サブステータスを自動更新（予約済）
      try {
        if (session.candidate_id) {
          await supabaseQuery(
            SUPABASE_URL, SUPABASE_KEY,
            `candidates?id=eq.${session.candidate_id}`,
            'PATCH',
            { stage: session.stage || undefined, substatus: '予約済', updated_at: new Date().toISOString() },
          );
          console.log(`[Booking] 候補者substatus更新: ${session.candidate_id} → ${session.stage} / 予約済`);
        }
      } catch (candErr) {
        console.error('[Booking] 候補者substatus更新失敗:', candErr.message);
      }

      // 面接官への通知メール送信
      try {
        const GMAIL_EMAIL = process.env.GMAIL_USER_EMAIL;
        if (GMAIL_EMAIL && session.interviewer_emails && session.interviewer_emails.length > 0) {
          const gmailScope = 'https://www.googleapis.com/auth/gmail.send';
          const gmailToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY.replace(/\\n/g, '\n'), GMAIL_EMAIL, gmailScope);

          const startJST = new Date(slotStart).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'long', day: 'numeric', weekday: 'short', hour: '2-digit', minute: '2-digit', hour12: false });
          const endTime = new Date(slotEnd).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', hour12: false });

          const subject = `【面接予約確定】${candidateInfo.name || '候補者'} - ${session.stage || '面接'}`;
          const body = `面接の予約が確定しました。\n\n` +
            `■ 候補者: ${candidateInfo.name || '（未設定）'}\n` +
            `■ ステージ: ${session.stage || '面接'}\n` +
            `■ 日時: ${startJST} 〜 ${endTime}\n` +
            `■ 形式: ${session.format === 'online' ? 'オンライン' : '対面'}` +
            (session.room_name ? `\n■ 会議室: ${session.room_name}` : '') +
            (meetLink ? `\n■ Meet: ${meetLink}` : '') +
            (session.location && session.format !== 'online' ? `\n■ 場所: ${session.location}` : '') +
            `\n\n※ Googleカレンダーにも登録済みです。\n※ 候補者が予約リンクから直接予約しました。`;

          for (const email of session.interviewer_emails) {
            try {
              await sendGmail(gmailToken, GMAIL_EMAIL, email, subject, body);
              console.log(`[Booking] 通知メール送信成功: ${email}`);
            } catch (mailErr) {
              console.error(`[Booking] 通知メール送信失敗 (${email}):`, mailErr.message);
            }
          }
        }
      } catch (e) {
        console.log('[Booking] 通知メール送信スキップ:', e.message);
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: '予約が確定しました！',
          eventId: eventResult.id,
          meetLink,
          htmlLink: eventResult.htmlLink || '',
          bookedSlotStart: slotStart,
          bookedSlotEnd: slotEnd,
        }),
      };
    }

    // ===== セッション状態確認 (管理者用) =====
    if (action === 'check-session') {
      const { token, sessionId } = reqBody;
      const query = token
        ? `booking_sessions?token=eq.${token}&select=*`
        : sessionId
          ? `booking_sessions?id=eq.${sessionId}&select=*`
          : null;

      if (!query) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'token または sessionId が必要です' }) };
      }

      const sessions = await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, query);
      if (!sessions || sessions.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: '予約セッションが見つかりません' }) };
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, session: sessions[0] }),
      };
    }

    // ===== 予約済み一覧取得 (スケジュール画面用) =====
    if (action === 'list-booked') {
      const sessions = await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        'booking_sessions?status=eq.booked&select=id,token,candidate_id,stage,format,location,interviewer_names,interviewer_emails,booked_slot_start,booked_slot_end,meet_link,add_meet,booked_at,room_email,room_name&order=booked_slot_start.asc',
      );

      if (!sessions || sessions.length === 0) {
        return { statusCode: 200, headers, body: JSON.stringify({ success: true, events: [] }) };
      }

      // candidate_id → 候補者名を取得
      const candidateIds = [...new Set(sessions.map(s => s.candidate_id).filter(Boolean))];
      let candidateMap = {};
      if (candidateIds.length > 0) {
        const idList = candidateIds.join(',');
        const candidates = await supabaseQuery(
          SUPABASE_URL, SUPABASE_KEY,
          `candidates?id=in.(${idList})&select=id,last_name,first_name,recruit_type,email`,
        );
        if (candidates) {
          for (const c of candidates) {
            candidateMap[c.id] = {
              name: ((c.last_name || '') + ' ' + (c.first_name || '')).trim(),
              recruitType: c.recruit_type,
              email: c.email,
            };
          }
        }
      }

      const events = sessions.map(s => {
        const cand = candidateMap[s.candidate_id] || {};
        return {
          id: 'booking_' + s.id,
          bookingSessionId: s.id,
          bookingToken: s.token,
          candidateId: s.candidate_id,
          candidateName: cand.name || '',
          recruitType: cand.recruitType || '',
          stage: s.stage || '',
          format: s.format || '',
          location: s.location || '',
          interviewerNames: s.interviewer_names || [],
          bookedSlotStart: s.booked_slot_start,
          bookedSlotEnd: s.booked_slot_end,
          meetLink: s.meet_link || '',
          roomName: s.room_name || '',
          roomEmail: s.room_email || '',
          bookedAt: s.booked_at,
        };
      });

      return { statusCode: 200, headers, body: JSON.stringify({ success: true, events }) };
    }

    // ===== リスケ用空き枠取得 (候補者用) =====
    if (action === 'get-reschedule-slots') {
      const { token } = reqBody;
      if (!token) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'token は必須です' }) };
      }

      const sessions = await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, `booking_sessions?token=eq.${token}&select=*`);
      if (!sessions || sessions.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: '予約リンクが見つかりません' }) };
      }
      const session = sessions[0];
      if (session.status !== 'booked') {
        return { statusCode: 200, headers, body: JSON.stringify({ success: false, message: 'この予約はリスケジュールできません。' }) };
      }

      // 空き枠を取得（get-session の active 時と同じロジック）
      const calEmail = CAL_EMAIL;
      const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

      const now = new Date();
      const jstNow = new Date(now.getTime() + 9 * 60 * 60 * 1000);
      const startDate = new Date(jstNow);
      startDate.setDate(startDate.getDate() + 1);
      const endDate = new Date(startDate);
      endDate.setDate(endDate.getDate() + session.date_range_days);

      const timeMin = startDate.toISOString().slice(0, 10) + 'T00:00:00+09:00';
      const timeMax = endDate.toISOString().slice(0, 10) + 'T23:59:59+09:00';

      const reschFbEmails = [...session.interviewer_emails];
      if (session.room_email) reschFbEmails.push(session.room_email);
      const freeBusyData = await getFreeBusy(accessToken, reschFbEmails, timeMin, timeMax);

      const allBusy = [];
      for (const email of reschFbEmails) {
        const cal = freeBusyData.calendars?.[email];
        if (cal?.busy) allBusy.push(...cal.busy);
      }

      const freeSlots = [];
      for (let d = new Date(startDate); d < endDate; d.setDate(d.getDate() + 1)) {
        const dow = d.getDay();
        if (dow === 0 || dow === 6) continue;
        const dateStr = d.toISOString().slice(0, 10);
        const slots = generateFreeSlots(allBusy, dateStr, session.start_hour, session.end_hour, session.slot_minutes);
        freeSlots.push(...slots);
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          session: {
            stage: session.stage,
            format: session.format,
            location: session.location,
            slotMinutes: session.slot_minutes,
            interviewerNames: session.interviewer_names,
            roomName: session.room_name || '',
            roomEmail: session.room_email || '',
          },
          freeSlots,
        }),
      };
    }

    // ===== 予約キャンセル (管理者用) =====
    if (action === 'cancel-booking') {
      const { sessionId } = reqBody;
      if (!sessionId) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'sessionId は必須です' }) };
      }

      const sessions = await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?id=eq.${sessionId}&select=*`,
      );
      if (!sessions || sessions.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: '予約セッションが見つかりません' }) };
      }
      const session = sessions[0];

      // Googleカレンダーイベント削除
      if (session.calendar_event_id) {
        try {
          const calEmail = CAL_EMAIL;
          const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);
          const delRes = await fetch(
            `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calEmail)}/events/${session.calendar_event_id}?sendUpdates=all`,
            { method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` } },
          );
          if (!delRes.ok && delRes.status !== 404) {
            console.error('[Cancel] カレンダー削除失敗:', delRes.status);
          }
        } catch (calErr) {
          console.error('[Cancel] カレンダー削除エラー:', calErr.message);
        }
      }

      // booking_sessions を cancelled に更新（リンクを再利用可能にするため active に戻すオプションも）
      const newStatus = reqBody.reactivate ? 'active' : 'cancelled';
      await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?id=eq.${session.id}`,
        'PATCH',
        {
          status: newStatus,
          booked_slot_start: null,
          booked_slot_end: null,
          booked_at: null,
          calendar_event_id: null,
          meet_link: null,
          updated_at: new Date().toISOString(),
        },
      );

      // 候補者のsubstatusを日程調整中に戻す
      if (session.candidate_id) {
        try {
          await supabaseQuery(
            SUPABASE_URL, SUPABASE_KEY,
            `candidates?id=eq.${session.candidate_id}`,
            'PATCH',
            { substatus: '日程調整中', updated_at: new Date().toISOString() },
          );
        } catch (e) { console.error('[Cancel] 候補者substatus更新失敗:', e.message); }
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: newStatus === 'active' ? '予約をキャンセルし、リンクを再有効化しました' : '予約をキャンセルしました',
          newStatus,
        }),
      };
    }

    // ===== リスケジュール (候補者用: 旧予約キャンセル → 新予約作成) =====
    if (action === 'reschedule') {
      const { token, slotStart, slotEnd } = reqBody;
      if (!token || !slotStart || !slotEnd) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'token, slotStart, slotEnd は必須です' }) };
      }

      const sessions = await supabaseQuery(
        SUPABASE_URL, SUPABASE_KEY,
        `booking_sessions?token=eq.${token}&select=*`,
      );
      if (!sessions || sessions.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: '予約リンクが見つかりません' }) };
      }
      const session = sessions[0];

      if (session.status !== 'booked') {
        return { statusCode: 200, headers, body: JSON.stringify({ success: false, message: 'この予約はリスケジュールできません。' }) };
      }

      const calEmail = CAL_EMAIL;
      const accessToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY, calEmail);

      // 1. 旧カレンダーイベント削除
      if (session.calendar_event_id) {
        try {
          const delRes = await fetch(
            `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calEmail)}/events/${session.calendar_event_id}?sendUpdates=all`,
            { method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` } },
          );
          if (!delRes.ok && delRes.status !== 404) {
            console.error('[Reschedule] 旧イベント削除失敗:', delRes.status);
          }
        } catch (e) { console.error('[Reschedule] 旧イベント削除エラー:', e.message); }
      }

      // 2. ダブルブッキング防止チェック（会議室含む）
      const reschFbEmails2 = [...session.interviewer_emails];
      if (session.room_email) reschFbEmails2.push(session.room_email);
      const freeBusyCheck = await getFreeBusy(accessToken, reschFbEmails2, slotStart, slotEnd);
      let hasConflict = false;
      for (const email of reschFbEmails2) {
        const cal = freeBusyCheck.calendars?.[email];
        if (cal?.busy && cal.busy.length > 0) {
          hasConflict = true;
          break;
        }
      }
      if (hasConflict) {
        // 旧イベントは既に削除済みなので、セッションをactiveに戻す
        await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, `booking_sessions?id=eq.${session.id}`, 'PATCH', {
          status: 'active', booked_slot_start: null, booked_slot_end: null, booked_at: null, calendar_event_id: null, meet_link: null, updated_at: new Date().toISOString(),
        });
        return { statusCode: 200, headers, body: JSON.stringify({ success: false, message: '選択された時間帯は埋まっています。別の時間をお選びください。', conflict: true, statusReset: true }) };
      }

      // 3. 候補者名取得
      let candidateInfo = { name: '', email: '' };
      try {
        const candidates = await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, `candidates?id=eq.${session.candidate_id}&select=name,email`);
        if (candidates && candidates.length > 0) {
          candidateInfo.name = candidates[0].name || '';
          candidateInfo.email = candidates[0].email || '';
        }
      } catch (e) { /* ignore */ }

      // 4. 新カレンダーイベント作成（会議室含む）
      const attendees = [...session.interviewer_emails.map(email => ({ email }))];
      if (candidateInfo.email) attendees.push({ email: candidateInfo.email, displayName: candidateInfo.name });
      if (session.room_email) attendees.push({ email: session.room_email });

      const reschLocation = session.room_name
        ? session.room_name + (session.location ? ' (' + session.location + ')' : '')
        : (session.format === 'online' ? '' : session.location);

      const eventResult = await createCalendarEvent(accessToken, calEmail, {
        summary: `【${session.stage || '面接'}】${candidateInfo.name || '候補者'}`,
        description: `候補者: ${candidateInfo.name}\nメール: ${candidateInfo.email}\n面接ステージ: ${session.stage}\n形式: ${session.format === 'online' ? 'オンライン' : '対面'}` +
          (session.room_name ? `\n会議室: ${session.room_name}` : '') +
          `\n\n※ 候補者がリスケジュールしました`,
        startDateTime: slotStart,
        endDateTime: slotEnd,
        attendees,
        location: reschLocation,
        addMeet: session.add_meet,
      });

      const meetLink = eventResult.hangoutLink || eventResult.conferenceData?.entryPoints?.[0]?.uri || '';

      // 5. booking_sessions 更新
      await supabaseQuery(SUPABASE_URL, SUPABASE_KEY, `booking_sessions?id=eq.${session.id}`, 'PATCH', {
        status: 'booked',
        booked_slot_start: slotStart,
        booked_slot_end: slotEnd,
        booked_at: new Date().toISOString(),
        calendar_event_id: eventResult.id,
        meet_link: meetLink,
        updated_at: new Date().toISOString(),
      });

      // 6. 面接官への通知メール
      try {
        const GMAIL_EMAIL = process.env.GMAIL_USER_EMAIL;
        if (GMAIL_EMAIL && session.interviewer_emails.length > 0) {
          const gmailScope = 'https://www.googleapis.com/auth/gmail.send';
          const gmailToken = await getGoogleAccessToken(SA_EMAIL, PRIVATE_KEY.replace(/\\n/g, '\n'), GMAIL_EMAIL, gmailScope);
          const startJST = new Date(slotStart).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'long', day: 'numeric', weekday: 'short', hour: '2-digit', minute: '2-digit', hour12: false });
          const endTime = new Date(slotEnd).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', hour12: false });
          const subject = `【面接日程変更】${candidateInfo.name || '候補者'} - ${session.stage || '面接'}`;
          const body = `候補者が面接日程を変更しました。\n\n■ 候補者: ${candidateInfo.name}\n■ ステージ: ${session.stage || '面接'}\n■ 新日時: ${startJST} 〜 ${endTime}\n■ 形式: ${session.format === 'online' ? 'オンライン' : '対面'}` +
            (meetLink ? `\n■ Meet: ${meetLink}` : '') + `\n\n※ Googleカレンダーは自動更新済みです。`;
          for (const email of session.interviewer_emails) {
            try { await sendGmail(gmailToken, GMAIL_EMAIL, email, subject, body); } catch (e) { console.error(`[Reschedule] 通知失敗 (${email}):`, e.message); }
          }
        }
      } catch (e) { console.log('[Reschedule] 通知メールスキップ:', e.message); }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: '日程を変更しました！',
          eventId: eventResult.id,
          meetLink,
          bookedSlotStart: slotStart,
          bookedSlotEnd: slotEnd,
        }),
      };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: '不明なaction: ' + action }) };
  } catch (err) {
    console.error('Booking function error:', err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'エラー: ' + err.message }),
    };
  }
};
