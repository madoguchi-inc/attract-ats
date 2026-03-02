// Netlify Serverless Function: LINE Webhook エンドポイント
// 環境変数:
//   LINE_CHANNEL_ACCESS_TOKEN - LINEチャネルアクセストークン
//   LINE_CHANNEL_SECRET - LINEチャネルシークレット
//   SUPABASE_URL - Supabase URL
//   SUPABASE_SERVICE_ROLE_KEY - Supabase service_role キー

const crypto = require('crypto');

const LINE_API = 'https://api.line.me/v2/bot';

// ===== 署名検証 =====
function verifySignature(body, signature, channelSecret) {
  const hash = crypto
    .createHmac('SHA256', channelSecret)
    .update(body)
    .digest('base64');
  return hash === signature;
}

// ===== LINE API ヘルパー =====
async function lineReply(replyToken, messages, accessToken) {
  const res = await fetch(`${LINE_API}/message/reply`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ replyToken, messages }),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error('[LINE Reply Error]', err);
  }
  return res;
}

async function lineGetProfile(userId, accessToken) {
  const res = await fetch(`${LINE_API}/profile/${userId}`, {
    headers: { 'Authorization': `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  return res.json();
}

// ===== Supabase ヘルパー =====
function sbHeaders(serviceRoleKey) {
  return {
    'apikey': serviceRoleKey,
    'Authorization': `Bearer ${serviceRoleKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation',
  };
}

async function sbSelect(supabaseUrl, serviceRoleKey, table, query) {
  const res = await fetch(`${supabaseUrl}/rest/v1/${table}?${query}`, {
    headers: sbHeaders(serviceRoleKey),
  });
  if (!res.ok) return [];
  return res.json();
}

async function sbInsert(supabaseUrl, serviceRoleKey, table, data) {
  const res = await fetch(`${supabaseUrl}/rest/v1/${table}`, {
    method: 'POST',
    headers: sbHeaders(serviceRoleKey),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error(`[Supabase INSERT ${table} Error]`, err);
    return null;
  }
  return res.json();
}

async function sbUpdate(supabaseUrl, serviceRoleKey, table, query, data) {
  const res = await fetch(`${supabaseUrl}/rest/v1/${table}?${query}`, {
    method: 'PATCH',
    headers: sbHeaders(serviceRoleKey),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error(`[Supabase UPDATE ${table} Error]`, err);
    return null;
  }
  return res.json();
}

// ===== イベント処理 =====

// 友だち追加イベント
async function handleFollow(event, env) {
  const userId = event.source.userId;
  console.log('[Follow]', userId);

  // LINEプロフィール取得
  const profile = await lineGetProfile(userId, env.LINE_CHANNEL_ACCESS_TOKEN);
  const displayName = profile?.displayName || '不明';
  const pictureUrl = profile?.pictureUrl || null;

  // line_users に INSERT（既存チェック）
  const existing = await sbSelect(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
    'line_users', `line_user_id=eq.${userId}`);

  if (existing.length > 0) {
    // ブロック解除の場合: status を pending に戻す
    await sbUpdate(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
      'line_users', `line_user_id=eq.${userId}`,
      { status: 'pending', display_name: displayName, picture_url: pictureUrl });
  } else {
    await sbInsert(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, 'line_users', {
      line_user_id: userId,
      display_name: displayName,
      picture_url: pictureUrl,
      status: 'pending',
    });
  }

  // ウェルカムメッセージ
  await lineReply(event.replyToken, [{
    type: 'text',
    text: `友だち追加ありがとうございます！\n\n本人確認のため、ご登録のメールアドレスまたはお名前（フルネーム）を送信してください。`,
  }], env.LINE_CHANNEL_ACCESS_TOKEN);
}

// ブロック（友だち解除）イベント
async function handleUnfollow(event, env) {
  const userId = event.source.userId;
  console.log('[Unfollow]', userId);

  await sbUpdate(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
    'line_users', `line_user_id=eq.${userId}`, { status: 'blocked' });
}

// メッセージ受信イベント
async function handleMessage(event, env) {
  const userId = event.source.userId;
  const msgType = event.message.type;
  const content = event.message.text || '';
  console.log('[Message]', userId, msgType, content.substring(0, 50));

  // line_users のステータスを取得
  const lineUsers = await sbSelect(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
    'line_users', `line_user_id=eq.${userId}`);

  if (lineUsers.length === 0) {
    // 未登録（通常はfollowで作られるが念のため）
    const profile = await lineGetProfile(userId, env.LINE_CHANNEL_ACCESS_TOKEN);
    await sbInsert(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, 'line_users', {
      line_user_id: userId,
      display_name: profile?.displayName || '不明',
      picture_url: profile?.pictureUrl || null,
      status: 'pending',
    });
    // マッチング試行
    await tryAutoMatch(userId, content, event.replyToken, env);
    return;
  }

  const lineUser = lineUsers[0];

  if (lineUser.status === 'pending') {
    // まだ紐付けされていない → 自動マッチング試行
    await tryAutoMatch(userId, content, event.replyToken, env);
    return;
  }

  if (lineUser.status === 'linked') {
    // 紐付け済み → メッセージを保存
    const msgData = {
      line_user_id: userId,
      candidate_id: lineUser.candidate_id,
      direction: 'inbound',
      message_type: msgType === 'text' ? 'text' : msgType,
      content: msgType === 'text' ? content : null,
      metadata: msgType !== 'text' ? JSON.stringify({
        messageId: event.message.id,
        type: msgType,
        ...(event.message.contentProvider ? { contentProvider: event.message.contentProvider } : {}),
      }) : '{}',
    };
    await sbInsert(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, 'line_messages', msgData);
    // 受信確認はしない（ATS側で確認・返信する）
  }
}

// 自動マッチングロジック
async function tryAutoMatch(lineUserId, inputText, replyToken, env) {
  const text = (inputText || '').trim();
  if (!text) return;

  let candidates = [];

  // 1. メールアドレスの形式チェック
  if (text.includes('@')) {
    candidates = await sbSelect(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
      'candidates', `email=eq.${encodeURIComponent(text)}`);
  }

  // 2. 名前で検索（姓名を結合して部分一致）
  if (candidates.length === 0) {
    // フルネーム検索: lastName + firstName に一致するものを探す
    const allCandidates = await sbSelect(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
      'candidates', 'select=id,firstName,lastName,email&limit=500');

    const normalizedInput = text.replace(/\s+/g, '');
    candidates = allCandidates.filter(c => {
      const fullName = `${c.lastName || ''}${c.firstName || ''}`.replace(/\s+/g, '');
      const fullNameReverse = `${c.firstName || ''}${c.lastName || ''}`.replace(/\s+/g, '');
      return fullName === normalizedInput || fullNameReverse === normalizedInput;
    });
  }

  if (candidates.length === 1) {
    // マッチ成功
    const candidate = candidates[0];
    await sbUpdate(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
      'line_users', `line_user_id=eq.${lineUserId}`, {
        candidate_id: candidate.id,
        status: 'linked',
        linked_at: new Date().toISOString(),
      });

    // candidates テーブルにも line_user_id を設定
    await sbUpdate(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY,
      'candidates', `id=eq.${candidate.id}`, { line_user_id: lineUserId });

    const name = `${candidate.lastName || ''} ${candidate.firstName || ''}`.trim();
    await lineReply(replyToken, [{
      type: 'text',
      text: `${name}さんとして紐付けが完了しました！\n今後はこのLINEアカウントで採用に関するご連絡をいたします。`,
    }], env.LINE_CHANNEL_ACCESS_TOKEN);

  } else if (candidates.length > 1) {
    await lineReply(replyToken, [{
      type: 'text',
      text: `複数の候補者が見つかりました。お手数ですが、ご登録のメールアドレスを送信してください。`,
    }], env.LINE_CHANNEL_ACCESS_TOKEN);

  } else {
    await lineReply(replyToken, [{
      type: 'text',
      text: `一致する候補者情報が見つかりませんでした。\nお手数ですが、採用担当にお問い合わせください。`,
    }], env.LINE_CHANNEL_ACCESS_TOKEN);
  }
}

// ===== メインハンドラー =====
exports.handler = async (event) => {
  // CORS 対応
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' }, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const {
    LINE_CHANNEL_ACCESS_TOKEN,
    LINE_CHANNEL_SECRET,
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
  } = process.env;

  if (!LINE_CHANNEL_ACCESS_TOKEN || !LINE_CHANNEL_SECRET) {
    console.error('Missing LINE env vars');
    return { statusCode: 500, body: 'Server configuration error' };
  }

  // 署名検証
  const signature = event.headers['x-line-signature'];
  if (!signature || !verifySignature(event.body, signature, LINE_CHANNEL_SECRET)) {
    console.error('[Signature Verification Failed]');
    return { statusCode: 403, body: 'Invalid signature' };
  }

  const env = { LINE_CHANNEL_ACCESS_TOKEN, LINE_CHANNEL_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY };

  try {
    const body = JSON.parse(event.body);
    const events = body.events || [];

    for (const evt of events) {
      switch (evt.type) {
        case 'follow':
          await handleFollow(evt, env);
          break;
        case 'unfollow':
          await handleUnfollow(evt, env);
          break;
        case 'message':
          await handleMessage(evt, env);
          break;
        default:
          console.log('[Unhandled event type]', evt.type);
      }
    }

    return { statusCode: 200, body: 'OK' };
  } catch (err) {
    console.error('[Webhook Error]', err);
    return { statusCode: 500, body: 'Internal Server Error' };
  }
};
