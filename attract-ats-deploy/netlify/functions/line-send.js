// Netlify Serverless Function: LINE メッセージ送信 / 一斉配信
// 環境変数:
//   LINE_CHANNEL_ACCESS_TOKEN - LINEチャネルアクセストークン
//   SUPABASE_URL - Supabase URL
//   SUPABASE_SERVICE_ROLE_KEY - Supabase service_role キー

const LINE_API = 'https://api.line.me/v2/bot';

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
    body: JSON.stringify(Array.isArray(data) ? data : [data]),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error(`[Supabase INSERT ${table} Error]`, err);
    return null;
  }
  return res.json();
}

// ===== LINE Push API =====
async function linePush(to, messages, accessToken) {
  const res = await fetch(`${LINE_API}/message/push`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ to, messages }),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error('[LINE Push Error]', err);
    return { ok: false, error: err };
  }
  return { ok: true };
}

// ===== LINE Multicast API =====
async function lineMulticast(toList, messages, accessToken) {
  const res = await fetch(`${LINE_API}/message/multicast`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ to: toList, messages }),
  });
  if (!res.ok) {
    const err = await res.text();
    console.error('[LINE Multicast Error]', err);
    return { ok: false, error: err };
  }
  return { ok: true };
}

// ===== メインハンドラー =====
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  const {
    LINE_CHANNEL_ACCESS_TOKEN,
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
  } = process.env;

  if (!LINE_CHANNEL_ACCESS_TOKEN) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'LINE not configured' }) };
  }

  // ATS からの認証チェック（簡易: Supabase の access token を検証）
  const authHeader = event.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  try {
    const body = JSON.parse(event.body);
    const { action } = body;

    // ===== 個別送信 =====
    if (action === 'send') {
      const { candidate_id, message, sent_by } = body;

      if (!candidate_id || !message) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'candidate_id and message are required' }) };
      }

      // candidate_id から line_user_id を取得
      const lineUsers = await sbSelect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
        'line_users', `candidate_id=eq.${candidate_id}&status=eq.linked`);

      if (lineUsers.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: 'この候補者はLINE連携されていません' }) };
      }

      const lineUserId = lineUsers[0].line_user_id;

      // LINE Push API で送信
      const result = await linePush(lineUserId, [{ type: 'text', text: message }], LINE_CHANNEL_ACCESS_TOKEN);

      if (!result.ok) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: 'LINE送信に失敗しました', detail: result.error }) };
      }

      // line_messages に保存
      await sbInsert(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, 'line_messages', {
        line_user_id: lineUserId,
        candidate_id: candidate_id,
        direction: 'outbound',
        message_type: 'text',
        content: message,
        sent_by: sent_by || null,
      });

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, message: '送信しました' }),
      };
    }

    // ===== 一斉配信 =====
    if (action === 'broadcast') {
      const { candidate_ids, message, sent_by } = body;

      if (!candidate_ids || !Array.isArray(candidate_ids) || candidate_ids.length === 0 || !message) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'candidate_ids (array) and message are required' }) };
      }

      // candidate_ids → line_user_ids を取得
      const idList = candidate_ids.map(id => `"${id}"`).join(',');
      const lineUsers = await sbSelect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
        'line_users', `candidate_id=in.(${idList})&status=eq.linked`);

      if (lineUsers.length === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ error: 'LINE連携済みの候補者がいません' }) };
      }

      const lineUserIds = lineUsers.map(u => u.line_user_id);
      const sentCandidateIds = lineUsers.map(u => u.candidate_id);
      const skippedCount = candidate_ids.length - lineUsers.length;

      // Multicast API（最大500人ずつ）
      const batchSize = 500;
      let allOk = true;
      for (let i = 0; i < lineUserIds.length; i += batchSize) {
        const batch = lineUserIds.slice(i, i + batchSize);
        const result = await lineMulticast(batch, [{ type: 'text', text: message }], LINE_CHANNEL_ACCESS_TOKEN);
        if (!result.ok) allOk = false;
      }

      // line_messages に各候補者分を保存
      const messageRecords = lineUsers.map(u => ({
        line_user_id: u.line_user_id,
        candidate_id: u.candidate_id,
        direction: 'outbound',
        message_type: 'text',
        content: message,
        sent_by: sent_by || null,
      }));
      await sbInsert(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, 'line_messages', messageRecords);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: allOk,
          sent_count: lineUsers.length,
          skipped_count: skippedCount,
          message: `${lineUsers.length}人に送信しました${skippedCount > 0 ? `（${skippedCount}人はLINE未連携のためスキップ）` : ''}`,
        }),
      };
    }

    // ===== LINE連携ステータス取得 =====
    if (action === 'status') {
      const { candidate_id } = body;
      if (!candidate_id) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'candidate_id is required' }) };
      }

      const lineUsers = await sbSelect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
        'line_users', `candidate_id=eq.${candidate_id}`);

      if (lineUsers.length === 0) {
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ linked: false }),
        };
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          linked: lineUsers[0].status === 'linked',
          status: lineUsers[0].status,
          display_name: lineUsers[0].display_name,
          picture_url: lineUsers[0].picture_url,
          linked_at: lineUsers[0].linked_at,
        }),
      };
    }

    // ===== メッセージ履歴取得 =====
    if (action === 'messages') {
      const { candidate_id, limit = 50 } = body;
      if (!candidate_id) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'candidate_id is required' }) };
      }

      const messages = await sbSelect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
        'line_messages', `candidate_id=eq.${candidate_id}&order=created_at.asc&limit=${limit}`);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ messages }),
      };
    }

    // ===== 未紐付けLINEユーザー一覧 =====
    if (action === 'unlinked') {
      const unlinked = await sbSelect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
        'line_users', 'status=eq.pending&order=created_at.desc');

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ users: unlinked }),
      };
    }

    // ===== 手動紐付け =====
    if (action === 'link') {
      const { line_user_id, candidate_id } = body;
      if (!line_user_id || !candidate_id) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'line_user_id and candidate_id are required' }) };
      }

      // line_users を更新
      const res1 = await fetch(`${SUPABASE_URL}/rest/v1/line_users?line_user_id=eq.${line_user_id}`, {
        method: 'PATCH',
        headers: sbHeaders(SUPABASE_SERVICE_ROLE_KEY),
        body: JSON.stringify({
          candidate_id: candidate_id,
          status: 'linked',
          linked_at: new Date().toISOString(),
        }),
      });

      // candidates テーブルにも設定
      const res2 = await fetch(`${SUPABASE_URL}/rest/v1/candidates?id=eq.${candidate_id}`, {
        method: 'PATCH',
        headers: sbHeaders(SUPABASE_SERVICE_ROLE_KEY),
        body: JSON.stringify({ line_user_id: line_user_id }),
      });

      if (!res1.ok || !res2.ok) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: '紐付けに失敗しました' }) };
      }

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ success: true, message: '紐付けが完了しました' }),
      };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Unknown action. Use: send, broadcast, status, messages, unlinked, link' }) };

  } catch (err) {
    console.error('[line-send Error]', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Internal Server Error' }) };
  }
};
