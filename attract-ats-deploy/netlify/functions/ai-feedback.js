// Netlify Serverless Function: AI フィードバック分析
// 録音音声 → Whisper文字起こし → GPT-4構造化分析
// 環境変数:
//   OPENAI_API_KEY - OpenAI APIキー

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_API_KEY) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'OPENAI_API_KEY not configured' }) };
  }

  try {
    const contentType = event.headers['content-type'] || '';

    // ── モード判定 ──
    // 1) multipart/form-data → 音声ファイル付き（文字起こし + 分析）
    // 2) application/json → テキストのみ（分析のみ）
    let transcript = '';
    let mode = 'text_only';

    if (contentType.includes('multipart/form-data')) {
      mode = 'audio';
      transcript = await transcribeAudio(event, OPENAI_API_KEY);
    } else {
      const body = JSON.parse(event.body || '{}');
      transcript = body.transcript || '';
      if (!transcript) {
        return { statusCode: 400, headers, body: JSON.stringify({ error: 'No transcript or audio provided' }) };
      }
    }

    // ── GPT-4 構造化分析 ──
    const analysis = await analyzeInterview(transcript, OPENAI_API_KEY);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        mode,
        transcript,
        analysis,
      }),
    };
  } catch (err) {
    console.error('AI Feedback error:', err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: err.message || 'Internal server error' }),
    };
  }
};

// ===== Whisper 文字起こし =====
async function transcribeAudio(event, apiKey) {
  // Netlify Functions は multipart を自動パースしないので手動で処理
  const boundary = getBoundary(event.headers['content-type']);
  if (!boundary) throw new Error('No boundary in content-type');

  const bodyBuffer = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64')
    : Buffer.from(event.body, 'binary');

  const parts = parseMultipart(bodyBuffer, boundary);
  const audioPart = parts.find(p => p.name === 'audio');
  if (!audioPart) throw new Error('No audio file in request');

  // FormData を構築して Whisper に送信
  const formBoundary = '----WhisperBoundary' + Date.now();
  const fileName = audioPart.filename || 'recording.webm';
  const mimeType = audioPart.contentType || 'audio/webm';

  const bodyParts = [];
  // file part
  bodyParts.push(`--${formBoundary}\r\n`);
  bodyParts.push(`Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n`);
  bodyParts.push(`Content-Type: ${mimeType}\r\n\r\n`);
  const fileBuffer = audioPart.data;
  // model part
  const modelPart = `\r\n--${formBoundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\nwhisper-1\r\n`;
  // language part
  const langPart = `--${formBoundary}\r\nContent-Disposition: form-data; name="language"\r\n\r\nja\r\n`;
  // response_format part
  const fmtPart = `--${formBoundary}\r\nContent-Disposition: form-data; name="response_format"\r\n\r\ntext\r\n`;
  const endPart = `--${formBoundary}--\r\n`;

  // Build complete body as Buffer
  const textEncoder = new TextEncoder();
  const headerBuf = Buffer.from(bodyParts.join(''));
  const trailingBuf = Buffer.from(modelPart + langPart + fmtPart + endPart);
  const fullBody = Buffer.concat([headerBuf, fileBuffer, trailingBuf]);

  const res = await fetch('https://api.openai.com/v1/audio/transcriptions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': `multipart/form-data; boundary=${formBoundary}`,
    },
    body: fullBody,
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Whisper API error (${res.status}): ${errText}`);
  }

  return await res.text();
}

// ===== GPT-4 構造化分析 =====
async function analyzeInterview(transcript, apiKey) {
  const systemPrompt = `あなたは採用面接のAI分析アシスタントです。
面接の文字起こしテキストを分析し、以下のJSON形式で構造化された結果を返してください。

{
  "summary": "面接全体の要約（200文字以内）",
  "careerPlan": "候補者が語ったキャリアプラン",
  "reason": "志望理由の要点",
  "competitors": "選考中の他社情報",
  "reverseQ": "候補者からの逆質問",
  "concerns": "懸念点・次回確認事項",
  "scores": {
    "charm": { "score": 1-5, "reason": "根拠" },
    "honesty": { "score": 1-5, "reason": "根拠" },
    "flexibility": { "score": 1-5, "reason": "根拠" },
    "tenacity": { "score": 1-5, "reason": "根拠" },
    "achievement": { "score": 1-5, "reason": "根拠" },
    "stress": { "score": 1-5, "reason": "根拠" }
  },
  "recommendation": "strong_yes | yes | neutral | no | strong_no",
  "keyInsights": ["発見事項1", "発見事項2", "発見事項3"],
  "speakingRatio": "候補者の発話割合（推定%）"
}

評価基準:
- charm (愛嬌): 人懐っこさ、明るさ、場を和ませる力
- honesty (素直さ): FB受容力、自己課題の認識
- flexibility (柔軟さ): 変化対応力、新環境への適応力
- tenacity (しつこさ・結果への執念): 粘り強さ、目標達成への執着心
- achievement (達成感への感度): 成果への喜び、モチベーション源泉
- stress (ストレス耐性): プレッシャー下での安定性

スコアガイド:
1: 身についていない
2: 教育次第で身につく
3: ある程度発揮
4: 即戦力レベル
5: トップレベル

推薦度は総合的な判断で決定してください。
JSONのみを返し、他のテキストは含めないでください。`;

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `以下は面接の文字起こしテキストです:\n\n${transcript}` },
      ],
      temperature: 0.3,
      max_tokens: 2000,
      response_format: { type: 'json_object' },
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GPT-4 API error (${res.status}): ${errText}`);
  }

  const data = await res.json();
  const content = data.choices[0]?.message?.content;
  return JSON.parse(content);
}

// ===== Multipart パーサー =====
function getBoundary(contentType) {
  if (!contentType) return null;
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/);
  return match ? (match[1] || match[2]) : null;
}

function parseMultipart(body, boundary) {
  const parts = [];
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const endBuf = Buffer.from(`--${boundary}--`);

  let start = indexOf(body, boundaryBuf, 0);
  if (start === -1) return parts;

  while (true) {
    start += boundaryBuf.length;
    // Skip \r\n after boundary
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;

    // Check for end boundary
    const nextBoundary = indexOf(body, boundaryBuf, start);
    if (nextBoundary === -1) break;

    // Parse headers
    const headerEnd = indexOf(body, Buffer.from('\r\n\r\n'), start);
    if (headerEnd === -1) break;

    const headerStr = body.slice(start, headerEnd).toString('utf-8');
    const dataStart = headerEnd + 4;
    // Data ends 2 bytes before next boundary (\r\n)
    const dataEnd = nextBoundary - 2;

    const part = { headers: headerStr, data: body.slice(dataStart, dataEnd) };

    // Parse Content-Disposition
    const dispMatch = headerStr.match(/Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]+)")?/i);
    if (dispMatch) {
      part.name = dispMatch[1];
      part.filename = dispMatch[2] || null;
    }

    // Parse Content-Type
    const ctMatch = headerStr.match(/Content-Type:\s*(.+)/i);
    if (ctMatch) {
      part.contentType = ctMatch[1].trim();
    }

    parts.push(part);

    // Check if next is end boundary
    if (indexOf(body, endBuf, nextBoundary) === nextBoundary) break;
  }

  return parts;
}

function indexOf(buf, search, offset) {
  for (let i = offset; i <= buf.length - search.length; i++) {
    let found = true;
    for (let j = 0; j < search.length; j++) {
      if (buf[i + j] !== search[j]) { found = false; break; }
    }
    if (found) return i;
  }
  return -1;
}
