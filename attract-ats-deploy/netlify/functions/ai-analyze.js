// Netlify Function: GPT-4o 構造化分析（テキストのみ受け取り）
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
  if (!OPENAI_API_KEY) return { statusCode: 500, headers, body: JSON.stringify({ error: 'OPENAI_API_KEY not configured' }) };

  try {
    const { transcript } = JSON.parse(event.body || '{}');
    if (!transcript) return { statusCode: 400, headers, body: JSON.stringify({ error: 'No transcript provided' }) };

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
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
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
    const analysis = JSON.parse(content);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success: true, analysis }),
    };
  } catch (err) {
    console.error('AI Analyze error:', err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: err.message || 'Internal server error' }),
    };
  }
};
