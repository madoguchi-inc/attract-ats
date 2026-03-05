// One-time migration - add room_email and room_name to booking_sessions
const handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };
  
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Missing env vars' }) };
  }

  // Use Supabase's SQL execution via the REST API
  // We'll use the RPC approach - create a function if available, or use the pg_net extension
  
  // Actually, the simplest approach for Supabase is to use the /rest/v1/rpc endpoint
  // But we need a function. Let's try adding a column via PATCH - Supabase auto-creates columns for jsonb
  
  // Better: use the Supabase Management API (requires management token) or just manually add via dashboard
  // For now, let's check if the columns already exist by trying to insert with them
  
  try {
    // Try to select with room_email column
    const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/booking_sessions?select=room_email&limit=1`, {
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` },
    });
    
    if (checkRes.ok) {
      return { statusCode: 200, headers, body: JSON.stringify({ message: 'Columns already exist' }) };
    }
    
    // If not, try to use the query/sql endpoint
    const sqlRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/exec_sql`, {
      method: 'POST',
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ sql: "ALTER TABLE booking_sessions ADD COLUMN IF NOT EXISTS room_email TEXT DEFAULT NULL; ALTER TABLE booking_sessions ADD COLUMN IF NOT EXISTS room_name TEXT DEFAULT NULL;" }),
    });
    
    const sqlData = await sqlRes.json().catch(() => null);
    return { statusCode: sqlRes.ok ? 200 : 500, headers, body: JSON.stringify({ status: sqlRes.status, data: sqlData }) };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
  }
};

module.exports = { handler };
