// VPS监控面板 - Cloudflare Worker解决方案
// 版本: 2.1.0 - 代码结构优化版

// ==================== 配置常量 ====================

// 默认管理员账户配置
const DEFAULT_ADMIN_CONFIG = {
  USERNAME: 'admin',
  PASSWORD: 'monitor2025!',
};

// 安全配置
function getSecurityConfig(env) {
  return {
    JWT_SECRET: env.JWT_SECRET || 'default-jwt-secret-please-set-in-worker-variables',
    TOKEN_EXPIRY: 24 * 60 * 60 * 1000, // 24小时
    MAX_LOGIN_ATTEMPTS: 5,
    LOGIN_ATTEMPT_WINDOW: 15 * 60 * 1000, // 15分钟
    API_RATE_LIMIT: 60, // 每分钟60次
    MIN_PASSWORD_LENGTH: 8,
    ALLOWED_ORIGINS: env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : [],
  };
}

// ==================== 全局存储 ====================

const rateLimitStore = new Map();
const loginAttemptStore = new Map();

// ==================== 工具函数 ====================

// 路径参数验证
function extractAndValidateServerId(path) {
  const serverId = path.split('/').pop();
  return serverId && /^[a-zA-Z0-9_-]{1,50}$/.test(serverId) ? serverId : null;
}

function extractPathSegment(path, index) {
  const segments = path.split('/');
  if (index >= segments.length) return null;

  const segment = segments[index];
  return segment && /^[a-zA-Z0-9_-]{1,50}$/.test(segment) ? segment : null;
}

// 输入验证
function validateInput(input, type, maxLength = 255) {
  if (!input || typeof input !== 'string' || input.length > maxLength) {
    return false;
  }

  const validators = {
    serverName: () => /^[\w\s\u4e00-\u9fa5-]{1,100}$/.test(input.trim()),
    description: () => input.trim().length <= 500,
    direction: () => ['up', 'down'].includes(input),
    url: () => {
      try {
        const url = new URL(input);
        return ['http:', 'https:'].includes(url.protocol);
      } catch {
        return false;
      }
    }
  };

  return validators[type] ? validators[type]() : input.trim().length > 0;
}

// ==================== 密码处理 ====================

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hashedPassword) {
  const hashedInput = await hashPassword(password);
  return hashedInput === hashedPassword;
}

// ==================== JWT处理 ====================

async function createJWT(payload, env) {
  const config = getSecurityConfig(env);
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Date.now();
  const jwtPayload = { ...payload, iat: now, exp: now + config.TOKEN_EXPIRY };

  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(jwtPayload));
  const data = encodedHeader + '.' + encodedPayload;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(config.JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));

  return data + '.' + encodedSignature;
}

async function verifyJWT(token, env) {
  try {
    const config = getSecurityConfig(env);
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    if (!encodedHeader || !encodedPayload || !encodedSignature) return null;

    const data = encodedHeader + '.' + encodedPayload;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(config.JWT_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signature = Uint8Array.from(atob(encodedSignature), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!isValid) return null;

    const payload = JSON.parse(atob(encodedPayload));
    if (payload.exp && Date.now() > payload.exp) return null;

    // 检查是否需要刷新令牌
    const tokenAge = Date.now() - payload.iat;
    const halfLife = config.TOKEN_EXPIRY / 2;
    if (tokenAge > halfLife) {
      payload.shouldRefresh = true;
    }

    return payload;
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

// ==================== 安全限制 ====================

function checkRateLimit(clientIP, endpoint, env) {
  const config = getSecurityConfig(env);
  const key = `${clientIP}:${endpoint}`;
  const now = Date.now();
  const windowStart = now - 60000;

  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, []);
  }

  const requests = rateLimitStore.get(key);
  const validRequests = requests.filter(timestamp => timestamp > windowStart);

  if (validRequests.length >= config.API_RATE_LIMIT) {
    return false;
  }

  validRequests.push(now);
  rateLimitStore.set(key, validRequests);
  return true;
}

function checkLoginAttempts(clientIP, env) {
  const config = getSecurityConfig(env);
  const now = Date.now();
  const windowStart = now - config.LOGIN_ATTEMPT_WINDOW;

  if (!loginAttemptStore.has(clientIP)) {
    loginAttemptStore.set(clientIP, []);
  }

  const attempts = loginAttemptStore.get(clientIP);
  const validAttempts = attempts.filter(timestamp => timestamp > windowStart);
  return validAttempts.length < config.MAX_LOGIN_ATTEMPTS;
}

function recordLoginAttempt(clientIP) {
  const now = Date.now();
  if (!loginAttemptStore.has(clientIP)) {
    loginAttemptStore.set(clientIP, []);
  }
  loginAttemptStore.get(clientIP).push(now);
}

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For') ||
         request.headers.get('X-Real-IP') ||
         '127.0.0.1';
}

// ==================== 数据库结构 ====================

const D1_SCHEMAS = {
  admin_credentials: `
    CREATE TABLE IF NOT EXISTS admin_credentials (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_login INTEGER,
      failed_attempts INTEGER DEFAULT 0,
      locked_until INTEGER DEFAULT NULL,
      must_change_password INTEGER DEFAULT 0,
      password_changed_at INTEGER DEFAULT NULL
    );`,

  servers: `
    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      api_key TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      sort_order INTEGER,
      last_notified_down_at INTEGER DEFAULT NULL
    );`,

  metrics: `
    CREATE TABLE IF NOT EXISTS metrics (
      server_id TEXT PRIMARY KEY,
      timestamp INTEGER,
      cpu TEXT,
      memory TEXT,
      disk TEXT,
      network TEXT,
      uptime INTEGER,
      FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
    );`,

  monitored_sites: `
    CREATE TABLE IF NOT EXISTS monitored_sites (
      id TEXT PRIMARY KEY,
      url TEXT NOT NULL UNIQUE,
      name TEXT,
      added_at INTEGER NOT NULL,
      last_checked INTEGER,
      last_status TEXT DEFAULT 'PENDING',
      last_status_code INTEGER,
      last_response_time_ms INTEGER,
      sort_order INTEGER,
      last_notified_down_at INTEGER DEFAULT NULL
    );`,

  site_status_history: `
    CREATE TABLE IF NOT EXISTS site_status_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      status TEXT NOT NULL,
      status_code INTEGER,
      response_time_ms INTEGER,
      FOREIGN KEY(site_id) REFERENCES monitored_sites(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_site_status_history_site_id_timestamp ON site_status_history (site_id, timestamp DESC);`,

  telegram_config: `
    CREATE TABLE IF NOT EXISTS telegram_config (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      bot_token TEXT,
      chat_id TEXT,
      enable_notifications INTEGER DEFAULT 0,
      updated_at INTEGER
    );
    INSERT OR IGNORE INTO telegram_config (id, bot_token, chat_id, enable_notifications, updated_at) VALUES (1, NULL, NULL, 0, NULL);`,

  app_config: `
    CREATE TABLE IF NOT EXISTS app_config (
      key TEXT PRIMARY KEY,
      value TEXT
    );
    INSERT OR IGNORE INTO app_config (key, value) VALUES ('vps_report_interval_seconds', '60');`
};

// ==================== 数据库初始化 ====================

async function ensureTablesExist(db, env) {
  console.log("初始化数据库表...");

  try {
    const createTableStatements = Object.values(D1_SCHEMAS).map(sql => db.prepare(sql));
    await db.batch(createTableStatements);
    console.log("✅ 数据库表创建成功");
  } catch (error) {
    console.error("数据库表创建失败:", error);
  }

  await createDefaultAdmin(db, env);
  await applySchemaAlterations(db);
}

async function applySchemaAlterations(db) {
  console.log("应用数据库结构更新...");

  const alterStatements = [
    "ALTER TABLE monitored_sites ADD COLUMN last_notified_down_at INTEGER DEFAULT NULL",
    "ALTER TABLE servers ADD COLUMN last_notified_down_at INTEGER DEFAULT NULL",
    "ALTER TABLE metrics ADD COLUMN uptime INTEGER DEFAULT NULL",
    "ALTER TABLE admin_credentials ADD COLUMN password_hash TEXT",
    "ALTER TABLE admin_credentials ADD COLUMN created_at INTEGER",
    "ALTER TABLE admin_credentials ADD COLUMN last_login INTEGER",
    "ALTER TABLE admin_credentials ADD COLUMN failed_attempts INTEGER DEFAULT 0",
    "ALTER TABLE admin_credentials ADD COLUMN locked_until INTEGER DEFAULT NULL",
    "ALTER TABLE admin_credentials ADD COLUMN must_change_password INTEGER DEFAULT 0",
    "ALTER TABLE admin_credentials ADD COLUMN password_changed_at INTEGER DEFAULT NULL"
  ];

  for (const alterSql of alterStatements) {
    try {
      await db.exec(alterSql);
    } catch (e) {
      if (!e.message?.includes("duplicate column name") && !e.message?.includes("already exists")) {
        console.error('数据库结构更新错误:', e.message);
      }
    }
  }
}

async function isUsingDefaultPassword(username, password) {
  return username === DEFAULT_ADMIN_CONFIG.USERNAME && password === DEFAULT_ADMIN_CONFIG.PASSWORD;
}

async function createDefaultAdmin(db, env) {
  try {
    console.log("检查管理员账户...");

    const adminExists = await db.prepare(
      "SELECT username FROM admin_credentials WHERE username = ?"
    ).bind(DEFAULT_ADMIN_CONFIG.USERNAME).first();

    if (!adminExists) {
      const adminPasswordHash = await hashPassword(DEFAULT_ADMIN_CONFIG.PASSWORD);
      const now = Math.floor(Date.now() / 1000);

      await db.prepare(`
        INSERT INTO admin_credentials (username, password_hash, created_at, failed_attempts, must_change_password)
        VALUES (?, ?, ?, 0, 0)
      `).bind(DEFAULT_ADMIN_CONFIG.USERNAME, adminPasswordHash, now).run();

      console.log('✅ 已创建默认管理员账户:', DEFAULT_ADMIN_CONFIG.USERNAME);
      console.log('✅ 默认密码:', DEFAULT_ADMIN_CONFIG.PASSWORD);
    } else {
      console.log('✅ 管理员账户已存在:', DEFAULT_ADMIN_CONFIG.USERNAME);
    }
  } catch (error) {
    console.error("创建管理员账户失败:", error);
    if (!error.message.includes('no such table')) {
      throw error;
    }
  }
}


// ==================== 身份验证 ====================

async function authenticateRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.substring(7);
  const payload = await verifyJWT(token, env);
  if (!payload) return null;

  // 验证用户状态
  const user = await env.DB.prepare(
    'SELECT username, locked_until FROM admin_credentials WHERE username = ?'
  ).bind(payload.username).first();

  if (!user || (user.locked_until && Date.now() < user.locked_until)) {
    return null;
  }

  return payload;
}

// ==================== CORS处理 ====================

function getSecureCorsHeaders(origin, env) {
  const config = getSecurityConfig(env);
  const allowedOrigins = config.ALLOWED_ORIGINS;

  let allowedOrigin = 'null';
  if (allowedOrigins.length === 0) {
    allowedOrigin = origin || '*';
  } else if (allowedOrigins.includes('*')) {
    allowedOrigin = '*';
  } else if (origin && allowedOrigins.includes(origin)) {
    allowedOrigin = origin;
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Allow-Credentials': allowedOrigin !== '*' ? 'true' : 'false',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net;"
  };
}

// ==================== API请求处理 ====================

async function handleApiRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientIP = getClientIP(request);
  const origin = request.headers.get('Origin');
  const corsHeaders = getSecureCorsHeaders(origin, env);

  // OPTIONS请求处理
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // 速率限制检查（登录接口除外）
  if (path !== '/api/auth/login' && !checkRateLimit(clientIP, path, env)) {
    return new Response(JSON.stringify({
      error: 'Rate limit exceeded',
      message: '请求过于频繁，请稍后再试'
    }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // 数据库初始化API（无需认证）
  if (path === '/api/init-db' && ['POST', 'GET'].includes(method)) {
    try {
      console.log("手动触发数据库初始化...");
      await ensureTablesExist(env.DB, env);
      return new Response(JSON.stringify({
        success: true,
        message: '数据库初始化完成'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("数据库初始化失败:", error);
      return new Response(JSON.stringify({
        error: 'Database initialization failed',
        message: `数据库初始化失败: ${error.message}`
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // ==================== 认证API ====================

  // 登录处理
  if (path === '/api/auth/login' && method === 'POST') {
    try {
      if (!checkLoginAttempts(clientIP, env)) {
        return new Response(JSON.stringify({
          error: 'Too many login attempts',
          message: '登录尝试次数过多，请15分钟后再试'
        }), {
          status: 429,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const { username, password } = await request.json();
      if (!username || !password) {
        recordLoginAttempt(clientIP);
        return new Response(JSON.stringify({
          error: 'Missing credentials',
          message: '用户名和密码不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取用户凭证
      const user = await env.DB.prepare(`
        SELECT username, password_hash, failed_attempts, locked_until, must_change_password
        FROM admin_credentials WHERE username = ?
      `).bind(username).first();

      if (!user) {
        recordLoginAttempt(clientIP);
        return new Response(JSON.stringify({
          error: 'Invalid credentials',
          message: '用户名或密码错误。如果是首次部署，请等待1-2分钟让数据库初始化完成。'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 检查账户锁定状态
      if (user.locked_until && Date.now() < user.locked_until) {
        const unlockTime = new Date(user.locked_until).toLocaleString('zh-CN');
        return new Response(JSON.stringify({
          error: 'Account locked',
          message: `账户已被锁定，解锁时间：${unlockTime}`
        }), {
          status: 423,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 密码验证
      const isValidPassword = await verifyPassword(password, user.password_hash);
      if (!isValidPassword) {
        recordLoginAttempt(clientIP);

        const newFailedAttempts = (user.failed_attempts || 0) + 1;
        const config = getSecurityConfig(env);
        const lockedUntil = newFailedAttempts >= config.MAX_LOGIN_ATTEMPTS
          ? Date.now() + config.LOGIN_ATTEMPT_WINDOW
          : null;

        await env.DB.prepare(`
          UPDATE admin_credentials SET failed_attempts = ?, locked_until = ? WHERE username = ?
        `).bind(newFailedAttempts, lockedUntil, username).run();

        return new Response(JSON.stringify({
          error: 'Invalid credentials',
          message: '用户名或密码错误'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 登录成功处理
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare(`
        UPDATE admin_credentials SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?
      `).bind(now, username).run();

      // 检查默认密码使用情况
      const usingDefaultPassword = await isUsingDefaultPassword(username, password);
      console.log('登录检查 - 使用默认密码:', usingDefaultPassword);

      // 生成JWT令牌
      const tokenPayload = { username };
      if (usingDefaultPassword) {
        tokenPayload.usingDefaultPassword = true;
      }

      const token = await createJWT(tokenPayload, env);
      const config = getSecurityConfig(env);
      const responseData = {
        token,
        user: { username },
        expires_in: config.TOKEN_EXPIRY / 1000
      };

      if (usingDefaultPassword) {
        responseData.usingDefaultPassword = true;
        responseData.message = '您正在使用默认密码，建议修改密码以确保安全';
      }

      return new Response(JSON.stringify(responseData), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error("Login error:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '服务器内部错误'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 密码修改
  if (path === '/api/auth/change-password' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要登录'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { current_password, new_password } = await request.json();
      if (!current_password || !new_password) {
        return new Response(JSON.stringify({
          error: 'Missing required fields',
          message: '当前密码和新密码都是必需的'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 密码强度验证
      const config = getSecurityConfig(env);
      if (new_password.length < config.MIN_PASSWORD_LENGTH) {
        return new Response(JSON.stringify({
          error: 'Password too weak',
          message: `新密码长度不能少于${config.MIN_PASSWORD_LENGTH}个字符`
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取当前用户信息
      const currentUser = await env.DB.prepare(`
        SELECT username, password_hash FROM admin_credentials WHERE username = ?
      `).bind(user.username).first();

      if (!currentUser) {
        return new Response(JSON.stringify({
          error: 'User not found',
          message: '用户不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 验证当前密码
      const isCurrentPasswordValid = await verifyPassword(current_password, currentUser.password_hash);
      if (!isCurrentPasswordValid) {
        return new Response(JSON.stringify({
          error: 'Invalid current password',
          message: '当前密码错误'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 更新密码
      const newPasswordHash = await hashPassword(new_password);
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare(`
        UPDATE admin_credentials SET password_hash = ?, password_changed_at = ? WHERE username = ?
      `).bind(newPasswordHash, now, user.username).run();

      return new Response(JSON.stringify({
        success: true,
        message: '密码修改成功'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error("Change password error:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '服务器内部错误'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 令牌刷新
  if (path === '/api/auth/refresh' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要有效的令牌'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const newToken = await createJWT({ username: user.username }, env);
      const config = getSecurityConfig(env);
      return new Response(JSON.stringify({
        token: newToken,
        user: { username: user.username },
        expires_in: config.TOKEN_EXPIRY / 1000,
        message: '令牌刷新成功'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("令牌刷新错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '令牌刷新失败'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 登录状态检查
  if (path === '/api/auth/status' && method === 'GET') {
    const user = await authenticateRequest(request, env);
    const responseData = {
      authenticated: !!user,
      user: user ? {
        username: user.username,
        mustChangePassword: user.mustChangePassword || false,
        shouldRefresh: user.shouldRefresh || false,
        usingDefaultPassword: user.usingDefaultPassword || false
      } : null
    };

    return new Response(JSON.stringify(responseData), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }


  
  // ==================== 服务器API ====================

  // 获取服务器列表（公开）
  if (path === '/api/servers' && method === 'GET') {
    try {
      const { results } = await env.DB.prepare(
        'SELECT id, name, description FROM servers ORDER BY sort_order ASC NULLS LAST, name ASC'
      ).all();

      return new Response(JSON.stringify({ servers: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取服务器列表错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("服务器表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.servers);
          return new Response(JSON.stringify({ servers: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建服务器表失败:", createError);
          return new Response(JSON.stringify({
            error: 'Database error',
            message: createError.message
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 获取服务器状态（公开）
  if (path.startsWith('/api/status/') && method === 'GET') {
    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取服务器信息
      const serverData = await env.DB.prepare(
        'SELECT id, name, description FROM servers WHERE id = ?'
      ).bind(serverId).first();

      if (!serverData) {
        return new Response(JSON.stringify({ error: 'Server not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取监控数据
      const metricsResult = await env.DB.prepare(
        'SELECT timestamp, cpu, memory, disk, network, uptime FROM metrics WHERE server_id = ?'
      ).bind(serverId).first();

      let metricsData = null;
      if (metricsResult) {
        try {
          metricsData = {
            timestamp: metricsResult.timestamp,
            cpu: JSON.parse(metricsResult.cpu || '{}'),
            memory: JSON.parse(metricsResult.memory || '{}'),
            disk: JSON.parse(metricsResult.disk || '{}'),
            network: JSON.parse(metricsResult.network || '{}'),
            uptime: metricsResult.uptime
          };
        } catch (parseError) {
          console.error(`解析服务器 ${serverId} 监控数据错误:`, parseError);
          metricsData = {
            timestamp: metricsResult.timestamp,
            uptime: metricsResult.uptime
          };
        }
      }

      return new Response(JSON.stringify({
        server: serverData,
        metrics: metricsData
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取服务器状态错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("服务器或监控表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.servers + D1_SCHEMAS.metrics);
          return new Response(JSON.stringify({
            error: 'Server not found (tables created)'
          }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建表失败:", createError);
          return new Response(JSON.stringify({
            error: 'Database error',
            message: createError.message
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // ==================== 管理员API ====================

  // 获取所有服务器（管理员）
  if (path === '/api/admin/servers' && method === 'GET') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { results } = await env.DB.prepare(`
        SELECT s.id, s.name, s.description, s.created_at, s.sort_order,
               s.last_notified_down_at, s.api_key, m.timestamp as last_report
        FROM servers s
        LEFT JOIN metrics m ON s.id = m.server_id
        ORDER BY s.sort_order ASC NULLS LAST, s.name ASC
      `).all();

      return new Response(JSON.stringify({ servers: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员获取服务器列表错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("服务器或监控表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.servers + D1_SCHEMAS.metrics);
          return new Response(JSON.stringify({ servers: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建表失败:", createError);
          return new Response(JSON.stringify({
            error: 'Database error',
            message: createError.message
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '服务器内部错误'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 添加新服务器（管理员）
  if (path === '/api/admin/servers' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { name, description } = await request.json();

      // 输入验证
      if (!name?.trim()) {
        return new Response(JSON.stringify({
          error: 'Server name is required',
          message: '服务器名称不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (name.trim().length > 100) {
        return new Response(JSON.stringify({
          error: 'Server name too long',
          message: '服务器名称不能超过100个字符'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 生成服务器ID和API密钥
      const serverId = Math.random().toString(36).substring(2, 10);
      const apiKey = Math.random().toString(36).substring(2, 15) +
                     Math.random().toString(36).substring(2, 15);
      const createdAt = Math.floor(Date.now() / 1000);

      // 获取下一个排序序号
      const maxOrderResult = await env.DB.prepare(
        'SELECT MAX(sort_order) as max_order FROM servers'
      ).first();
      const nextSortOrder = (maxOrderResult?.max_order && typeof maxOrderResult.max_order === 'number')
        ? maxOrderResult.max_order + 1
        : 0;

      // 保存服务器数据
      await env.DB.prepare(`
        INSERT INTO servers (id, name, description, api_key, created_at, sort_order)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(serverId, name, description || '', apiKey, createdAt, nextSortOrder).run();

      const serverData = {
        id: serverId,
        name,
        description: description || '',
        api_key: apiKey,
        created_at: createdAt,
        sort_order: nextSortOrder
      };

      return new Response(JSON.stringify({ server: serverData }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员添加服务器错误:", error);

      if (error.message.includes('UNIQUE constraint failed')) {
        return new Response(JSON.stringify({
          error: 'Server ID or API Key conflict',
          message: '服务器ID或API密钥冲突，请重试'
        }), {
          status: 409,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (error.message.includes('no such table')) {
        console.warn("服务器表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.servers);
          return new Response(JSON.stringify({
            error: 'Database table created, please retry',
            message: '数据库表已创建，请重试添加操作'
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建服务器表失败:", createError);
          return new Response(JSON.stringify({
            error: 'Database error',
            message: createError.message
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 删除服务器（管理员）
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'DELETE') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 删除服务器（外键约束会自动删除关联的metrics数据）
      const info = await env.DB.prepare('DELETE FROM servers WHERE id = ?').bind(serverId).run();

      if (info.changes === 0) {
        return new Response(JSON.stringify({
          error: 'Server not found',
          message: '服务器不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      return new Response(JSON.stringify({
        success: true,
        message: '服务器删除成功'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员删除服务器错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '服务器内部错误'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // 更新服务器（管理员）
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'PUT') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const { name, description } = await request.json();

      // 输入验证
      if (!name || !validateInput(name, 'serverName')) {
        return new Response(JSON.stringify({
          error: 'Invalid server name',
          message: '服务器名称格式无效（1-100个字符，支持字母、数字、空格、连字符、下划线、中文）'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (description && !validateInput(description, 'description')) {
        return new Response(JSON.stringify({
          error: 'Invalid description',
          message: '描述格式无效（最多500个字符）'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 构建动态更新查询
      const setClauses = [];
      const bindings = [];

      if (name !== undefined) {
        setClauses.push("name = ?");
        bindings.push(name);
      }
      if (description !== undefined) {
        setClauses.push("description = ?");
        bindings.push(description || '');
      }

      if (setClauses.length === 0) {
        return new Response(JSON.stringify({
          error: 'No fields to update provided'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      bindings.push(serverId);
      const info = await env.DB.prepare(
        `UPDATE servers SET ${setClauses.join(', ')} WHERE id = ?`
      ).bind(...bindings).run();

      if (info.changes === 0) {
        return new Response(JSON.stringify({
          error: 'Server not found'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员更新服务器错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  
  // ==================== 配置获取API ====================

  // VPS配置获取（使用API密钥认证）
  if (path.startsWith('/api/config/') && method === 'GET') {
    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const apiKey = request.headers.get('X-API-Key');
      if (!apiKey) {
        return new Response(JSON.stringify({
          error: 'API key required',
          message: '需要API密钥'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 验证服务器和API密钥
      const serverData = await env.DB.prepare(
        'SELECT id, name, description, api_key FROM servers WHERE id = ?'
      ).bind(serverId).first();

      if (!serverData) {
        return new Response(JSON.stringify({
          error: 'Server not found',
          message: '服务器不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (serverData.api_key !== apiKey) {
        return new Response(JSON.stringify({
          error: 'Invalid API key',
          message: 'API密钥无效'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取VPS上报间隔设置
      let reportInterval = 60; // 默认值
      try {
        const intervalResult = await env.DB.prepare(
          'SELECT value FROM app_config WHERE key = ?'
        ).bind('vps_report_interval_seconds').first();

        if (intervalResult?.value) {
          const parsedInterval = parseInt(intervalResult.value, 10);
          if (!isNaN(parsedInterval) && parsedInterval > 0) {
            reportInterval = parsedInterval;
          }
        }
      } catch (intervalError) {
        console.warn("获取VPS上报间隔失败，使用默认值:", intervalError);
      }

      // 返回配置信息
      const configData = {
        success: true,
        config: {
          report_interval: reportInterval,
          enabled_metrics: ['cpu', 'memory', 'disk', 'network', 'uptime'],
          server_info: {
            id: serverData.id,
            name: serverData.name,
            description: serverData.description || ''
          }
        },
        timestamp: Math.floor(Date.now() / 1000)
      };

      return new Response(JSON.stringify(configData), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error("配置获取API错误:", error, {
        serverId,
        errorType: error.constructor.name,
        errorMessage: error.message,
        stack: error.stack
      });

      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: `服务器内部错误: ${error.message}`,
        details: '请稍后重试，如果问题持续存在请联系管理员'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // ==================== 数据上报API ====================

  // VPS数据上报
  if (path.startsWith('/api/report/') && method === 'POST') {
    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const apiKey = request.headers.get('X-API-Key');
      if (!apiKey) {
        return new Response(JSON.stringify({
          error: 'API key required'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 验证服务器和API密钥
      const serverData = await env.DB.prepare(
        'SELECT api_key FROM servers WHERE id = ?'
      ).bind(serverId).first();

      if (!serverData) {
        return new Response(JSON.stringify({
          error: 'Server not found'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (serverData.api_key !== apiKey) {
        return new Response(JSON.stringify({
          error: 'Invalid API key'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 解析和验证上报数据
      let reportData;
      let rawBody;
      try {
        rawBody = await request.text();
        console.log('收到的原始数据:', rawBody.substring(0, 200) + '...');
        reportData = JSON.parse(rawBody);
      } catch (parseError) {
        console.error('JSON解析错误:', parseError.message);
        console.error('原始数据:', rawBody || '无法读取原始数据');
        return new Response(JSON.stringify({
          error: 'Invalid JSON format',
          message: `JSON解析失败: ${parseError.message}`,
          details: '请检查上报的JSON格式是否正确'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      const requiredFields = ['timestamp', 'cpu', 'memory', 'disk', 'network'];

      for (const field of requiredFields) {
        if (!reportData[field]) {
          console.error(`VPS数据验证失败 - 缺少字段: ${field}`, {
            serverId,
            receivedFields: Object.keys(reportData),
            missingField: field
          });
          return new Response(JSON.stringify({
            error: 'Invalid data format',
            message: `缺少必需字段: ${field}`,
            details: `上报数据必须包含以下字段: ${requiredFields.join(', ')}, uptime`,
            received_fields: Object.keys(reportData)
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (typeof reportData.uptime === 'undefined') {
        console.error(`VPS数据验证失败 - 缺少uptime字段`, {
          serverId,
          receivedFields: Object.keys(reportData)
        });
        return new Response(JSON.stringify({
          error: 'Invalid data format',
          message: '缺少uptime字段',
          details: 'uptime字段是必需的，用于记录系统运行时间（秒）',
          received_fields: Object.keys(reportData)
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 增强的JSON对象结构验证
      const validateJsonObject = (obj, fieldName) => {
        if (!obj || typeof obj !== 'object') {
          console.warn(`${fieldName}字段不是有效的对象:`, obj);
          return false;
        }
        return true;
      };

      // 详细的数据结构验证
      const validateDataStructure = (data, type) => {
        if (!validateJsonObject(data, type)) {
          return false;
        }

        switch (type) {
          case 'CPU':
            return typeof data.usage_percent === 'number' &&
                   Array.isArray(data.load_avg) &&
                   data.load_avg.length === 3;
          case '内存':
          case '磁盘':
            return typeof data.total === 'number' &&
                   typeof data.used === 'number' &&
                   typeof data.free === 'number' &&
                   typeof data.usage_percent === 'number';
          case '网络':
            return typeof data.upload_speed === 'number' &&
                   typeof data.download_speed === 'number' &&
                   typeof data.total_upload === 'number' &&
                   typeof data.total_download === 'number';
          default:
            return true;
        }
      };

      // 验证各个JSON字段的结构，如果无效则使用默认值
      if (!validateDataStructure(reportData.cpu, 'CPU')) {
        console.warn('CPU数据结构无效，使用默认值:', reportData.cpu);
        reportData.cpu = { usage_percent: 0, load_avg: [0, 0, 0] };
      }
      if (!validateDataStructure(reportData.memory, '内存')) {
        console.warn('内存数据结构无效，使用默认值:', reportData.memory);
        reportData.memory = { total: 0, used: 0, free: 0, usage_percent: 0 };
      }
      if (!validateDataStructure(reportData.disk, '磁盘')) {
        console.warn('磁盘数据结构无效，使用默认值:', reportData.disk);
        reportData.disk = { total: 0, used: 0, free: 0, usage_percent: 0 };
      }
      if (!validateDataStructure(reportData.network, '网络')) {
        console.warn('网络数据结构无效，使用默认值:', reportData.network);
        reportData.network = { upload_speed: 0, download_speed: 0, total_upload: 0, total_download: 0 };
      }

      // 验证时间戳
      if (!Number.isInteger(reportData.timestamp) || reportData.timestamp <= 0) {
        console.warn('时间戳无效，使用当前时间:', reportData.timestamp);
        reportData.timestamp = Math.floor(Date.now() / 1000);
      }

      // 验证uptime
      if (!Number.isInteger(reportData.uptime) || reportData.uptime < 0) {
        console.warn('运行时间无效，设置为0:', reportData.uptime);
        reportData.uptime = 0;
      }

      // 保存监控数据
      await env.DB.prepare(`
        REPLACE INTO metrics (server_id, timestamp, cpu, memory, disk, network, uptime)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        serverId,
        reportData.timestamp,
        JSON.stringify(reportData.cpu),
        JSON.stringify(reportData.memory),
        JSON.stringify(reportData.disk),
        JSON.stringify(reportData.network),
        reportData.uptime
      ).run();

      // 获取VPS上报间隔设置
      let currentInterval = 60;
      try {
        const intervalResult = await env.DB.prepare(
          'SELECT value FROM app_config WHERE key = ?'
        ).bind('vps_report_interval_seconds').first();

        if (intervalResult?.value) {
          const parsedInterval = parseInt(intervalResult.value, 10);
          if (!isNaN(parsedInterval) && parsedInterval > 0) {
            currentInterval = parsedInterval;
          }
        }
      } catch (intervalError) {
        console.warn("获取VPS上报间隔失败，使用默认值:", intervalError);
      }

      return new Response(JSON.stringify({
        success: true,
        interval: currentInterval
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("数据上报API错误:", error, {
        serverId,
        errorType: error.constructor.name,
        errorMessage: error.message,
        stack: error.stack
      });

      if (error.message.includes('no such table')) {
        console.warn("服务器或监控表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.servers + D1_SCHEMAS.metrics);
          return new Response(JSON.stringify({
            error: 'Database table created or server not found, please retry or verify server ID/API Key',
            message: '数据库表已创建或服务器不存在，请重试或验证服务器ID/API密钥',
            details: '如果问题持续存在，请检查服务器配置',
            retry_suggested: true
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建表失败:", createError);
          return new Response(JSON.stringify({
            error: 'Database error',
            message: `数据库错误: ${createError.message}`,
            details: '无法创建必需的数据库表，请联系管理员'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: `服务器内部错误: ${error.message}`,
        details: '请稍后重试，如果问题持续存在请联系管理员',
        error_id: Date.now().toString(36) // 简单的错误ID用于追踪
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
  


  // ==================== 高级排序功能 ====================

  // 批量服务器排序（管理员）
  if (path === '/api/admin/servers/batch-reorder' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { serverIds } = await request.json(); // 按新顺序排列的服务器ID数组

      if (!Array.isArray(serverIds) || serverIds.length === 0) {
        return new Response(JSON.stringify({
          error: 'Invalid server IDs',
          message: '服务器ID数组无效'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 批量更新排序
      const updateStmts = serverIds.map((serverId, index) =>
        env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(index, serverId)
      );

      await env.DB.batch(updateStmts);

      return new Response(JSON.stringify({
        success: true,
        message: '批量排序完成'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("批量服务器排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 自动服务器排序（管理员）
  if (path === '/api/admin/servers/auto-sort' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { sortBy, order } = await request.json(); // sortBy: 'custom'|'name'|'status', order: 'asc'|'desc'

      const validSortFields = ['custom', 'name', 'status'];
      const validOrders = ['asc', 'desc'];

      if (!validSortFields.includes(sortBy) || !validOrders.includes(order)) {
        return new Response(JSON.stringify({
          error: 'Invalid sort parameters',
          message: '无效的排序参数'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 如果是自定义排序，直接返回成功，不做任何操作
      if (sortBy === 'custom') {
        return new Response(JSON.stringify({
          success: true,
          message: '已设置为自定义排序'
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取所有服务器并排序
      let orderClause = '';
      if (sortBy === 'name') {
        orderClause = `ORDER BY name ${order.toUpperCase()}`;
      } else if (sortBy === 'status') {
        orderClause = `ORDER BY (CASE WHEN m.timestamp IS NULL OR (strftime('%s', 'now') - m.timestamp) > 300 THEN 1 ELSE 0 END) ${order.toUpperCase()}, name ASC`;
      }

      const { results: servers } = await env.DB.prepare(`
        SELECT s.id FROM servers s
        LEFT JOIN metrics m ON s.id = m.server_id
        ${orderClause}
      `).all();

      // 批量更新排序
      const updateStmts = servers.map((server, index) =>
        env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(index, server.id)
      );

      await env.DB.batch(updateStmts);

      return new Response(JSON.stringify({
        success: true,
        message: `已按${sortBy}${order === 'asc' ? '升序' : '降序'}排序`
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("自动服务器排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 服务器排序（管理员）- 保留原有的单个移动功能
  if (path.match(/\/api\/admin\/servers\/[^\/]+\/reorder$/) && method === 'POST') {
    try {
      const serverId = extractPathSegment(path, 4);
      if (!serverId) {
        return new Response(JSON.stringify({
          error: 'Invalid server ID',
          message: '无效的服务器ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const { direction } = await request.json();
      if (!['up', 'down'].includes(direction)) {
        return new Response(JSON.stringify({
          error: 'Invalid direction'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取所有服务器排序信息
      const results = await env.DB.batch([
        env.DB.prepare('SELECT id, sort_order FROM servers ORDER BY sort_order ASC NULLS LAST, name ASC')
      ]);

      const allServers = results[0].results;
      const currentIndex = allServers.findIndex(s => s.id === serverId);

      if (currentIndex === -1) {
        return new Response(JSON.stringify({
          error: 'Server not found'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 计算目标位置
      let targetIndex = -1;
      if (direction === 'up' && currentIndex > 0) {
        targetIndex = currentIndex - 1;
      } else if (direction === 'down' && currentIndex < allServers.length - 1) {
        targetIndex = currentIndex + 1;
      }

      if (targetIndex !== -1) {
        const currentServer = allServers[currentIndex];
        const targetServer = allServers[targetIndex];

        // 处理排序值交换
        if (currentServer.sort_order === null || targetServer.sort_order === null) {
          console.warn("检测到NULL排序值，重新分配所有排序");
          const updateStmts = allServers.map((server, index) =>
            env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(index, server.id)
          );
          await env.DB.batch(updateStmts);

          // 重新获取并交换
          const updatedResults = await env.DB.batch([
            env.DB.prepare('SELECT id, sort_order FROM servers ORDER BY sort_order ASC')
          ]);
          const updatedServers = updatedResults[0].results;
          const newCurrentIndex = updatedServers.findIndex(s => s.id === serverId);
          let newTargetIndex = -1;

          if (direction === 'up' && newCurrentIndex > 0) {
            newTargetIndex = newCurrentIndex - 1;
          } else if (direction === 'down' && newCurrentIndex < updatedServers.length - 1) {
            newTargetIndex = newCurrentIndex + 1;
          }

          if (newTargetIndex !== -1) {
            const newCurrentOrder = updatedServers[newCurrentIndex].sort_order;
            const newTargetOrder = updatedServers[newTargetIndex].sort_order;
            await env.DB.batch([
              env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(newTargetOrder, serverId),
              env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(newCurrentOrder, updatedServers[newTargetIndex].id)
            ]);
          }
        } else {
          // 直接交换排序值
          await env.DB.batch([
            env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(targetServer.sort_order, serverId),
            env.DB.prepare('UPDATE servers SET sort_order = ? WHERE id = ?').bind(currentServer.sort_order, targetServer.id)
          ]);
        }
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员服务器排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }



  // ==================== 网站监控API ====================

  // 获取监控站点列表（管理员）
  if (path === '/api/admin/sites' && method === 'GET') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { results } = await env.DB.prepare(`
        SELECT id, name, url, added_at, last_checked, last_status, last_status_code,
               last_response_time_ms, sort_order, last_notified_down_at
        FROM monitored_sites
        ORDER BY sort_order ASC NULLS LAST, name ASC, url ASC
      `).all();

      return new Response(JSON.stringify({ sites: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员获取监控站点错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("监控站点表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.monitored_sites);
          return new Response(JSON.stringify({ sites: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建监控站点表失败:", createError);
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: '服务器内部错误'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 添加监控站点（管理员）
  if (path === '/api/admin/sites' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { url, name } = await request.json();

      if (!url || !isValidHttpUrl(url)) {
        return new Response(JSON.stringify({
          error: 'Valid URL is required',
          message: '请输入有效的URL'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const siteId = Math.random().toString(36).substring(2, 12);
      const addedAt = Math.floor(Date.now() / 1000);

      // 获取下一个排序序号
      const maxOrderResult = await env.DB.prepare(
        'SELECT MAX(sort_order) as max_order FROM monitored_sites'
      ).first();
      const nextSortOrder = (maxOrderResult?.max_order && typeof maxOrderResult.max_order === 'number')
        ? maxOrderResult.max_order + 1
        : 0;

      await env.DB.prepare(`
        INSERT INTO monitored_sites (id, url, name, added_at, last_status, sort_order)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(siteId, url, name || '', addedAt, 'PENDING', nextSortOrder).run();

      const siteData = {
        id: siteId,
        url,
        name: name || '',
        added_at: addedAt,
        last_status: 'PENDING',
        sort_order: nextSortOrder
      };

      // 立即执行健康检查
      const newSiteForCheck = { id: siteId, url, name: name || '' };
      if (ctx?.waitUntil) {
        ctx.waitUntil(checkWebsiteStatus(newSiteForCheck, env.DB, ctx));
        console.log(`已安排新站点立即健康检查: ${siteId} (${url})`);
      } else {
        console.warn("ctx.waitUntil不可用，尝试直接调用检查");
        checkWebsiteStatus(newSiteForCheck, env.DB, ctx).catch(e =>
          console.error("直接站点检查错误:", e)
        );
      }

      return new Response(JSON.stringify({ site: siteData }), {
        status: 201,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员添加监控站点错误:", error);

      if (error.message.includes('UNIQUE constraint failed')) {
        return new Response(JSON.stringify({
          error: 'URL already exists or ID conflict',
          message: '该URL已被监控或ID冲突'
        }), {
          status: 409,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (error.message.includes('no such table')) {
        console.warn("监控站点表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.monitored_sites);
          return new Response(JSON.stringify({
            error: 'Database table created, please retry',
            message: '数据库表已创建，请重试添加操作'
          }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建监控站点表失败:", createError);
        }
      }

      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 更新监控站点（管理员）
  if (path.match(/\/api\/admin\/sites\/[^\/]+$/) && method === 'PUT') {
    try {
      const siteId = extractAndValidateServerId(path);
      if (!siteId) {
        return new Response(JSON.stringify({
          error: 'Invalid site ID',
          message: '无效的站点ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const { url, name } = await request.json();
      const setClauses = [];
      const bindings = [];

      if (url !== undefined) {
        if (!isValidHttpUrl(url)) {
          return new Response(JSON.stringify({
            error: 'Valid URL is required if provided'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        setClauses.push("url = ?");
        bindings.push(url);
      }

      if (name !== undefined) {
        setClauses.push("name = ?");
        bindings.push(name || '');
      }

      if (setClauses.length === 0) {
        return new Response(JSON.stringify({
          error: 'No fields to update provided'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      bindings.push(siteId);
      const info = await env.DB.prepare(
        `UPDATE monitored_sites SET ${setClauses.join(', ')} WHERE id = ?`
      ).bind(...bindings).run();

      if (info.changes === 0) {
        return new Response(JSON.stringify({
          error: 'Site not found or no changes made'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const updatedSite = await env.DB.prepare(`
        SELECT id, url, name, added_at, last_checked, last_status, last_status_code,
               last_response_time_ms, sort_order
        FROM monitored_sites WHERE id = ?
      `).bind(siteId).first();

      return new Response(JSON.stringify({ site: updatedSite }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error("管理员更新监控站点错误:", error);
      if (error.message.includes('UNIQUE constraint failed')) {
        return new Response(JSON.stringify({
          error: 'URL already exists for another site',
          message: '该URL已被其他监控站点使用'
        }), {
          status: 409,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 删除监控站点（管理员）
  if (path.match(/\/api\/admin\/sites\/[^\/]+$/) && method === 'DELETE') {
    try {
      const siteId = extractAndValidateServerId(path);
      if (!siteId) {
        return new Response(JSON.stringify({
          error: 'Invalid site ID',
          message: '无效的站点ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const info = await env.DB.prepare('DELETE FROM monitored_sites WHERE id = ?').bind(siteId).run();

      if (info.changes === 0) {
        return new Response(JSON.stringify({
          error: 'Site not found'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员删除监控站点错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 批量网站排序（管理员）
  if (path === '/api/admin/sites/batch-reorder' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { siteIds } = await request.json(); // 按新顺序排列的站点ID数组

      if (!Array.isArray(siteIds) || siteIds.length === 0) {
        return new Response(JSON.stringify({
          error: 'Invalid site IDs',
          message: '站点ID数组无效'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 批量更新排序
      const updateStmts = siteIds.map((siteId, index) =>
        env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(index, siteId)
      );

      await env.DB.batch(updateStmts);

      return new Response(JSON.stringify({
        success: true,
        message: '批量排序完成'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("批量网站排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 自动网站排序（管理员）
  if (path === '/api/admin/sites/auto-sort' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { sortBy, order } = await request.json(); // sortBy: 'custom'|'name'|'url'|'status', order: 'asc'|'desc'

      const validSortFields = ['custom', 'name', 'url', 'status'];
      const validOrders = ['asc', 'desc'];

      if (!validSortFields.includes(sortBy) || !validOrders.includes(order)) {
        return new Response(JSON.stringify({
          error: 'Invalid sort parameters',
          message: '无效的排序参数'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 如果是自定义排序，直接返回成功，不做任何操作
      if (sortBy === 'custom') {
        return new Response(JSON.stringify({
          success: true,
          message: '已设置为自定义排序'
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取所有站点并排序
      const { results: sites } = await env.DB.prepare(`
        SELECT id FROM monitored_sites
        ORDER BY ${sortBy} ${order.toUpperCase()}
      `).all();

      // 批量更新排序
      const updateStmts = sites.map((site, index) =>
        env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(index, site.id)
      );

      await env.DB.batch(updateStmts);

      return new Response(JSON.stringify({
        success: true,
        message: `已按${sortBy}${order === 'asc' ? '升序' : '降序'}排序`
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("自动网站排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 网站排序（管理员）- 保留原有的单个移动功能
  if (path.match(/\/api\/admin\/sites\/[^\/]+\/reorder$/) && method === 'POST') {
    try {
      const siteId = extractPathSegment(path, 4);
      if (!siteId) {
        return new Response(JSON.stringify({
          error: 'Invalid site ID',
          message: '无效的站点ID格式'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const { direction } = await request.json();
      if (!['up', 'down'].includes(direction)) {
        return new Response(JSON.stringify({
          error: 'Invalid direction'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 获取所有站点排序信息
      const results = await env.DB.batch([
        env.DB.prepare('SELECT id, sort_order FROM monitored_sites ORDER BY sort_order ASC NULLS LAST, name ASC, url ASC')
      ]);
      const allSites = results[0].results;
      const currentIndex = allSites.findIndex(s => s.id === siteId);

      if (currentIndex === -1) {
        return new Response(JSON.stringify({
          error: 'Site not found'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 计算目标位置
      let targetIndex = -1;
      if (direction === 'up' && currentIndex > 0) {
        targetIndex = currentIndex - 1;
      } else if (direction === 'down' && currentIndex < allSites.length - 1) {
        targetIndex = currentIndex + 1;
      }

      if (targetIndex !== -1) {
        const currentSite = allSites[currentIndex];
        const targetSite = allSites[targetIndex];

        // 处理排序值交换
        if (currentSite.sort_order === null || targetSite.sort_order === null) {
          console.warn("检测到NULL排序值，重新分配所有站点排序");
          const updateStmts = allSites.map((site, index) =>
            env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(index, site.id)
          );
          await env.DB.batch(updateStmts);

          // 重新获取并交换
          const updatedResults = await env.DB.batch([
            env.DB.prepare('SELECT id, sort_order FROM monitored_sites ORDER BY sort_order ASC')
          ]);
          const updatedSites = updatedResults[0].results;
          const newCurrentIndex = updatedSites.findIndex(s => s.id === siteId);
          let newTargetIndex = -1;

          if (direction === 'up' && newCurrentIndex > 0) {
            newTargetIndex = newCurrentIndex - 1;
          } else if (direction === 'down' && newCurrentIndex < updatedSites.length - 1) {
            newTargetIndex = newCurrentIndex + 1;
          }

          if (newTargetIndex !== -1) {
            const newCurrentOrder = updatedSites[newCurrentIndex].sort_order;
            const newTargetOrder = updatedSites[newTargetIndex].sort_order;
            await env.DB.batch([
              env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(newTargetOrder, siteId),
              env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(newCurrentOrder, updatedSites[newTargetIndex].id)
            ]);
          }
        } else {
          // 直接交换排序值
          await env.DB.batch([
            env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(targetSite.sort_order, siteId),
            env.DB.prepare('UPDATE monitored_sites SET sort_order = ? WHERE id = ?').bind(currentSite.sort_order, targetSite.id)
          ]);
        }
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("管理员网站排序错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }


  // ==================== 公共API ====================

  // 获取所有监控站点状态（公开，不包含URL）
  if (path === '/api/sites/status' && method === 'GET') {
    try {
      const { results } = await env.DB.prepare(`
        SELECT id, name, last_checked, last_status, last_status_code, last_response_time_ms
        FROM monitored_sites
        ORDER BY sort_order ASC NULLS LAST, name ASC, id ASC
      `).all();

      return new Response(JSON.stringify({ sites: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取站点状态错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("监控站点表不存在，尝试创建...");
        try {
          await env.DB.exec(D1_SCHEMAS.monitored_sites);
          return new Response(JSON.stringify({ sites: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建监控站点表失败:", createError);
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // ==================== VPS配置API ====================

  // 获取VPS上报间隔（公开，优化版本）
  if (path === '/api/admin/settings/vps-report-interval' && method === 'GET') {
    try {
      // 优化：减少数据库查询，快速返回默认值或缓存值
      let interval = 60; // 默认值

      try {
        const result = await env.DB.prepare(
          'SELECT value FROM app_config WHERE key = ?'
        ).bind('vps_report_interval_seconds').first();

        if (result && result.value) {
          const parsedInterval = parseInt(result.value, 10);
          if (!isNaN(parsedInterval) && parsedInterval > 0) {
            interval = parsedInterval;
          }
        }
      } catch (dbError) {
        console.warn("数据库查询VPS间隔失败，使用默认值:", dbError);
        // 继续使用默认值，不阻塞响应
      }

      return new Response(JSON.stringify({ interval }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取VPS上报间隔错误:", error);
      // 任何错误都返回默认值，确保系统继续工作
      return new Response(JSON.stringify({ interval: 60 }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 设置VPS上报间隔（管理员）
  if (path === '/api/admin/settings/vps-report-interval' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { interval } = await request.json();
      if (typeof interval !== 'number' || interval <= 0 || !Number.isInteger(interval)) {
        return new Response(JSON.stringify({
          error: 'Invalid interval value. Must be a positive integer (seconds).'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      await env.DB.prepare('REPLACE INTO app_config (key, value) VALUES (?, ?)').bind(
        'vps_report_interval_seconds',
        interval.toString()
      ).run();

      return new Response(JSON.stringify({ success: true, interval }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("更新VPS上报间隔错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }


  // ==================== Telegram配置API ====================

  // 获取Telegram设置（管理员）
  if (path === '/api/admin/telegram-settings' && method === 'GET') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const settings = await env.DB.prepare(
        'SELECT bot_token, chat_id, enable_notifications FROM telegram_config WHERE id = 1'
      ).first();

      return new Response(JSON.stringify(
        settings || { bot_token: null, chat_id: null, enable_notifications: 0 }
      ), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取Telegram设置错误:", error);
      if (error.message.includes('no such table')) {
        try {
          await env.DB.exec(D1_SCHEMAS.telegram_config);
          return new Response(JSON.stringify({
            bot_token: null,
            chat_id: null,
            enable_notifications: 0
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建Telegram配置表失败:", createError);
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 设置Telegram配置（管理员）
  if (path === '/api/admin/telegram-settings' && method === 'POST') {
    const user = await authenticateRequest(request, env);
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: '需要管理员权限'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const { bot_token, chat_id, enable_notifications } = await request.json();
      const updatedAt = Math.floor(Date.now() / 1000);
      const enableNotifValue = (enable_notifications === true || enable_notifications === 1) ? 1 : 0;

      await env.DB.prepare(`
        UPDATE telegram_config SET bot_token = ?, chat_id = ?, enable_notifications = ?, updated_at = ? WHERE id = 1
      `).bind(bot_token || null, chat_id || null, enableNotifValue, updatedAt).run();

      // 发送测试通知
      if (enableNotifValue === 1 && bot_token && chat_id) {
        const testMessage = "✅ Telegram通知已在此监控面板激活。这是一条测试消息。";
        if (ctx?.waitUntil) {
          ctx.waitUntil(sendTelegramNotification(env.DB, testMessage));
        } else {
          console.warn("ctx.waitUntil不可用，尝试直接发送测试通知");
          sendTelegramNotification(env.DB, testMessage).catch(e =>
            console.error("发送测试通知错误:", e)
          );
        }
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("更新Telegram设置错误:", error);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 获取监控站点24小时历史状态（公开）
  if (path.match(/\/api\/sites\/[^\/]+\/history$/) && method === 'GET') {
    try {
      const siteId = path.split('/')[3];
      const nowSeconds = Math.floor(Date.now() / 1000);
      const twentyFourHoursAgoSeconds = nowSeconds - (24 * 60 * 60);

      const { results } = await env.DB.prepare(`
        SELECT timestamp, status, status_code, response_time_ms
        FROM site_status_history
        WHERE site_id = ? AND timestamp >= ?
        ORDER BY timestamp DESC
      `).bind(siteId, twentyFourHoursAgoSeconds).all();

      return new Response(JSON.stringify({ history: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
      console.error("获取站点历史错误:", error);
      if (error.message.includes('no such table')) {
        console.warn("站点状态历史表不存在，返回空列表");
        try {
          await env.DB.exec(D1_SCHEMAS.site_status_history);
          return new Response(JSON.stringify({ history: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
          console.error("创建站点状态历史表失败:", createError);
        }
      }
      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }


  // 未找到匹配的API路由
  return new Response(JSON.stringify({ error: 'API endpoint not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}


// --- Scheduled Task for Website Monitoring ---

// ==================== Telegram通知 ====================

async function sendTelegramNotification(db, message) {
  try {
    const config = await db.prepare(
      'SELECT bot_token, chat_id, enable_notifications FROM telegram_config WHERE id = 1'
    ).first();

    if (!config?.enable_notifications || !config.bot_token || !config.chat_id) {
      console.log("Telegram通知未启用或配置不完整");
      return;
    }

    const response = await fetch(`https://api.telegram.org/bot${config.bot_token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.chat_id,
        text: message,
        parse_mode: 'Markdown'
      })
    });

    if (response.ok) {
      console.log("Telegram通知发送成功");
    } else {
      const errorData = await response.json();
      console.error(`Telegram通知发送失败: ${response.status}`, errorData);
    }
  } catch (error) {
    console.error("Telegram通知发送错误:", error);
  }
}


async function checkWebsiteStatus(site, db, ctx) { // Added ctx for waitUntil
  const { id, url, name } = site; // Added name
  const startTime = Date.now();
  let newStatus = 'PENDING'; // Renamed to newStatus to avoid conflict
  let newStatusCode = null; // Renamed
  let newResponseTime = null; // Renamed

  // Get current status and last notification time from DB
  let previousStatus = 'PENDING';
  let siteLastNotifiedDownAt = null;

  try {
    const siteDetailsStmt = db.prepare('SELECT last_status, last_notified_down_at FROM monitored_sites WHERE id = ?'); // Removed enable_frequent_down_notifications
    const siteDetailsResult = await siteDetailsStmt.bind(id).first();
    if (siteDetailsResult) {
      previousStatus = siteDetailsResult.last_status || 'PENDING';
      siteLastNotifiedDownAt = siteDetailsResult.last_notified_down_at;
    }
  } catch (e) {
    console.error(`获取网站 ${id} 详情错误:`, e);
  }
  const NOTIFICATION_INTERVAL_SECONDS = 1 * 60 * 60; // 1 hour


  try {
    const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(15000) });
    newResponseTime = Date.now() - startTime;
    newStatusCode = response.status;

    if (response.ok || (response.status >= 300 && response.status < 500)) { // 2xx, 3xx, and 4xx are considered UP
      newStatus = 'UP';
    } else {
      newStatus = 'DOWN';
    }
  } catch (error) {
    newResponseTime = Date.now() - startTime;
    if (error.name === 'TimeoutError') {
      newStatus = 'TIMEOUT';
    } else {
      newStatus = 'ERROR';
      console.error(`检查网站 ${id} (${url}) 错误:`, error.message);
    }
  }

  const checkTime = Math.floor(Date.now() / 1000);
  const siteDisplayName = name || url;
  let newSiteLastNotifiedDownAt = siteLastNotifiedDownAt; // Preserve by default

  if (['DOWN', 'TIMEOUT', 'ERROR'].includes(newStatus)) {
    const isFirstTimeDown = !['DOWN', 'TIMEOUT', 'ERROR'].includes(previousStatus);
    if (isFirstTimeDown) {
      // Site just went down
      const message = `🔴 网站故障: *${siteDisplayName}* 当前状态 ${newStatus.toLowerCase()} (状态码: ${newStatusCode || '无'}).\n网址: ${url}`;
      ctx.waitUntil(sendTelegramNotification(db, message));
      newSiteLastNotifiedDownAt = checkTime;
      console.log(`网站 ${siteDisplayName} 刚刚故障。已发送初始通知。last_notified_down_at 已更新。`);
    } else {
      // Site is still down, check if 1-hour interval has passed for resend
      const shouldResend = siteLastNotifiedDownAt === null || (checkTime - siteLastNotifiedDownAt > NOTIFICATION_INTERVAL_SECONDS);
      if (shouldResend) {
        const message = `🔴 网站持续故障: *${siteDisplayName}* 状态 ${newStatus.toLowerCase()} (状态码: ${newStatusCode || '无'}).\n网址: ${url}`;
        ctx.waitUntil(sendTelegramNotification(db, message));
        newSiteLastNotifiedDownAt = checkTime;
        console.log(`网站 ${siteDisplayName} 持续故障。已发送重复通知。last_notified_down_at 已更新。`);
      } else {
        console.log(`网站 ${siteDisplayName} 持续故障，但1小时通知间隔未到。`);
      }
    }
  } else if (newStatus === 'UP' && ['DOWN', 'TIMEOUT', 'ERROR'].includes(previousStatus)) {
    // Site just came back up
    const message = `✅ 网站恢复: *${siteDisplayName}* 已恢复在线!\n网址: ${url}`;
    ctx.waitUntil(sendTelegramNotification(db, message));
    newSiteLastNotifiedDownAt = null; // Clear notification timestamp as site is up
    console.log(`网站 ${siteDisplayName} 已恢复。已发送通知。last_notified_down_at 已清除。`);
  }

  // Update D1
  try {
    const updateSiteStmt = db.prepare(
      'UPDATE monitored_sites SET last_checked = ?, last_status = ?, last_status_code = ?, last_response_time_ms = ?, last_notified_down_at = ? WHERE id = ?'
    );
    const recordHistoryStmt = db.prepare(
      'INSERT INTO site_status_history (site_id, timestamp, status, status_code, response_time_ms) VALUES (?, ?, ?, ?, ?)'
    );
    
    await db.batch([
      updateSiteStmt.bind(checkTime, newStatus, newStatusCode, newResponseTime, newSiteLastNotifiedDownAt, id),
      recordHistoryStmt.bind(id, checkTime, newStatus, newStatusCode, newResponseTime)
    ]);
    console.log(`已检查网站 ${id} (${url}): ${newStatus} (${newStatusCode || '无'}), ${newResponseTime}ms。历史已记录。通知时间戳已更新。`);
  } catch (dbError) {
    console.error(`更新网站 ${id} (${url}) 状态或记录历史到D1失败:`, dbError);
  }
}

// ==================== 主函数导出 ====================

export default {
  async fetch(request, env, ctx) {
    // 初始化数据库表
    try {
      await ensureTablesExist(env.DB, env);
    } catch (error) {
      console.error("数据库初始化失败:", error);
      // 继续执行，各个端点会处理缺失的表
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // API请求处理
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env, ctx);
    }

    // 安装脚本处理
    if (path === '/install.sh') {
      return handleInstallScript(request, url, env);
    }

    // 前端静态文件处理
    return handleFrontendRequest(request, path);
  },

  async scheduled(event, env, ctx) {
    console.log(`定时任务触发: ${event.cron} - 开始执行状态检查...`);
    ctx.waitUntil(
      (async () => {
        try {
          // 确保数据库表存在
          await ensureTablesExist(env.DB, env);

          // ==================== 网站监控部分 ====================
          console.log("开始定时网站检查...");
          const { results: sitesToCheck } = await env.DB.prepare(
            'SELECT id, url, name FROM monitored_sites'
          ).all();

          if (sitesToCheck?.length > 0) {
            console.log(`发现 ${sitesToCheck.length} 个站点需要检查`);
            const sitePromises = [];
            const siteConcurrencyLimit = 10;

            for (const site of sitesToCheck) {
              sitePromises.push(checkWebsiteStatus(site, env.DB, ctx));
              if (sitePromises.length >= siteConcurrencyLimit) {
                await Promise.all(sitePromises);
                sitePromises.length = 0;
              }
            }

            if (sitePromises.length > 0) {
              await Promise.all(sitePromises);
            }
            console.log("网站状态检查完成");
          } else {
            console.log("未配置监控网站");
          }

          // ==================== VPS监控部分 ====================
          console.log("开始定时VPS状态检查...");
          const telegramConfig = await env.DB.prepare(
            'SELECT bot_token, chat_id, enable_notifications FROM telegram_config WHERE id = 1'
          ).first();

          if (!telegramConfig?.enable_notifications || !telegramConfig.bot_token || !telegramConfig.chat_id) {
            console.log("VPS的Telegram通知已禁用或未配置，跳过VPS检查");
            return;
          }

          const { results: serversToCheck } = await env.DB.prepare(`
            SELECT s.id, s.name, s.last_notified_down_at, m.timestamp as last_report
            FROM servers s LEFT JOIN metrics m ON s.id = m.server_id
          `).all();

          if (!serversToCheck?.length) {
            console.log("未找到用于VPS状态检查的服务器");
            return;
          }

          console.log(`发现 ${serversToCheck.length} 台服务器需要VPS状态检查`);
          const nowSeconds = Math.floor(Date.now() / 1000);
          const staleThresholdSeconds = 5 * 60; // 5分钟
          const NOTIFICATION_INTERVAL_SECONDS = 1 * 60 * 60; // 1小时

          for (const server of serversToCheck) {
            const isStale = !server.last_report || (nowSeconds - server.last_report > staleThresholdSeconds);
            const serverDisplayName = server.name || server.id;
            const lastReportTimeStr = server.last_report
              ? new Date(server.last_report * 1000).toLocaleString('zh-CN')
              : '从未';

            if (isStale) {
              // 服务器被认为离线/过期
              const shouldSendNotification = server.last_notified_down_at === null ||
                (nowSeconds - server.last_notified_down_at > NOTIFICATION_INTERVAL_SECONDS);

              if (shouldSendNotification) {
                const message = `🔴 VPS故障: 服务器 *${serverDisplayName}* 似乎已离线。最后报告: ${lastReportTimeStr}`;
                ctx.waitUntil(sendTelegramNotification(env.DB, message));
                ctx.waitUntil(env.DB.prepare('UPDATE servers SET last_notified_down_at = ? WHERE id = ?').bind(nowSeconds, server.id).run());
                console.log(`VPS ${serverDisplayName} 状态过期，已发送通知`);
              } else {
                console.log(`VPS ${serverDisplayName} 状态过期，但1小时通知间隔未到`);
              }
            } else {
              // 服务器正在报告（在线）
              if (server.last_notified_down_at !== null) {
                // 之前被通知为离线，现在已恢复
                const message = `✅ VPS恢复: 服务器 *${serverDisplayName}* 已恢复在线并正在报告。当前报告: ${lastReportTimeStr}`;
                ctx.waitUntil(sendTelegramNotification(env.DB, message));
                ctx.waitUntil(env.DB.prepare('UPDATE servers SET last_notified_down_at = NULL WHERE id = ?').bind(server.id).run());
                console.log(`VPS ${serverDisplayName} 已恢复，已发送通知`);
              } else {
                console.log(`VPS ${serverDisplayName} 在线并正在报告，无需通知`);
              }
            }
          }
          console.log("VPS状态检查完成");

        } catch (error) {
          console.error("定时任务执行错误:", error);
        }
      })()
    );
  }
};


// ==================== 工具函数 ====================

// HTTP/HTTPS URL验证
function isValidHttpUrl(string) {
  try {
    const url = new URL(string);
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}


// ==================== 处理函数 ====================

// 安装脚本处理
async function handleInstallScript(request, url, env) {
  const baseUrl = url.origin;
  let vpsReportInterval = '60'; // 默认值

  try {
    // 确保app_config表存在
    if (D1_SCHEMAS?.app_config) {
      await env.DB.exec(D1_SCHEMAS.app_config);
    } else {
      console.warn("D1_SCHEMAS.app_config未定义，跳过创建");
    }

    const result = await env.DB.prepare(
      'SELECT value FROM app_config WHERE key = ?'
    ).bind('vps_report_interval_seconds').first();

    if (result?.value) {
      const parsedInterval = parseInt(result.value, 10);
      if (!isNaN(parsedInterval) && parsedInterval > 0) {
        vpsReportInterval = parsedInterval.toString();
      }
    }
  } catch (e) {
    console.error("获取VPS上报间隔失败:", e);
    // 使用默认值
  }
  
  const script = `#!/bin/bash
# VPS监控脚本 - 安装程序

# 默认值
API_KEY=""
SERVER_ID=""
WORKER_URL="${baseUrl}"
INSTALL_DIR="/opt/vps-monitor"
SERVICE_NAME="vps-monitor"

# 解析参数
while [[ $# -gt 0 ]]; do
  case $1 in
    -k|--key)
      API_KEY="$2"
      shift 2
      ;;
    -s|--server)
      SERVER_ID="$2"
      shift 2
      ;;
    -u|--url)
      WORKER_URL="$2"
      shift 2
      ;;
    -d|--dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    *)
      echo "未知参数: $1"
      exit 1
      ;;
  esac
done

# 检查必要参数
if [ -z "$API_KEY" ] || [ -z "$SERVER_ID" ]; then
  echo "错误: API密钥和服务器ID是必需的"
  echo "用法: $0 -k API_KEY -s SERVER_ID [-u WORKER_URL] [-d INSTALL_DIR]"
  exit 1
fi

# 检查权限
if [ "$(id -u)" -ne 0 ]; then
  echo "错误: 此脚本需要root权限"
  exit 1
fi

echo "=== VPS监控脚本安装程序 ==="
echo "安装目录: $INSTALL_DIR"
echo "Worker URL: $WORKER_URL"

# 创建安装目录
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" || exit 1

# 创建监控脚本
cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/bash

# 配置
API_KEY="__API_KEY__"
SERVER_ID="__SERVER_ID__"
WORKER_URL="__WORKER_URL__"
INTERVAL=${vpsReportInterval}  # 上报间隔（秒）

# 日志函数
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 获取CPU使用率
get_cpu_usage() {
  cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk '{print 100 - $1}')
  cpu_load=$(cat /proc/loadavg | awk '{print $1","$2","$3}')
  echo "{\"usage_percent\":$cpu_usage,\"load_avg\":[$cpu_load]}"
}

# 获取内存使用情况
get_memory_usage() {
  total=$(free -k | grep Mem | awk '{print $2}')
  used=$(free -k | grep Mem | awk '{print $3}')
  free=$(free -k | grep Mem | awk '{print $4}')
  usage_percent=$(echo "scale=1; $used * 100 / $total" | bc)
  echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取硬盘使用情况
get_disk_usage() {
  disk_info=$(df -k / | tail -1)
  total=$(echo "$disk_info" | awk '{print $2 / 1024 / 1024}')
  used=$(echo "$disk_info" | awk '{print $3 / 1024 / 1024}')
  free=$(echo "$disk_info" | awk '{print $4 / 1024 / 1024}')
  usage_percent=$(echo "$disk_info" | awk '{print $5}' | tr -d '%')
  echo "{\"total\":$total,\"used\":$used,\"free\":$free,\"usage_percent\":$usage_percent}"
}

# 获取网络使用情况
get_network_usage() {
  # 检查是否安装了ifstat
  if ! command -v ifstat &> /dev/null; then
    log "ifstat未安装，无法获取网络速度"
    echo "{\"upload_speed\":0,\"download_speed\":0,\"total_upload\":0,\"total_download\":0}"
    return
  fi
  
  # 获取网络接口
  interface=$(ip route | grep default | awk '{print $5}')
  
  # 获取网络速度（KB/s）
  network_speed=$(ifstat -i "$interface" 1 1 | tail -1)
  download_speed=$(echo "$network_speed" | awk '{print $1 * 1024}')
  upload_speed=$(echo "$network_speed" | awk '{print $2 * 1024}')
  
  # 获取总流量
  rx_bytes=$(cat /proc/net/dev | grep "$interface" | awk '{print $2}')
  tx_bytes=$(cat /proc/net/dev | grep "$interface" | awk '{print $10}')
  
  echo "{\"upload_speed\":$upload_speed,\"download_speed\":$download_speed,\"total_upload\":$tx_bytes,\"total_download\":$rx_bytes}"
}

# 上报数据
report_metrics() {
  timestamp=$(date +%s)
  cpu=$(get_cpu_usage)
  memory=$(get_memory_usage)
  disk=$(get_disk_usage)
  network=$(get_network_usage)
  
  data="{\"timestamp\":$timestamp,\"cpu\":$cpu,\"memory\":$memory,\"disk\":$disk,\"network\":$network}"
  
  log "正在上报数据..."
  log "API密钥: $API_KEY"
  log "服务器ID: $SERVER_ID"
  log "Worker URL: $WORKER_URL"
  
  response=$(curl -s -X POST "$WORKER_URL/api/report/$SERVER_ID" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "$data")
  
  if [[ "$response" == *"success"* ]]; then
    log "数据上报成功"
  else
    log "数据上报失败: $response"
  fi
}

# 安装依赖
install_dependencies() {
  log "检查并安装依赖..."
  
  # 检测包管理器
  if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
  elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
  else
    log "不支持的系统，无法自动安装依赖"
    return 1
  fi
  
  # 安装依赖
  $PKG_MANAGER update -y
  $PKG_MANAGER install -y bc curl ifstat
  
  log "依赖安装完成"
  return 0
}

# 主函数
main() {
  log "VPS监控脚本启动"
  
  # 安装依赖
  install_dependencies
  
  # 主循环
  while true; do
    report_metrics
    sleep $INTERVAL
  done
}

# 启动主函数
main
EOF

# 替换配置
sed -i "s|__API_KEY__|$API_KEY|g" "$INSTALL_DIR/monitor.sh"
sed -i "s|__SERVER_ID__|$SERVER_ID|g" "$INSTALL_DIR/monitor.sh"
sed -i "s|__WORKER_URL__|$WORKER_URL|g" "$INSTALL_DIR/monitor.sh"
# This line ensures the INTERVAL placeholder is replaced with the fetched value.
sed -i "s|^INTERVAL=.*|INTERVAL=${vpsReportInterval}|g" "$INSTALL_DIR/monitor.sh"

# 设置执行权限
chmod +x "$INSTALL_DIR/monitor.sh"

# 创建systemd服务
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=VPS Monitor Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/monitor.sh
Restart=always
User=root
Group=root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo "=== 安装完成 ==="
echo "服务已启动并设置为开机自启"
echo "查看服务状态: systemctl status $SERVICE_NAME"
echo "查看服务日志: journalctl -u $SERVICE_NAME -f"
`;

  return new Response(script, {
    headers: {
      'Content-Type': 'text/plain',
      'Content-Disposition': 'attachment; filename="install.sh"'
    }
  });
}

// 前端请求处理
function handleFrontendRequest(request, path) {
  const routes = {
    '/': () => new Response(getIndexHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '': () => new Response(getIndexHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '/login': () => new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '/login.html': () => new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '/admin': () => new Response(getAdminHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '/admin.html': () => new Response(getAdminHtml(), { headers: { 'Content-Type': 'text/html' } }),
    '/css/style.css': () => new Response(getStyleCss(), { headers: { 'Content-Type': 'text/css' } }),
    '/js/main.js': () => new Response(getMainJs(), { headers: { 'Content-Type': 'application/javascript' } }),
    '/js/login.js': () => new Response(getLoginJs(), { headers: { 'Content-Type': 'application/javascript' } }),
    '/js/admin.js': () => new Response(getAdminJs(), { headers: { 'Content-Type': 'application/javascript' } })
  };

  const handler = routes[path];
  if (handler) {
    return handler();
  }

  // 404页面
  return new Response('Not Found', {
    status: 404,
    headers: { 'Content-Type': 'text/plain' }
  });
}

// ==================== 前端代码 ====================

// 主页HTML
function getIndexHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
    <style>
        .server-row {
            cursor: pointer; /* Indicate clickable rows */
        }
        .server-details-row {
            /* display: none; /* Initially hidden - controlled by JS */ */
        }
        .server-details-row td {
            padding: 1rem;
            background-color: #f8f9fa; /* Light background for details */
        }
        .server-details-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .detail-item {
            background-color: #e9ecef;
            padding: 0.75rem;
            border-radius: 0.25rem;
        }
        .detail-item strong {
            display: block;
            margin-bottom: 0.25rem;
        }
        .history-bar-container {
            display: inline-flex; /* Changed to inline-flex for centering within td */
            flex-direction: row-reverse; /* Newest on the right */
            align-items: center;
            justify-content: center; /* Center the bars within this container */
            height: 25px; /* Increased height */
            gap: 2px; /* Space between bars */
        }
        .history-bar {
            width: 8px; /* Increased width of each bar */
            height: 100%;
            /* margin-left: 1px; /* Replaced by gap */
            border-radius: 1px;
        }
        .history-bar-up { background-color: #28a745; } /* Green */
        .history-bar-down { background-color: #dc3545; } /* Red */
        .history-bar-pending { background-color: #6c757d; } /* Gray */

        /* Default styling for progress bar text (light mode) */
        .progress span {
            color: #000000; /* Black text for progress bars by default */
            /* font-weight: bold; is handled by inline style in JS */
        }

        /* Center the "24h记录" (site table) and "上传" (server table) headers and their data cells */
        .table > thead > tr > th:nth-child(6), /* Targets 6th header in both tables */
        #siteStatusTableBody tr > td:nth-child(6), /* Targets 6th data cell in site status table */
        #serverTableBody tr > td:nth-child(6) { /* Targets 6th data cell in server status table */
            text-align: center;
        }

        /* Dark Theme Adjustments */
        [data-bs-theme="dark"] body {
            background-color: #212529 !important; /* Bootstrap dark bg */
            color: #ffffff !important; /* White text for dark mode */
        }
        [data-bs-theme="dark"] h1, [data-bs-theme="dark"] h2, [data-bs-theme="dark"] h3, [data-bs-theme="dark"] h4, [data-bs-theme="dark"] h5, [data-bs-theme="dark"] h6 {
            color: #ffffff; /* White color for headings */
        }
        [data-bs-theme="dark"] a:not(.btn):not(.nav-link):not(.dropdown-item):not(.navbar-brand) {
            color: #87cefa; /* LightSkyBlue for general links, good contrast on dark */
        }
        [data-bs-theme="dark"] a:not(.btn):not(.nav-link):not(.dropdown-item):not(.navbar-brand):hover {
            color: #add8e6; /* Lighter blue on hover */
        }
        [data-bs-theme="dark"] .navbar-dark {
            background-color: #343a40 !important; /* Darker navbar */
        }
        [data-bs-theme="dark"] .table {
            color: #ffffff; /* White table text */
        }
        [data-bs-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) > * {
            --bs-table-accent-bg: rgba(255, 255, 255, 0.05); /* Darker stripe */
            color: #ffffff; /* Ensure text in striped rows is white */
        }
        [data-bs-theme="dark"] .table-hover > tbody > tr:hover > * {
            --bs-table-accent-bg: rgba(255, 255, 255, 0.075); /* Darker hover */
            color: #ffffff; /* Ensure text in hovered rows is white */
        }
        [data-bs-theme="dark"] .server-details-row td {
            background-color: #343a40; /* Darker details background */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .detail-item {
            background-color: #495057; /* Darker detail item background */
            color: #ffffff; /* White text for detail items */
        }
        [data-bs-theme="dark"] .progress {
            background-color: #495057; /* Darker progress bar background */
        }
        [data-bs-theme="dark"] .progress span { /* Text on progress bar */
            color: #000000 !important; /* Black text for progress bars */
            text-shadow: none; /* Remove shadow for black text or use a very light one if needed */
        }
        [data-bs-theme="dark"] .footer.bg-light {
            background-color: #343a40 !important; /* Darker footer */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .footer .text-muted {
            color: #adb5bd !important; /* Lighter muted text */
        }
        [data-bs-theme="dark"] .alert-info {
            background-color: #17a2b8; /* Bootstrap info color, adjust if needed */
            color: #fff;
            border-color: #17a2b8;
        }
        [data-bs-theme="dark"] .btn-outline-light {
            color: #f8f9fa;
            border-color: #f8f9fa;
        }
        [data-bs-theme="dark"] .btn-outline-light:hover {
            color: #212529;
            background-color: #f8f9fa;
        }
        [data-bs-theme="dark"] .card {
            background-color: #343a40;
            border: 1px solid #495057;
        }
        [data-bs-theme="dark"] .card-header {
            background-color: #495057;
            border-bottom: 1px solid #5b6167;
        }
        [data-bs-theme="dark"] .modal-content {
            background-color: #343a40;
            color: #ffffff; /* White modal text */
        }
        [data-bs-theme="dark"] .modal-header {
            border-bottom-color: #495057;
        }
        [data-bs-theme="dark"] .modal-footer {
            border-top-color: #495057;
        }
        [data-bs-theme="dark"] .form-control {
            background-color: #495057;
            color: #ffffff; /* White form control text */
            border-color: #5b6167;
        }
        [data-bs-theme="dark"] .form-control:focus {
            background-color: #495057;
            color: #ffffff; /* White form control text on focus */
            border-color: #86b7fe; /* Bootstrap focus color */
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
        }
        [data-bs-theme="dark"] .form-label {
            color: #adb5bd;
        }
        [data-bs-theme="dark"] .text-danger { /* Ensure custom text-danger is visible */
            color: #ff8888 !important;
        }
        [data-bs-theme="dark"] .text-muted {
             color: #adb5bd !important;
        }
        [data-bs-theme="dark"] span[style*="color: #000"] { /* For inline styled black text */
            color: #ffffff !important; /* Change to white */
        }

        /* 拖拽排序样式 */
        .server-row-draggable, .site-row-draggable {
            transition: all 0.2s ease;
        }
        .server-row-draggable:hover, .site-row-draggable:hover {
            background-color: rgba(0, 123, 255, 0.1) !important;
        }
        .server-row-draggable.drag-over-top, .site-row-draggable.drag-over-top {
            border-top: 3px solid #007bff !important;
            background-color: rgba(0, 123, 255, 0.1) !important;
        }
        .server-row-draggable.drag-over-bottom, .site-row-draggable.drag-over-bottom {
            border-bottom: 3px solid #007bff !important;
            background-color: rgba(0, 123, 255, 0.1) !important;
        }
        .server-row-draggable[draggable="true"], .site-row-draggable[draggable="true"] {
            cursor: grab;
        }
        .server-row-draggable[draggable="true"]:active, .site-row-draggable[draggable="true"]:active {
            cursor: grabbing;
        }

        /* 暗色主题下的拖拽样式 */
        [data-bs-theme="dark"] .server-row-draggable:hover,
        [data-bs-theme="dark"] .site-row-draggable:hover {
            background-color: rgba(13, 110, 253, 0.2) !important;
        }
        [data-bs-theme="dark"] .server-row-draggable.drag-over-top,
        [data-bs-theme="dark"] .site-row-draggable.drag-over-top {
            border-top: 3px solid #0d6efd !important;
            background-color: rgba(13, 110, 253, 0.2) !important;
        }
        [data-bs-theme="dark"] .server-row-draggable.drag-over-bottom,
        [data-bs-theme="dark"] .site-row-draggable.drag-over-bottom {
            border-bottom: 3px solid #0d6efd !important;
            background-color: rgba(13, 110, 253, 0.2) !important;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <div class="d-flex align-items-center">
                <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="btn btn-outline-light btn-sm me-2" title="GitHub Repository">
                    <i class="bi bi-github"></i>
                </a>
                <button id="themeToggler" class="btn btn-outline-light btn-sm me-2" title="切换主题">
                    <i class="bi bi-moon-stars-fill"></i>
                </button>
                <a class="nav-link text-light" id="adminAuthLink" href="/login.html" style="white-space: nowrap;">管理员登录</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div id="noServers" class="alert alert-info d-none">
            暂无服务器数据，请先登录管理后台添加服务器。
        </div>

        <!-- 桌面端表格视图 -->
        <div class="table-responsive">
            <table class="table table-striped table-hover align-middle">
                <thead>
                    <tr>
                        <th>名称</th>
                        <th>状态</th>
                        <th>CPU</th>
                        <th>内存</th>
                        <th>硬盘</th>
                        <th>上传</th>
                        <th>下载</th>
                        <th>总上传</th>
                        <th>总下载</th>
                        <th>运行时长</th>
                        <th>最后更新</th>
                    </tr>
                </thead>
                <tbody id="serverTableBody">
                    <tr>
                        <td colspan="11" class="text-center">加载中...</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- 移动端卡片视图 -->
        <div class="mobile-card-container" id="mobileServerContainer">
            <div class="text-center p-3">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">加载中...</span>
                </div>
                <div class="mt-2">加载服务器数据中...</div>
            </div>
        </div>
    </div>

    <!-- Website Status Section -->
    <div class="container mt-5">
        <h2>网站在线状态</h2>
        <div id="noSites" class="alert alert-info d-none">
            暂无监控网站数据。
        </div>
        <!-- 桌面端表格视图 -->
        <div class="table-responsive">
            <table class="table table-striped table-hover align-middle">
                <thead>
                    <tr>
                        <th>名称</th>
                        <th>状态</th>
                        <th>状态码</th>
                        <th>响应时间 (ms)</th>
                        <th>最后检查</th>
                        <th>24h记录</th>
                    </tr>
                </thead>
                <tbody id="siteStatusTableBody">
                    <tr>
                        <td colspan="6" class="text-center">加载中...</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- 移动端卡片视图 -->
        <div class="mobile-card-container" id="mobileSiteContainer">
            <div class="text-center p-3">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">加载中...</span>
                </div>
                <div class="mt-2">加载网站数据中...</div>
            </div>
        </div>
    </div>
    <!-- End Website Status Section -->

    <!-- Server Detailed row template (hidden by default) -->
    <template id="serverDetailsTemplate">
        <tr class="server-details-row d-none">
            <td colspan="11">
                <div class="server-details-content">
                    <!-- Detailed metrics will be populated here by JavaScript -->
                </div>
            </td>
        </tr>
    </template>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github fs-5"></i>
            </a>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/main.js"></script>
</body>
</html>`;
}

function getLoginHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
    <style>
        .server-row {
            cursor: pointer; /* Indicate clickable rows */
        }
        .server-details-row {
            /* display: none; /* Initially hidden - controlled by JS */ */
        }
        .server-details-row td {
            padding: 1rem;
            background-color: #f8f9fa; /* Light background for details */
        }
        .server-details-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .detail-item {
            background-color: #e9ecef;
            padding: 0.75rem;
            border-radius: 0.25rem;
        }
        .detail-item strong {
            display: block;
            margin-bottom: 0.25rem;
        }
        .history-bar-container {
            display: inline-flex; /* Changed to inline-flex for centering within td */
            flex-direction: row-reverse; /* Newest on the right */
            align-items: center;
            justify-content: center; /* Center the bars within this container */
            height: 25px; /* Increased height */
            gap: 2px; /* Space between bars */
        }
        .history-bar {
            width: 8px; /* Increased width of each bar */
            height: 100%;
            /* margin-left: 1px; /* Replaced by gap */
            border-radius: 1px;
        }
        .history-bar-up { background-color: #28a745; } /* Green */
        .history-bar-down { background-color: #dc3545; } /* Red */
        .history-bar-pending { background-color: #6c757d; } /* Gray */

        /* Default styling for progress bar text (light mode) */
        .progress span {
            color: #000000; /* Black text for progress bars by default */
            /* font-weight: bold; is handled by inline style in JS */
        }

        /* Center the "24h记录" (site table) and "上传" (server table) headers and their data cells */
        .table > thead > tr > th:nth-child(6), /* Targets 6th header in both tables */
        #siteStatusTableBody tr > td:nth-child(6), /* Targets 6th data cell in site status table */
        #serverTableBody tr > td:nth-child(6) { /* Targets 6th data cell in server status table */
            text-align: center;
        }

        /* Dark Theme Adjustments */
        [data-bs-theme="dark"] body {
            background-color: #212529; /* Bootstrap dark bg */
            color: #ffffff; /* White text for dark mode */
        }
        [data-bs-theme="dark"] h1, [data-bs-theme="dark"] h2, [data-bs-theme="dark"] h3, [data-bs-theme="dark"] h4, [data-bs-theme="dark"] h5, [data-bs-theme="dark"] h6 {
            color: #ffffff; /* White color for headings */
        }
        [data-bs-theme="dark"] a:not(.btn):not(.nav-link):not(.dropdown-item):not(.navbar-brand) {
            color: #87cefa; /* LightSkyBlue for general links, good contrast on dark */
        }
        [data-bs-theme="dark"] a:not(.btn):not(.nav-link):not(.dropdown-item):not(.navbar-brand):hover {
            color: #add8e6; /* Lighter blue on hover */
        }
        [data-bs-theme="dark"] .navbar-dark {
            background-color: #343a40 !important; /* Darker navbar */
        }
        [data-bs-theme="dark"] .table {
            color: #ffffff; /* White table text */
        }
        [data-bs-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) > * {
            --bs-table-accent-bg: rgba(255, 255, 255, 0.05); /* Darker stripe */
            color: #ffffff; /* Ensure text in striped rows is white */
        }
        [data-bs-theme="dark"] .table-hover > tbody > tr:hover > * {
            --bs-table-accent-bg: rgba(255, 255, 255, 0.075); /* Darker hover */
            color: #ffffff; /* Ensure text in hovered rows is white */
        }
        [data-bs-theme="dark"] .server-details-row td {
            background-color: #343a40; /* Darker details background */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .detail-item {
            background-color: #495057; /* Darker detail item background */
            color: #ffffff; /* White text for detail items */
        }
        [data-bs-theme="dark"] .progress {
            background-color: #495057; /* Darker progress bar background */
        }
        [data-bs-theme="dark"] .progress span { /* Text on progress bar */
            color: #000000 !important; /* Black text for progress bars */
            text-shadow: none; /* Remove shadow for black text or use a very light one if needed */
        }
        [data-bs-theme="dark"] .footer.bg-light {
            background-color: #343a40 !important; /* Darker footer */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .footer .text-muted {
            color: #adb5bd !important; /* Lighter muted text */
        }
        [data-bs-theme="dark"] .alert-info {
            background-color: #17a2b8; /* Bootstrap info color, adjust if needed */
            color: #fff;
            border-color: #17a2b8;
        }
        [data-bs-theme="dark"] .btn-outline-light {
            color: #f8f9fa;
            border-color: #f8f9fa;
        }
        [data-bs-theme="dark"] .btn-outline-light:hover {
            color: #212529;
            background-color: #f8f9fa;
        }
        [data-bs-theme="dark"] .card {
            background-color: #343a40;
            border: 1px solid #495057;
        }
        [data-bs-theme="dark"] .card-header {
            background-color: #495057;
            border-bottom: 1px solid #5b6167;
        }
        [data-bs-theme="dark"] .modal-content {
            background-color: #343a40;
            color: #ffffff; /* White modal text */
        }
        [data-bs-theme="dark"] .modal-header {
            border-bottom-color: #495057;
        }
        [data-bs-theme="dark"] .modal-footer {
            border-top-color: #495057;
        }
        [data-bs-theme="dark"] .form-control {
            background-color: #495057;
            color: #ffffff; /* White form control text */
            border-color: #5b6167;
        }
        [data-bs-theme="dark"] .form-control:focus {
            background-color: #495057;
            color: #ffffff; /* White form control text on focus */
            border-color: #86b7fe; /* Bootstrap focus color */
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
        }
        [data-bs-theme="dark"] .form-label {
            color: #adb5bd;
        }
        [data-bs-theme="dark"] .text-danger { /* Ensure custom text-danger is visible */
            color: #ff8888 !important;
        }
        [data-bs-theme="dark"] .text-muted {
             color: #adb5bd !important;
        }
        [data-bs-theme="dark"] span[style*="color: #000"] { /* For inline styled black text */
            color: #ffffff !important; /* Change to white */
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <div class="d-flex align-items-center">
                <button id="themeToggler" class="btn btn-outline-light btn-sm me-2" title="切换主题">
                    <i class="bi bi-moon-stars-fill"></i>
                </button>
                <a class="nav-link text-light" href="/" style="white-space: nowrap;">返回首页</a>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title mb-0">管理员登录</h4>
                    </div>
                    <div class="card-body">
                        <div id="loginAlert" class="alert alert-danger d-none"></div>
                        <form id="loginForm">
                            <div class="mb-3">
                                <label for="username" class="form-label">用户名</label>
                                <input type="text" class="form-control" id="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">密码</label>
                                <input type="password" class="form-control" id="password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">登录</button>
                            </div>
                        </form>
                    </div>
                    <div class="card-footer text-muted">
                        <small id="defaultCredentialsInfo">加载默认凭据信息中...</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github fs-5"></i>
            </a>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/login.js"></script>
</body>
</html>`;
}

function getAdminHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台 - VPS监控面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">VPS监控面板</a>
            <div class="d-flex align-items-center flex-wrap">
                <a class="nav-link text-light me-2" href="/" style="white-space: nowrap;">返回首页</a>
                <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="btn btn-outline-light btn-sm me-1" title="GitHub Repository">
                    <i class="bi bi-github"></i>
                </a>
                <button id="themeToggler" class="btn btn-outline-light btn-sm me-1" title="切换主题">
                    <i class="bi bi-moon-stars-fill"></i>
                </button>
                <button id="changePasswordBtn" class="btn btn-outline-light btn-sm me-1" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">密码</button>
                <button id="logoutBtn" class="btn btn-outline-light btn-sm" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">退出</button>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="d-flex align-items-center mb-4"> <!-- Main flex container for the header row -->
            <h2 class="mb-0 me-3">服务器管理</h2> <!-- Server Management Heading -->

            <!-- VPS Data Update Frequency Form -->
            <form id="globalSettingsFormPartial" class="row gx-2 gy-2 align-items-center me-auto"> <!-- me-auto pushes Add Server button to the right -->
                <div class="col-auto">
                     <label for="vpsReportInterval" class="col-form-label col-form-label-sm">VPS数据更新频率 (秒):</label>
                </div>
                <div class="col-auto">
                    <input type="number" class="form-control form-control-sm" id="vpsReportInterval" placeholder="例如: 60" min="1" style="width: 100px;">
                </div>
                <div class="col-auto">
                    <button type="button" id="saveVpsReportIntervalBtn" class="btn btn-info btn-sm">保存频率</button>
                </div>
            </form>

            <!-- Server Auto Sort Dropdown -->
            <div class="dropdown me-2">
                <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="serverAutoSortDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-sort-alpha-down"></i> 自动排序
                </button>
                <ul class="dropdown-menu" aria-labelledby="serverAutoSortDropdown">
                    <li><a class="dropdown-item active" href="#" onclick="autoSortServers('custom')">自定义排序</a></li>
                    <li><a class="dropdown-item" href="#" onclick="autoSortServers('name')">按名称排序</a></li>
                    <li><a class="dropdown-item" href="#" onclick="autoSortServers('status')">按状态排序</a></li>
                </ul>
            </div>

            <!-- Add Server Button -->
            <button id="addServerBtn" class="btn btn-primary">
                <i class="bi bi-plus-circle"></i> 添加服务器
            </button>
        </div>
        <!-- Removed globalSettingsAlert as serverAlert will be used -->
        <div id="serverAlert" class="alert d-none"></div>
        <div class="card">
            <div class="card-body">
                <!-- 桌面端表格视图 -->
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>排序</th>
                                <th>ID</th>
                                <th>名称</th>
                                <th>描述</th>
                                <th>状态</th>
                                <th>最后更新</th>
                                <th>API密钥</th>
                                <th>VPS脚本</th>
                                <!-- Removed <th>频繁通知 (10分钟)</th> -->
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="serverTableBody">
                            <tr>
                                <td colspan="10" class="text-center">加载中...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- 移动端卡片视图 -->
                <div class="mobile-card-container" id="mobileAdminServerContainer">
                    <div class="text-center p-3">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">加载中...</span>
                        </div>
                        <div class="mt-2">加载服务器数据中...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Website Monitoring Section -->
    <div class="container mt-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>网站监控管理</h2>
            <div class="d-flex align-items-center">
                <!-- Site Auto Sort Dropdown -->
                <div class="dropdown me-2">
                    <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="siteAutoSortDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="bi bi-sort-alpha-down"></i> 自动排序
                    </button>
                    <ul class="dropdown-menu" aria-labelledby="siteAutoSortDropdown">
                        <li><a class="dropdown-item active" href="#" onclick="autoSortSites('custom')">自定义排序</a></li>
                        <li><a class="dropdown-item" href="#" onclick="autoSortSites('name')">按名称排序</a></li>
                        <li><a class="dropdown-item" href="#" onclick="autoSortSites('url')">按URL排序</a></li>
                        <li><a class="dropdown-item" href="#" onclick="autoSortSites('status')">按状态排序</a></li>
                    </ul>
                </div>

                <button id="addSiteBtn" class="btn btn-success">
                    <i class="bi bi-plus-circle"></i> 添加监控网站
                </button>
            </div>
        </div>

        <div id="siteAlert" class="alert d-none"></div>

        <div class="card">
            <div class="card-body">
                <!-- 桌面端表格视图 -->
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>排序</th>
                                <th>名称</th>
                                <th>URL</th>
                                <th>状态</th>
                                <th>状态码</th>
                                <th>响应时间 (ms)</th>
                                <th>最后检查</th>
                                <!-- Removed <th>频繁通知 (10分钟)</th> -->
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="siteTableBody">
                            <tr>
                                <td colspan="10" class="text-center">加载中...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- 移动端卡片视图 -->
                <div class="mobile-card-container" id="mobileAdminSiteContainer">
                    <div class="text-center p-3">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">加载中...</span>
                        </div>
                        <div class="mt-2">加载网站数据中...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- End Website Monitoring Section -->

    <!-- Telegram Notification Settings Section -->
    <div class="container mt-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Telegram 通知设置</h2>
        </div>
        <div id="telegramSettingsAlert" class="alert d-none"></div>
        <div class="card">
            <div class="card-body">
                <form id="telegramSettingsForm">
                    <div class="mb-3">
                        <label for="telegramBotToken" class="form-label">Bot Token</label>
                        <input type="text" class="form-control" id="telegramBotToken" placeholder="请输入 Telegram Bot Token">
                    </div>
                    <div class="mb-3">
                        <label for="telegramChatId" class="form-label">Chat ID</label>
                        <input type="text" class="form-control" id="telegramChatId" placeholder="请输入接收通知的 Chat ID">
                    </div>
                    <div class="form-check mb-3">
                        <input class="form-check-input" type="checkbox" id="enableTelegramNotifications">
                        <label class="form-check-label" for="enableTelegramNotifications">
                            启用通知
                        </label>
                    </div>
                    <button type="button" id="saveTelegramSettingsBtn" class="btn btn-info">保存Telegram设置</button>
                </form>
            </div>
        </div>
    </div>
    <!-- End Telegram Notification Settings Section -->

    <!-- Global Settings Section (Now integrated above Server Management List) -->
    <!-- The form is now part of the header for Server Management -->
    <!-- End Global Settings Section -->


    <!-- 服务器模态框 -->
    <div class="modal fade" id="serverModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="serverModalTitle">添加服务器</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="serverForm">
                        <input type="hidden" id="serverId">
                        <div class="mb-3">
                            <label for="serverName" class="form-label">服务器名称</label>
                            <input type="text" class="form-control" id="serverName" required>
                        </div>
                        <div class="mb-3">
                            <label for="serverDescription" class="form-label">描述（可选）</label>
                            <textarea class="form-control" id="serverDescription" rows="2"></textarea>
                        </div>
                        <!-- Removed serverEnableFrequentNotifications checkbox -->

                        <div id="serverIdDisplayGroup" class="mb-3 d-none">
                            <label for="serverIdDisplay" class="form-label">服务器ID</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="serverIdDisplay" readonly>
                                <button class="btn btn-outline-secondary" type="button" id="copyServerIdBtn">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                        </div>

                        <div id="apiKeyGroup" class="mb-3 d-none">
                            <label for="apiKey" class="form-label">API密钥</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="apiKey" readonly>
                                <button class="btn btn-outline-secondary" type="button" id="copyApiKeyBtn">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                        </div>

                        <div id="workerUrlDisplayGroup" class="mb-3 d-none">
                            <label for="workerUrlDisplay" class="form-label">Worker 地址</label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="workerUrlDisplay" readonly>
                                <button class="btn btn-outline-secondary" type="button" id="copyWorkerUrlBtn">
                                    <i class="bi bi-clipboard"></i>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" id="saveServerBtn">保存</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 网站监控模态框 -->
    <div class="modal fade" id="siteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="siteModalTitle">添加监控网站</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="siteForm">
                        <input type="hidden" id="siteId">
                        <div class="mb-3">
                            <label for="siteName" class="form-label">网站名称（可选）</label>
                            <input type="text" class="form-control" id="siteName">
                        </div>
                        <div class="mb-3">
                            <label for="siteUrl" class="form-label">网站URL</label>
                            <input type="url" class="form-control" id="siteUrl" placeholder="https://example.com" required>
                        </div>
                        <!-- Removed siteEnableFrequentNotifications checkbox -->
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" id="saveSiteBtn">保存</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 服务器删除确认模态框 -->
    <div class="modal fade" id="deleteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">确认删除</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>确定要删除服务器 "<span id="deleteServerName"></span>" 吗？</p>
                    <p class="text-danger">此操作不可逆，所有相关的监控数据也将被删除。</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-danger" id="confirmDeleteBtn">删除</button>
                </div>
            </div>
        </div>
    </div>

     <!-- 网站删除确认模态框 -->
    <div class="modal fade" id="deleteSiteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">确认删除网站监控</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>确定要停止监控网站 "<span id="deleteSiteName"></span>" (<span id="deleteSiteUrl"></span>) 吗？</p>
                    <p class="text-danger">此操作不可逆。</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-danger" id="confirmDeleteSiteBtn">删除</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 修改密码模态框 -->
    <div class="modal fade" id="passwordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">修改密码</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="passwordAlert" class="alert d-none"></div>
                    <form id="passwordForm">
                        <div class="mb-3">
                            <label for="currentPassword" class="form-label">当前密码</label>
                            <input type="password" class="form-control" id="currentPassword" required>
                        </div>
                        <div class="mb-3">
                            <label for="newPassword" class="form-label">新密码</label>
                            <input type="password" class="form-control" id="newPassword" required>
                        </div>
                        <div class="mb-3">
                            <label for="confirmPassword" class="form-label">确认新密码</label>
                            <input type="password" class="form-control" id="confirmPassword" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" id="savePasswordBtn">保存</button>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github fs-5"></i>
            </a>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/js/admin.js"></script>
</body>
</html>`;
}

function getStyleCss() {
  return `/* 全局样式 */
body {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.footer {
    margin-top: auto;
}

/* 图表容器 */
.chart-container {
    position: relative;
    height: 200px;
    width: 100%;
}

/* 卡片样式 */
.card {
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    margin-bottom: 1.5rem;
}

.card-header {
    background-color: rgba(0, 0, 0, 0.03);
    border-bottom: 1px solid rgba(0, 0, 0, 0.125);
}

/* 进度条样式 */
.progress {
    height: 0.75rem;
}

/* 表格样式 */
.table th {
    font-weight: 600;
}

/* Modal centering and light theme transparency */
.modal-dialog {
    display: flex;
    align-items: center;
    min-height: calc(100% - 1rem); /* Adjust as needed */
}

.modal-content {
    background-color: rgba(255, 255, 255, 0.9); /* Semi-transparent white for light theme */
    /* backdrop-filter: blur(5px); /* Optional: adds a blur effect to content behind modal */
}


/* 响应式调整 */
@media (max-width: 768px) {
    .chart-container {
        height: 150px;
    }

    /* 移动端隐藏表格，显示卡片 */
    .table-responsive {
        display: none !important;
    }

    .mobile-card-container {
        display: block !important;
    }

    /* 移动端导航栏优化 */
    .navbar-brand {
        font-size: 1rem;
        margin-right: 0.5rem;
    }

    .container {
        padding-left: 10px;
        padding-right: 10px;
    }

    /* 移动端导航栏按钮组优化 */
    .navbar .d-flex {
        gap: 0.25rem;
        flex-wrap: wrap;
    }

    .navbar .btn-sm {
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
        min-width: auto;
        border-width: 1px;
    }

    .navbar .nav-link {
        font-size: 0.8rem;
        padding: 0.25rem 0.5rem;
        margin: 0;
    }

    /* 超小屏幕优化 (小于400px) */
    @media (max-width: 400px) {
        .navbar-brand {
            font-size: 0.9rem;
        }

        .navbar .btn-sm {
            padding: 0.2rem 0.4rem;
            font-size: 0.7rem;
        }

        .navbar .nav-link {
            font-size: 0.75rem;
            padding: 0.2rem 0.4rem;
        }

        .container {
            padding-left: 8px;
            padding-right: 8px;
        }
    }

    /* 移动端按钮优化 */
    .btn-sm {
        padding: 0.375rem 0.75rem;
        font-size: 0.875rem;
    }
}

/* 桌面端隐藏卡片容器 */
@media (min-width: 769px) {
    .mobile-card-container {
        display: none !important;
    }
}

/* 移动端卡片样式 */
.mobile-card-container {
    display: none; /* 默认隐藏，通过媒体查询控制 */
}

.mobile-server-card, .mobile-site-card {
    background: var(--bs-card-bg, #fff);
    border: 1px solid var(--bs-border-color, rgba(0,0,0,.125));
    border-radius: 0.5rem;
    margin-bottom: 0.75rem;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    overflow: hidden;
    transition: box-shadow 0.15s ease-in-out, transform 0.15s ease-in-out;
}

@media (max-width: 768px) {
    .mobile-server-card:hover, .mobile-site-card:hover {
        box-shadow: 0 0.25rem 0.5rem rgba(0, 0, 0, 0.1);
        transform: translateY(-1px);
    }
}

.mobile-card-header {
    padding: 0.75rem;
    background-color: var(--bs-card-cap-bg, rgba(0,0,0,.03));
    border-bottom: 1px solid var(--bs-border-color, rgba(0,0,0,.125));
    display: flex;
    justify-content: space-between;
    align-items: center;
}

@media (max-width: 768px) {
    .mobile-card-header:hover {
        background-color: var(--bs-card-cap-bg, rgba(0,0,0,.05));
    }
}

.mobile-card-title {
    font-weight: 600;
    margin: 0;
    font-size: 1rem;
    line-height: 1.3;
}

.mobile-card-status {
    flex-shrink: 0;
}

.mobile-card-body {
    padding: 0.75rem;
}

.mobile-card-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--bs-border-color-translucent, rgba(0,0,0,.08));
}

.mobile-card-row:last-child {
    border-bottom: none;
    padding-bottom: 0;
}

/* 两列布局样式 */
.mobile-card-two-columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--bs-border-color-translucent, rgba(0,0,0,.08));
}

.mobile-card-two-columns:last-child {
    border-bottom: none;
    padding-bottom: 0.25rem;
}

.mobile-card-column-item {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    min-height: 2rem;
    justify-content: center;
}

.mobile-card-column-item .mobile-card-label {
    font-size: 0.7rem;
    margin-bottom: 0;
    color: var(--bs-secondary-color, #6c757d);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.02em;
}

.mobile-card-column-item .mobile-card-value {
    font-size: 0.85rem;
    font-weight: 600;
    text-align: left;
    max-width: 100%;
    word-break: break-word;
    line-height: 1.2;
}

/* 移动端单行样式优化 */
@media (max-width: 768px) {
    .mobile-card-row {
        padding: 0.5rem 0;
        min-height: 2rem;
        align-items: center;
    }

    .mobile-card-label {
        font-weight: 500;
        font-size: 0.875rem;
    }

    .mobile-card-value {
        font-weight: 600;
        font-size: 0.875rem;
        word-break: break-word;
    }
}

.mobile-card-label {
    font-weight: 500;
    color: var(--bs-secondary-color, #6c757d);
    font-size: 0.875rem;
}

.mobile-card-value {
    text-align: right;
    flex-shrink: 0;
    max-width: 60%;
}



/* 移动端进度条优化 */
@media (max-width: 768px) {
    .progress {
        height: 1rem;
        margin-top: 0.25rem;
        border-radius: 0.5rem;
    }

    .progress span {
        font-size: 0.75rem;
        line-height: 1rem;
    }
}

/* 移动端状态徽章优化 */
@media (max-width: 768px) {
    .badge {
        font-size: 0.75rem;
        padding: 0.35em 0.65em;
        border-radius: 0.375rem;
    }
}

/* 移动端历史记录条优化 */
@media (max-width: 768px) {
    .history-bar-container {
        height: 1.5rem;
        border-radius: 0.25rem;
        overflow: hidden;
    }

    .history-bar {
        min-width: 2px;
        border-radius: 0;
    }
}

/* 移动端历史记录条优化 */
.mobile-history-container {
    margin-top: 0.5rem;
}

.mobile-history-label {
    font-size: 0.75rem;
    color: var(--bs-secondary-color, #6c757d);
    margin-bottom: 0.25rem;
}



/* 移动端按钮优化 */
@media (max-width: 768px) {
    .mobile-card-body .btn-sm {
        padding: 0.5rem 0.75rem;
        font-size: 0.8rem;
        border-radius: 0.375rem;
        transition: all 0.15s ease-in-out;
    }

    .mobile-card-body .d-flex.gap-2 {
        gap: 0.5rem !important;
    }

    .mobile-card-body .btn i {
        font-size: 0.875rem;
    }

    /* 移动端触摸反馈 */
    .mobile-card-header:active {
        background-color: var(--bs-card-cap-bg, rgba(0,0,0,.08)) !important;
        transform: scale(0.98);
    }

    .mobile-card-body .btn:active {
        transform: scale(0.95);
    }

    /* 移动端容器标题优化 */
    .container h2 {
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }

    /* 移动端卡片标题层次优化 */
    .mobile-card-title {
        font-size: 1rem;
        line-height: 1.3;
        font-weight: 600;
    }
}

/* 自定义浅绿色进度条 */
.bg-light-green {
    background-color: #90ee90 !important; /* LightGreen */
}

/* Custom styles for non-disruptive alerts in admin page */
#serverAlert, #siteAlert, #telegramSettingsAlert {
    position: fixed !important; /* Use !important to override Bootstrap if necessary */
    top: 70px; /* Below navbar */
    left: 50%;
    transform: translateX(-50%);
    z-index: 1055; /* Higher than Bootstrap modals (1050) */
    padding: 0.75rem 1.25rem;
    /* margin-bottom: 1rem; /* Not needed for fixed */
    border: 1px solid transparent;
    border-radius: 0.25rem;
    min-width: 300px; /* Minimum width */
    max-width: 90%; /* Max width */
    text-align: center;
    box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.15);
    /* Ensure d-none works to hide them, !important might be needed if Bootstrap's .alert.d-none is too specific */
}

#serverAlert.d-none, #siteAlert.d-none, #telegramSettingsAlert.d-none {
    display: none !important;
}

/* Semi-transparent backgrounds for different alert types */
/* Light Theme Overrides for fixed alerts */
#serverAlert.alert-success, #siteAlert.alert-success, #telegramSettingsAlert.alert-success {
    color: #0f5132; /* Bootstrap success text color */
    background-color: rgba(209, 231, 221, 0.95) !important; /* Semi-transparent success, !important for specificity */
    border-color: rgba(190, 221, 208, 0.95) !important;
}

#serverAlert.alert-danger, #siteAlert.alert-danger, #telegramSettingsAlert.alert-danger {
    color: #842029; /* Bootstrap danger text color */
    background-color: rgba(248, 215, 218, 0.95) !important; /* Semi-transparent danger */
    border-color: rgba(245, 198, 203, 0.95) !important;
}

#serverAlert.alert-warning, #siteAlert.alert-warning, #telegramSettingsAlert.alert-warning { /* For siteAlert if it uses warning */
    color: #664d03; /* Bootstrap warning text color */
    background-color: rgba(255, 243, 205, 0.95) !important; /* Semi-transparent warning */
    border-color: rgba(255, 238, 186, 0.95) !important;
}


    [data-bs-theme="dark"] {
        body {
            background-color: #121212; /* 深色背景 */
            color: #e0e0e0; /* 浅色文字 */
        }

        .card {
            background-color: #1e1e1e; /* 卡片深色背景 */
            border: 1px solid #333;
            color: #e0e0e0; /* 卡片内文字颜色 */
        }

        .card-header {
            background-color: #2a2a2a;
            border-bottom: 1px solid #333;
            color: #f5f5f5;
        }

        .table {
            color: #e0e0e0; /* 表格文字颜色 */
        }

        .table th, .table td {
            border-color: #333; /* 表格边框颜色 */
        }

        .table-striped > tbody > tr:nth-of-type(odd) > * {
             background-color: rgba(255, 255, 255, 0.05); /* 深色模式下的条纹 */
             color: #e0e0e0;
        }
        
        .table-hover > tbody > tr:hover > * {
            background-color: rgba(255, 255, 255, 0.075); /* 深色模式下的悬停 */
            color: #f0f0f0;
        }

        .modal-content {
            background-color: rgba(30, 30, 30, 0.9); /* Semi-transparent dark grey for dark theme */
            color: #e0e0e0;
            /* backdrop-filter: blur(5px); /* Optional: adds a blur effect to content behind modal */
        }

        .modal-header {
            border-bottom-color: #333;
        }
        
        .modal-footer {
            border-top-color: #333;
        }

        .form-control {
            background-color: #2a2a2a;
            color: #e0e0e0;
            border-color: #333;
        }

        .form-control:focus {
            background-color: #2a2a2a;
            color: #e0e0e0;
            border-color: #555;
            box-shadow: 0 0 0 0.25rem rgba(100, 100, 100, 0.25);
        }
        
        .btn-outline-secondary {
             color: #adb5bd;
             border-color: #6c757d;
        }
        .btn-outline-secondary:hover {
             color: #fff;
             background-color: #6c757d;
             border-color: #6c757d;
        }

        .navbar {
            background-color: #1e1e1e !important; /* 确保覆盖 Bootstrap 默认 */
        }

        /* 暗色主题移动端卡片样式 */
        .mobile-server-card, .mobile-site-card {
            background: var(--bs-dark, #212529);
            border-color: var(--bs-border-color, #495057);
        }

        .mobile-card-header {
            background-color: rgba(255, 255, 255, 0.05);
            border-bottom-color: var(--bs-border-color, #495057);
        }

        .mobile-card-title {
            color: #ffffff !important;
        }

        .mobile-card-label {
            color: #ced4da !important;
        }

        .mobile-card-value {
            color: #ffffff !important;
        }



        .mobile-card-row {
            border-bottom-color: rgba(255, 255, 255, 0.08);
        }

        .mobile-card-two-columns {
            border-bottom-color: rgba(255, 255, 255, 0.08);
        }

        .mobile-card-column-item .mobile-card-label {
            color: #ced4da !important;
        }

        .mobile-card-column-item .mobile-card-value {
            color: #ffffff !important;
        }

        .mobile-history-label {
            color: #ced4da !important;
        }

        /* 暗色主题下的空状态和错误状态文字 */
        .mobile-card-container .text-muted {
            color: #ced4da !important;
        }

        .mobile-card-container .text-danger {
            color: #ff6b6b !important;
        }

        .mobile-card-container h6 {
            color: #ffffff !important;
        }

        .mobile-card-container small {
            color: #adb5bd !important;
        }

        /* 暗色主题下的移动端按钮优化 */
        .mobile-card-body .btn-outline-primary {
            color: #6ea8fe !important;
            border-color: #6ea8fe !important;
        }

        .mobile-card-body .btn-outline-primary:hover {
            color: #000 !important;
            background-color: #6ea8fe !important;
            border-color: #6ea8fe !important;
        }

        .mobile-card-body .btn-outline-info {
            color: #6edff6 !important;
            border-color: #6edff6 !important;
        }

        .mobile-card-body .btn-outline-info:hover {
            color: #000 !important;
            background-color: #6edff6 !important;
            border-color: #6edff6 !important;
        }

        .mobile-card-body .btn-outline-danger {
            color: #ea868f !important;
            border-color: #ea868f !important;
        }

        .mobile-card-body .btn-outline-danger:hover {
            color: #000 !important;
            background-color: #ea868f !important;
            border-color: #ea868f !important;
        }

        /* 暗色主题下的Badge徽章优化 */
        .mobile-card-header .badge.bg-success {
            background-color: #198754 !important;
            color: #ffffff !important;
        }

        .mobile-card-header .badge.bg-danger {
            background-color: #dc3545 !important;
            color: #ffffff !important;
        }

        .mobile-card-header .badge.bg-warning {
            background-color: #ffc107 !important;
            color: #000000 !important;
        }

        .mobile-card-header .badge.bg-secondary {
            background-color: #6c757d !important;
            color: #ffffff !important;
        }

        .mobile-card-header .badge.bg-primary {
            background-color: #0d6efd !important;
            color: #ffffff !important;
        }

        /* 暗色主题下的移动端容器标题优化 */
        .container h2 {
            color: #ffffff !important;
        }

        /* 暗色主题下的移动端加载状态优化 */
        .mobile-card-container .spinner-border {
            color: #6ea8fe !important;
        }

        .mobile-card-container .mt-2 {
            color: #ced4da !important;
        }

        /* 暗色主题下的导航栏按钮优化 */
        .navbar .btn-outline-light {
            color: #f8f9fa !important;
            border-color: #f8f9fa !important;
        }

        .navbar .btn-outline-light:hover {
            color: #000 !important;
            background-color: #f8f9fa !important;
            border-color: #f8f9fa !important;
        }

        .navbar .nav-link {
            color: #f8f9fa !important;
        }

        .navbar .nav-link:hover {
            color: #e9ecef !important;
        }
        .navbar-light .navbar-nav .nav-link {
             color: #ccc;
        }
        .navbar-light .navbar-nav .nav-link:hover {
             color: #fff;
        }
        .navbar-light .navbar-brand {
             color: #fff;
        }
         .footer {
            background-color: #1e1e1e !important;
            color: #cccccc; /* 修复夜间模式页脚文本颜色 */
        }
        a {
            color: #8ab4f8; /* 示例链接颜色 */
        }
        a:hover {
            color: #a9c9fc;
        }

        /* Dark Theme Overrides for fixed alerts */
        [data-bs-theme="dark"] #serverAlert.alert-success,
        [data-bs-theme="dark"] #siteAlert.alert-success,
        [data-bs-theme="dark"] #telegramSettingsAlert.alert-success {
            color: #75b798; /* Lighter green text for dark theme */
            background-color: rgba(40, 167, 69, 0.85) !important; /* Darker semi-transparent success */
            border-color: rgba(34, 139, 57, 0.85) !important;
        }

        [data-bs-theme="dark"] #serverAlert.alert-danger,
        [data-bs-theme="dark"] #siteAlert.alert-danger,
        [data-bs-theme="dark"] #telegramSettingsAlert.alert-danger {
            color: #ea868f; /* Lighter red text for dark theme */
            background-color: rgba(220, 53, 69, 0.85) !important; /* Darker semi-transparent danger */
            border-color: rgba(187, 45, 59, 0.85) !important;
        }
        
        [data-bs-theme="dark"] #serverAlert.alert-warning,
        [data-bs-theme="dark"] #siteAlert.alert-warning,
        [data-bs-theme="dark"] #telegramSettingsAlert.alert-warning {
            color: #ffd373; /* Lighter yellow text for dark theme */
            background-color: rgba(255, 193, 7, 0.85) !important; /* Darker semi-transparent warning */
            border-color: rgba(217, 164, 6, 0.85) !important;
        }
    }

/* 拖拽排序样式 */
.server-row-draggable, .site-row-draggable {
    transition: all 0.2s ease;
}
.server-row-draggable:hover, .site-row-draggable:hover {
    background-color: rgba(0, 123, 255, 0.1) !important;
}
.server-row-draggable.drag-over-top, .site-row-draggable.drag-over-top {
    border-top: 3px solid #007bff !important;
    background-color: rgba(0, 123, 255, 0.1) !important;
}
.server-row-draggable.drag-over-bottom, .site-row-draggable.drag-over-bottom {
    border-bottom: 3px solid #007bff !important;
    background-color: rgba(0, 123, 255, 0.1) !important;
}
.server-row-draggable[draggable="true"], .site-row-draggable[draggable="true"] {
    cursor: grab;
}
.server-row-draggable[draggable="true"]:active, .site-row-draggable[draggable="true"]:active {
    cursor: grabbing;
}

/* 暗色主题下的拖拽样式 */
[data-bs-theme="dark"] .server-row-draggable:hover,
[data-bs-theme="dark"] .site-row-draggable:hover {
    background-color: rgba(13, 110, 253, 0.2) !important;
}
[data-bs-theme="dark"] .server-row-draggable.drag-over-top,
[data-bs-theme="dark"] .site-row-draggable.drag-over-top {
    border-top: 3px solid #0d6efd !important;
    background-color: rgba(13, 110, 253, 0.2) !important;
}
[data-bs-theme="dark"] .server-row-draggable.drag-over-bottom,
[data-bs-theme="dark"] .site-row-draggable.drag-over-bottom {
    border-bottom: 3px solid #0d6efd !important;
    background-color: rgba(13, 110, 253, 0.2) !important;
}
`;
}

function getMainJs() {
  return `// main.js - 首页面的JavaScript逻辑

// Global variables
let vpsUpdateInterval = null;
let siteUpdateInterval = null;
let serverDataCache = {}; // Cache server data to avoid re-fetching for details
const DEFAULT_VPS_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for VPS data if backend setting fails
const DEFAULT_SITE_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for Site data

// Function to fetch VPS refresh interval and start periodic VPS data updates
async function initializeVpsDataUpdates() {
    console.log('initializeVpsDataUpdates() called');
    let vpsRefreshIntervalMs = DEFAULT_VPS_REFRESH_INTERVAL_MS;

    try {
        console.log('Fetching VPS refresh interval from API...');
        const response = await fetch('/api/admin/settings/vps-report-interval'); // This API is public for GET
        console.log('API response status:', response.status);

        if (response.ok) {
            const data = await response.json();
            console.log('API response data:', data);

            if (data && typeof data.interval === 'number' && data.interval > 0) {
                vpsRefreshIntervalMs = data.interval * 1000; // Convert seconds to milliseconds
                console.log(\`Using backend-defined VPS refresh interval: \${data.interval}s (\${vpsRefreshIntervalMs}ms)\`);
            } else {
                console.warn('Invalid VPS interval from backend, using default:', data);
            }
        } else {
            console.warn('Failed to fetch VPS refresh interval from backend, using default. Status:', response.status);
        }
    } catch (error) {
        console.error('Error fetching VPS refresh interval, using default:', error);
    }

    // Clear existing interval if any
    if (vpsUpdateInterval) {
        console.log('Clearing existing VPS update interval');
        clearInterval(vpsUpdateInterval);
    }

    // Set up new periodic updates for VPS data ONLY
    console.log('Setting up new VPS update interval with', vpsRefreshIntervalMs, 'ms');
    vpsUpdateInterval = setInterval(() => {
        console.log('VPS data refresh triggered by interval');
        loadAllServerStatuses();
    }, vpsRefreshIntervalMs);

    console.log(\`VPS data will refresh every \${vpsRefreshIntervalMs / 1000} seconds. Interval ID: \${vpsUpdateInterval}\`);
}

// Function to start periodic site status updates
function initializeSiteDataUpdates() {
    const siteRefreshIntervalMs = DEFAULT_SITE_REFRESH_INTERVAL_MS; // Using a fixed interval for sites

    // Clear existing interval if any
    if (siteUpdateInterval) {
        clearInterval(siteUpdateInterval);
    }

    // Set up new periodic updates for site statuses ONLY
    siteUpdateInterval = setInterval(() => {
        loadAllSiteStatuses();
    }, siteRefreshIntervalMs);

    console.log(\`Site status data will refresh every \${siteRefreshIntervalMs / 1000} seconds.\`);
}

// Execute after the page loads (only for main page)
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded event fired');

    // Check if we're on the main page by looking for the server table
    const serverTableBody = document.getElementById('serverTableBody');
    if (!serverTableBody) {
        // Not on the main page, only initialize theme
        console.log('Not on main page, only initializing theme');
        initializeTheme();
        return;
    }

    console.log('On main page, initializing all features');

    // Initialize theme
    initializeTheme();

    // Load initial data
    loadAllServerStatuses();
    loadAllSiteStatuses();

    // Initialize periodic updates separately
    console.log('Initializing VPS data updates...');
    initializeVpsDataUpdates();
    console.log('Initializing site data updates...');
    initializeSiteDataUpdates();

    // Add click event listener to the table body for row expansion
    serverTableBody.addEventListener('click', handleRowClick);

    // Check login status and update admin link
    updateAdminLink();
});

// --- Theme Management ---
const THEME_KEY = 'themePreference';
const LIGHT_THEME = 'light';
const DARK_THEME = 'dark';

function initializeTheme() {
    const themeToggler = document.getElementById('themeToggler');
    if (!themeToggler) return;

    const storedTheme = localStorage.getItem(THEME_KEY) || LIGHT_THEME;
    applyTheme(storedTheme);

    themeToggler.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === DARK_THEME ? LIGHT_THEME : DARK_THEME;
        applyTheme(newTheme);
        localStorage.setItem(THEME_KEY, newTheme);
    });
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    const themeTogglerIcon = document.querySelector('#themeToggler i');
    if (themeTogglerIcon) {
        if (theme === DARK_THEME) {
            themeTogglerIcon.classList.remove('bi-moon-stars-fill');
            themeTogglerIcon.classList.add('bi-sun-fill');
        } else {
            themeTogglerIcon.classList.remove('bi-sun-fill');
            themeTogglerIcon.classList.add('bi-moon-stars-fill');
        }
    }
}
// --- End Theme Management ---

// Check login status and update the admin link in the navbar
async function updateAdminLink() {
    const adminLink = document.getElementById('adminAuthLink');
    if (!adminLink) return; // Exit if link not found

    try {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            // Not logged in (no token)
            adminLink.textContent = '管理员登录';
            adminLink.href = '/login.html';
            return;
        }

        const response = await fetch('/api/auth/status', {
            headers: {
                'Authorization': \`Bearer \${token}\`
            }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                // Logged in
                adminLink.textContent = '管理后台';
                adminLink.href = '/admin.html';
            } else {
                // Invalid token or not authenticated
                adminLink.textContent = '管理员登录';
                adminLink.href = '/login.html';
                localStorage.removeItem('auth_token'); // Clean up invalid token
            }
        } else {
            // API error, assume not logged in
            adminLink.textContent = '管理员登录';
            adminLink.href = '/login.html';
        }
    } catch (error) {
        console.error('Error checking auth status for navbar link:', error);
        // Network error, assume not logged in
        adminLink.textContent = '管理员登录';
        adminLink.href = '/login.html';
    }
}


// Handle click on a server row
function handleRowClick(event) {
    const clickedRow = event.target.closest('tr.server-row');
    if (!clickedRow) return; // Not a server row

    const serverId = clickedRow.getAttribute('data-server-id');
    const detailsRow = clickedRow.nextElementSibling; // The details row is the next sibling

    if (detailsRow && detailsRow.classList.contains('server-details-row')) {
        // Toggle visibility
        detailsRow.classList.toggle('d-none');

        // If showing, populate with detailed data
        if (!detailsRow.classList.contains('d-none')) {
            populateDetailsRow(serverId, detailsRow);
        }
    }
}

// Populate the detailed row with data
function populateDetailsRow(serverId, detailsRow) {
    const serverData = serverDataCache[serverId];
    const detailsContentDiv = detailsRow.querySelector('.server-details-content');

    if (!serverData || !serverData.metrics || !detailsContentDiv) {
        detailsContentDiv.innerHTML = '<p class="text-muted">无详细数据</p>';
        return;
    }

    const metrics = serverData.metrics;

    let detailsHtml = '';

    // CPU Details
    if (metrics.cpu && metrics.cpu.load_avg) {
        detailsHtml += \`
            <div class="detail-item">
                <strong>CPU负载 (1m, 5m, 15m):</strong> \${metrics.cpu.load_avg.join(', ')}
            </div>
        \`;
    }

    // Memory Details
    if (metrics.memory) {
        detailsHtml += \`
            <div class="detail-item">
                <strong>内存:</strong>
                总计: \${formatDataSize(metrics.memory.total * 1024)}<br>
                已用: \${formatDataSize(metrics.memory.used * 1024)}<br>
                空闲: \${formatDataSize(metrics.memory.free * 1024)}
            </div>
        \`;
    }

    // Disk Details
    if (metrics.disk) {
         detailsHtml += \`
            <div class="detail-item">
                <strong>硬盘 (/):</strong>
                总计: \${metrics.disk.total.toFixed(2)} GB<br>
                已用: \${metrics.disk.used.toFixed(2)} GB<br>
                空闲: \${metrics.disk.free.toFixed(2)} GB
            </div>
        \`;
    }

    // Network Totals
    if (metrics.network) {
        detailsHtml += \`
            <div class="detail-item">
                <strong>总流量:</strong>
                上传: \${formatDataSize(metrics.network.total_upload)}<br>
                下载: \${formatDataSize(metrics.network.total_download)}
            </div>
        \`;
    }

    detailsContentDiv.innerHTML = detailsHtml || '<p class="text-muted">无详细数据</p>';
}


// Load all server statuses
async function loadAllServerStatuses() {
    console.log('loadAllServerStatuses() called at', new Date().toLocaleTimeString());
    try {
        // 1. Get server list
        const serversResponse = await fetch('/api/servers');
        if (!serversResponse.ok) {
            throw new Error('Failed to get server list');
        }
        const serversData = await serversResponse.json();
        const servers = serversData.servers || [];
        console.log('Found', servers.length, 'servers');

        const noServersAlert = document.getElementById('noServers');
        const serverTableBody = document.getElementById('serverTableBody');

        if (servers.length === 0) {
            noServersAlert.classList.remove('d-none');
            serverTableBody.innerHTML = '<tr><td colspan="11" class="text-center">No server data available. Please log in to the admin panel to add servers.</td></tr>';
            // Remove any existing detail rows if the server list becomes empty
            removeAllDetailRows();
            // 同时更新移动端卡片容器
            renderMobileServerCards([]);
            return;
        } else {
            noServersAlert.classList.add('d-none');
        }

        // 2. Fetch status for all servers in parallel
        const statusPromises = servers.map(server =>
            fetch(\`/api/status/\${server.id}\`)
                .then(res => res.ok ? res.json() : Promise.resolve({ server: server, metrics: null, error: true }))
                .catch(() => Promise.resolve({ server: server, metrics: null, error: true }))
        );

        const allStatuses = await Promise.all(statusPromises);

        // Update the serverDataCache with the latest data
        allStatuses.forEach(data => {
             serverDataCache[data.server.id] = data;
        });


        // 3. Render the table using DOM manipulation
        renderServerTable(allStatuses);

    } catch (error) {
        console.error('Error loading server statuses:', error);
        const serverTableBody = document.getElementById('serverTableBody');
        serverTableBody.innerHTML = '<tr><td colspan="11" class="text-center text-danger">Failed to load server data. Please refresh the page.</td></tr>';
        removeAllDetailRows();
        // 同时更新移动端卡片容器显示错误状态
        const mobileContainer = document.getElementById('mobileServerContainer');
        if (mobileContainer) {
            mobileContainer.innerHTML = '<div class="text-center p-3 text-danger">加载服务器数据失败，请刷新页面重试。</div>';
        }
    }
}

// Remove all existing server detail rows
function removeAllDetailRows() {
    document.querySelectorAll('.server-details-row').forEach(row => row.remove());
}


// Generate progress bar HTML
function getProgressBarHtml(percentage) {
    if (typeof percentage !== 'number' || isNaN(percentage)) return '-';
    const percent = Math.max(0, Math.min(100, percentage)); // Ensure percentage is between 0 and 100
    let bgColorClass = 'bg-light-green'; // Use custom light green for < 50%

    if (percent >= 80) {
        bgColorClass = 'bg-danger'; // Red for >= 80%
    } else if (percent >= 50) {
        bgColorClass = 'bg-warning'; // Yellow for 50% - 79%
    }

    // Use relative positioning on the container and absolute for the text, centered over the whole bar
    return \`
        <div class="progress" style="height: 25px; font-size: 0.8em; position: relative; background-color: #e9ecef;">
            <div class="progress-bar \${bgColorClass}" role="progressbar" style="width: \${percent}%;" aria-valuenow="\${percent}" aria-valuemin="0" aria-valuemax="100"></div>
            <span style="position: absolute; width: 100%; text-align: center; line-height: 25px; font-weight: bold;">
                \${percent.toFixed(1)}%
            </span>
        </div>
    \`;
}


// 移动端辅助函数
function getServerStatusBadge(status) {
    if (status === 'online') {
        return { class: 'bg-success', text: '在线' };
    } else if (status === 'offline') {
        return { class: 'bg-danger', text: '离线' };
    } else if (status === 'error') {
        return { class: 'bg-warning text-dark', text: '错误' };
    } else {
        return { class: 'bg-secondary', text: '未知' };
    }
}

function formatBytes(bytes) {
    if (typeof bytes !== 'number' || isNaN(bytes)) return '-';
    if (bytes < 1024) return \`\${bytes.toFixed(1)} B\`;
    if (bytes < 1024 * 1024) return \`\${(bytes / 1024).toFixed(1)} KB\`;
    if (bytes < 1024 * 1024 * 1024) return \`\${(bytes / (1024 * 1024)).toFixed(1)} MB\`;
    return \`\${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB\`;
}

function renderHistoryBar(container, history) {
    if (!history || history.length === 0) {
        container.innerHTML = '<small class="text-muted">暂无历史记录</small>';
        return;
    }

    let historyHtml = '';
    const now = new Date();

    for (let i = 0; i < 24; i++) {
        const slotTime = new Date(now);
        slotTime.setHours(now.getHours() - i);

        const slotStart = new Date(slotTime);
        slotStart.setMinutes(0, 0, 0);

        const slotEnd = new Date(slotTime);
        slotEnd.setMinutes(59, 59, 999);

        const slotStartTimestamp = Math.floor(slotStart.getTime() / 1000);
        const slotEndTimestamp = Math.floor(slotEnd.getTime() / 1000);

        const recordForHour = history.find(
            r => r.timestamp >= slotStartTimestamp && r.timestamp <= slotEndTimestamp
        );

        let barClass = 'history-bar-pending';
        let titleText = \`\${String(slotStart.getHours()).padStart(2, '0')}:00 - \${String((slotStart.getHours() + 1) % 24).padStart(2, '0')}:00: 无记录\`;

        if (recordForHour) {
            if (recordForHour.status === 'UP') {
                barClass = 'history-bar-up';
            } else if (['DOWN', 'TIMEOUT', 'ERROR'].includes(recordForHour.status)) {
                barClass = 'history-bar-down';
            }
            const recordDate = new Date(recordForHour.timestamp * 1000);
            titleText = \`\${recordDate.toLocaleString()}: \${recordForHour.status} (\${recordForHour.status_code || 'N/A'}), \${recordForHour.response_time_ms || '-'}ms\`;
        }

        historyHtml += \`<div class="history-bar \${barClass}" title="\${titleText}"></div>\`;
    }

    container.innerHTML = historyHtml;
}

// 移动端服务器卡片渲染函数
function renderMobileServerCards(allStatuses) {
    const mobileContainer = document.getElementById('mobileServerContainer');
    if (!mobileContainer) return;

    mobileContainer.innerHTML = '';

    if (!allStatuses || allStatuses.length === 0) {
        mobileContainer.innerHTML = \`
            <div class="text-center p-4">
                <i class="bi bi-server text-muted" style="font-size: 3rem;"></i>
                <div class="mt-3 text-muted">
                    <h6>暂无服务器数据</h6>
                    <small>请登录管理后台添加服务器</small>
                </div>
            </div>
        \`;
        return;
    }

    allStatuses.forEach(data => {
        const serverId = data.server.id;
        const serverName = data.server.name;
        const metrics = data.metrics;
        const hasError = data.error;

        const card = document.createElement('div');
        card.className = 'mobile-server-card';
        card.setAttribute('data-server-id', serverId);

        // 确定服务器状态
        let status = 'unknown';
        let lastUpdate = '从未';

        if (hasError) {
            status = 'error';
        } else if (metrics) {
            const now = new Date();
            const lastReportTime = new Date(metrics.timestamp * 1000);
            const diffMinutes = (now - lastReportTime) / (1000 * 60);

            if (diffMinutes <= 5) {
                status = 'online';
            } else {
                status = 'offline';
            }
            lastUpdate = lastReportTime.toLocaleString();
        }

        const statusInfo = getServerStatusBadge(status);

        // 卡片头部
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <h6 class="mobile-card-title">\${serverName || '未命名服务器'}</h6>
            <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
        \`;

        // 卡片主体 - 显示所有信息
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // 获取所有数据
        const cpuValue = metrics && metrics.cpu ? \`\${metrics.cpu.usage_percent.toFixed(1)}%\` : '-';
        const memoryValue = metrics && metrics.memory ? \`\${metrics.memory.usage_percent.toFixed(1)}%\` : '-';
        const diskValue = metrics && metrics.disk ? \`\${metrics.disk.usage_percent.toFixed(1)}%\` : '-';
        const uptimeValue = metrics && metrics.uptime ? formatUptime(metrics.uptime) : '-';
        const uploadSpeed = metrics && metrics.network ? formatNetworkSpeed(metrics.network.upload_speed) : '-';
        const downloadSpeed = metrics && metrics.network ? formatNetworkSpeed(metrics.network.download_speed) : '-';
        const totalUpload = metrics && metrics.network ? formatDataSize(metrics.network.total_upload) : '-';
        const totalDownload = metrics && metrics.network ? formatDataSize(metrics.network.total_download) : '-';

        // 上传速度 | 下载速度
        const speedRow = document.createElement('div');
        speedRow.className = 'mobile-card-two-columns';
        speedRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">上传速度</span>
                <span class="mobile-card-value">\${uploadSpeed}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">下载速度</span>
                <span class="mobile-card-value">\${downloadSpeed}</span>
            </div>
        \`;
        cardBody.appendChild(speedRow);

        // CPU | 内存
        const cpuMemoryRow = document.createElement('div');
        cpuMemoryRow.className = 'mobile-card-two-columns';
        cpuMemoryRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">CPU</span>
                <span class="mobile-card-value">\${cpuValue}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">内存</span>
                <span class="mobile-card-value">\${memoryValue}</span>
            </div>
        \`;
        cardBody.appendChild(cpuMemoryRow);

        // 硬盘 | 运行时长
        const diskUptimeRow = document.createElement('div');
        diskUptimeRow.className = 'mobile-card-two-columns';
        diskUptimeRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">硬盘</span>
                <span class="mobile-card-value">\${diskValue}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">运行时长</span>
                <span class="mobile-card-value">\${uptimeValue}</span>
            </div>
        \`;
        cardBody.appendChild(diskUptimeRow);

        // 总上传 | 总下载
        const totalRow = document.createElement('div');
        totalRow.className = 'mobile-card-two-columns';
        totalRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">总上传</span>
                <span class="mobile-card-value">\${totalUpload}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">总下载</span>
                <span class="mobile-card-value">\${totalDownload}</span>
            </div>
        \`;
        cardBody.appendChild(totalRow);

        // 最后更新 - 单行
        const lastUpdateRow = document.createElement('div');
        lastUpdateRow.className = 'mobile-card-row';
        lastUpdateRow.innerHTML = \`
            <span class="mobile-card-label">最后更新</span>
            <span class="mobile-card-value">\${lastUpdate}</span>
        \`;
        cardBody.appendChild(lastUpdateRow);

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });
}

// 移动端网站卡片渲染函数
function renderMobileSiteCards(sites) {
    const mobileContainer = document.getElementById('mobileSiteContainer');
    if (!mobileContainer) return;

    mobileContainer.innerHTML = '';

    if (!sites || sites.length === 0) {
        mobileContainer.innerHTML = \`
            <div class="text-center p-4">
                <i class="bi bi-globe text-muted" style="font-size: 3rem;"></i>
                <div class="mt-3 text-muted">
                    <h6>暂无监控网站数据</h6>
                    <small>请登录管理后台添加监控网站</small>
                </div>
            </div>
        \`;
        return;
    }

    sites.forEach(site => {
        const card = document.createElement('div');
        card.className = 'mobile-site-card';

        const statusInfo = getSiteStatusBadge(site.last_status);
        const lastCheckTime = site.last_checked ? new Date(site.last_checked * 1000).toLocaleString() : '从未';
        const responseTime = site.last_response_time_ms !== null ? \`\${site.last_response_time_ms} ms\` : '-';

        // 卡片头部
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <h6 class="mobile-card-title">\${site.name || '未命名网站'}</h6>
            <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
        \`;

        // 卡片主体
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // 网站信息 - 两列布局
        const statusCode = site.last_status_code || '-';

        // 状态码 | 响应时间
        const statusResponseRow = document.createElement('div');
        statusResponseRow.className = 'mobile-card-two-columns';
        statusResponseRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">状态码</span>
                <span class="mobile-card-value">\${statusCode}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">响应时间</span>
                <span class="mobile-card-value">\${responseTime}</span>
            </div>
        \`;
        cardBody.appendChild(statusResponseRow);

        // 最后检查 - 单行
        const lastCheckRow = document.createElement('div');
        lastCheckRow.className = 'mobile-card-row';
        lastCheckRow.innerHTML = \`
            <span class="mobile-card-label">最后检查</span>
            <span class="mobile-card-value">\${lastCheckTime}</span>
        \`;
        cardBody.appendChild(lastCheckRow);

        // 24小时历史记录
        if (site.history && site.history.length > 0) {
            const historyContainer = document.createElement('div');
            historyContainer.className = 'mobile-history-container';
            historyContainer.innerHTML = \`
                <div class="mobile-history-label">24小时记录</div>
                <div class="history-bar-container"></div>
            \`;
            cardBody.appendChild(historyContainer);

            // 渲染历史记录条
            const historyBarContainer = historyContainer.querySelector('.history-bar-container');
            renderHistoryBar(historyBarContainer, site.history);
        }

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });
}

// 管理页面移动端服务器卡片渲染函数
function renderMobileAdminServerCards(servers) {
    const mobileContainer = document.getElementById('mobileAdminServerContainer');
    if (!mobileContainer) return;

    mobileContainer.innerHTML = '';

    if (!servers || servers.length === 0) {
        mobileContainer.innerHTML = '<div class="text-center p-3 text-muted">暂无服务器数据</div>';
        return;
    }

    servers.forEach(server => {
        const card = document.createElement('div');
        card.className = 'mobile-server-card';
        card.setAttribute('data-server-id', server.id);

        // 卡片头部
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <h6 class="mobile-card-title">\${server.name || '未命名服务器'}</h6>
            <span class="badge bg-primary">ID: \${server.id}</span>
        \`;

        // 卡片主体
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // 基本信息 - 两列布局
        const lastUpdate = server.last_update ? new Date(server.last_update * 1000).toLocaleString() : '从未';

        // 描述 - 单行
        if (server.description) {
            const descRow = document.createElement('div');
            descRow.className = 'mobile-card-row';
            descRow.innerHTML = \`
                <span class="mobile-card-label">描述</span>
                <span class="mobile-card-value">\${server.description}</span>
            \`;
            cardBody.appendChild(descRow);
        }

        // 最后更新 - 单行
        const lastUpdateRow = document.createElement('div');
        lastUpdateRow.className = 'mobile-card-row';
        lastUpdateRow.innerHTML = \`
            <span class="mobile-card-label">最后更新</span>
            <span class="mobile-card-value">\${lastUpdate}</span>
        \`;
        cardBody.appendChild(lastUpdateRow);

        // API密钥 - 单行（部分显示）
        const apiKeyDisplay = server.api_key ? \`\${server.api_key.substring(0, 8)}...\` : '-';
        const apiKeyRow = document.createElement('div');
        apiKeyRow.className = 'mobile-card-row';
        apiKeyRow.innerHTML = \`
            <span class="mobile-card-label">API密钥</span>
            <span class="mobile-card-value">\${apiKeyDisplay}</span>
        \`;
        cardBody.appendChild(apiKeyRow);

        // 操作按钮
        const actionsRow = document.createElement('div');
        actionsRow.className = 'mobile-card-row';
        actionsRow.innerHTML = \`
            <div class="d-flex gap-2 w-100">
                <button class="btn btn-outline-primary btn-sm flex-fill" onclick="editServer('\${server.id}')">
                    <i class="bi bi-pencil"></i> 编辑
                </button>
                <button class="btn btn-outline-info btn-sm flex-fill" onclick="copyInstallScript('\${server.id}', this)">
                    <i class="bi bi-clipboard"></i> 脚本
                </button>
                <button class="btn btn-outline-danger btn-sm" onclick="deleteServer('\${server.id}')">
                    <i class="bi bi-trash"></i>
                </button>
            </div>
        \`;
        cardBody.appendChild(actionsRow);

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });
}

// 管理页面移动端网站卡片渲染函数
function renderMobileAdminSiteCards(sites) {
    const mobileContainer = document.getElementById('mobileAdminSiteContainer');
    if (!mobileContainer) return;

    mobileContainer.innerHTML = '';

    if (!sites || sites.length === 0) {
        mobileContainer.innerHTML = '<div class="text-center p-3 text-muted">暂无监控网站数据</div>';
        return;
    }

    sites.forEach(site => {
        const card = document.createElement('div');
        card.className = 'mobile-site-card';

        const statusInfo = getSiteStatusBadge(site.last_status);
        const lastCheckTime = site.last_checked ? new Date(site.last_checked * 1000).toLocaleString() : '从未';
        const responseTime = site.last_response_time_ms !== null ? \`\${site.last_response_time_ms} ms\` : '-';

        // 卡片头部
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <h6 class="mobile-card-title">\${site.name || '未命名网站'}</h6>
            <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
        \`;

        // 卡片主体
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // URL - 单行
        const urlRow = document.createElement('div');
        urlRow.className = 'mobile-card-row';
        urlRow.innerHTML = \`
            <span class="mobile-card-label">URL</span>
            <span class="mobile-card-value" style="word-break: break-all;">\${site.url}</span>
        \`;
        cardBody.appendChild(urlRow);

        // 状态码 | 响应时间
        const statusCode = site.last_status_code || '-';
        const statusResponseRow = document.createElement('div');
        statusResponseRow.className = 'mobile-card-two-columns';
        statusResponseRow.innerHTML = \`
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">状态码</span>
                <span class="mobile-card-value">\${statusCode}</span>
            </div>
            <div class="mobile-card-column-item">
                <span class="mobile-card-label">响应时间</span>
                <span class="mobile-card-value">\${responseTime}</span>
            </div>
        \`;
        cardBody.appendChild(statusResponseRow);

        // 最后检查 - 单行
        const lastCheckRow = document.createElement('div');
        lastCheckRow.className = 'mobile-card-row';
        lastCheckRow.innerHTML = \`
            <span class="mobile-card-label">最后检查</span>
            <span class="mobile-card-value">\${lastCheckTime}</span>
        \`;
        cardBody.appendChild(lastCheckRow);

        // 操作按钮
        const actionsRow = document.createElement('div');
        actionsRow.className = 'mobile-card-row';
        actionsRow.innerHTML = \`
            <div class="d-flex gap-2 w-100">
                <button class="btn btn-outline-primary btn-sm flex-fill" onclick="editSite('\${site.id}')">
                    <i class="bi bi-pencil"></i> 编辑
                </button>
                <button class="btn btn-outline-danger btn-sm" onclick="deleteSite('\${site.id}')">
                    <i class="bi bi-trash"></i> 删除
                </button>
            </div>
        \`;
        cardBody.appendChild(actionsRow);

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });
}

// Render the server table using DOM manipulation
function renderServerTable(allStatuses) {
    const tableBody = document.getElementById('serverTableBody');
    const detailsTemplate = document.getElementById('serverDetailsTemplate');

    // 1. Store IDs of currently expanded servers
    const expandedServerIds = new Set();
    // Iterate over main server rows to find their expanded detail rows
    tableBody.querySelectorAll('tr.server-row').forEach(mainRow => {
        const detailRow = mainRow.nextElementSibling;
        if (detailRow && detailRow.classList.contains('server-details-row') && !detailRow.classList.contains('d-none')) {
            const serverId = mainRow.getAttribute('data-server-id');
            if (serverId) {
                expandedServerIds.add(serverId);
            }
        }
    });

    tableBody.innerHTML = ''; // Clear existing rows

    allStatuses.forEach(data => {
        const serverId = data.server.id;
        const serverName = data.server.name;
        const metrics = data.metrics;
        const hasError = data.error;

        let statusBadge = '<span class="badge bg-secondary">未知</span>';
        let cpuHtml = '-';
        let memoryHtml = '-';
        let diskHtml = '-';
        let uploadSpeed = '-';
        let downloadSpeed = '-';
        let totalUpload = '-';
        let totalDownload = '-';
        let uptime = '-';
        let lastUpdate = '-';

        if (hasError) {
            statusBadge = '<span class="badge bg-warning text-dark">错误</span>';
        } else if (metrics) {
            const now = new Date();
            const lastReportTime = new Date(metrics.timestamp * 1000);
            const diffMinutes = (now - lastReportTime) / (1000 * 60);

            if (diffMinutes <= 5) { // Considered online within 5 minutes
                statusBadge = '<span class="badge bg-success">在线</span>';
            } else {
                statusBadge = '<span class="badge bg-danger">离线</span>';
            }

            cpuHtml = getProgressBarHtml(metrics.cpu.usage_percent);
            memoryHtml = getProgressBarHtml(metrics.memory.usage_percent);
            diskHtml = getProgressBarHtml(metrics.disk.usage_percent);
            uploadSpeed = formatNetworkSpeed(metrics.network.upload_speed);
            downloadSpeed = formatNetworkSpeed(metrics.network.download_speed);
            totalUpload = formatDataSize(metrics.network.total_upload);
            totalDownload = formatDataSize(metrics.network.total_download);
            uptime = metrics.uptime ? formatUptime(metrics.uptime) : '-';
            lastUpdate = lastReportTime.toLocaleString();
        }

        // Create the main row
        const mainRow = document.createElement('tr');
        mainRow.classList.add('server-row');
        mainRow.setAttribute('data-server-id', serverId);
        mainRow.innerHTML = \`
            <td>\${serverName}</td>
            <td>\${statusBadge}</td>
            <td>\${cpuHtml}</td>
            <td>\${memoryHtml}</td>
            <td>\${diskHtml}</td>
            <td><span style="color: #000;">\${uploadSpeed}</span></td>
            <td><span style="color: #000;">\${downloadSpeed}</span></td>
            <td><span style="color: #000;">\${totalUpload}</span></td>
            <td><span style="color: #000;">\${totalDownload}</span></td>
            <td><span style="color: #000;">\${uptime}</span></td>
            <td><span style="color: #000;">\${lastUpdate}</span></td>
        \`;

        // Clone the details row template
        const detailsRowElement = detailsTemplate.content.cloneNode(true).querySelector('tr');
        // The template has d-none by default. We will remove it if needed.
        // Set a unique attribute for easier selection if needed, though direct reference is used here.
        // detailsRowElement.setAttribute('data-detail-for', serverId); 

        tableBody.appendChild(mainRow);
        tableBody.appendChild(detailsRowElement);

        // 2. If this server was previously expanded, re-expand it and populate its details
        if (expandedServerIds.has(serverId)) {
            detailsRowElement.classList.remove('d-none');
            populateDetailsRow(serverId, detailsRowElement); // Populate content
        }
    });

    // 3. 同时渲染移动端卡片
    renderMobileServerCards(allStatuses);
}


// Format network speed
function formatNetworkSpeed(bytesPerSecond) {
    if (typeof bytesPerSecond !== 'number' || isNaN(bytesPerSecond)) return '-';
    if (bytesPerSecond < 1024) {
        return \`\${bytesPerSecond.toFixed(1)} B/s\`;
    } else if (bytesPerSecond < 1024 * 1024) {
        return \`\${(bytesPerSecond / 1024).toFixed(1)} KB/s\`;
    } else if (bytesPerSecond < 1024 * 1024 * 1024) {
        return \`\${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MB/s\`;
    } else {
        return \`\${(bytesPerSecond / (1024 * 1024 * 1024)).toFixed(1)} GB/s\`;
    }
}

// Format data size
function formatDataSize(bytes) {
    if (typeof bytes !== 'number' || isNaN(bytes)) return '-';
    if (bytes < 1024) {
        return \`\${bytes.toFixed(1)} B\`;
    } else if (bytes < 1024 * 1024) {
        return \`\${(bytes / 1024).toFixed(1)} KB\`;
    } else if (bytes < 1024 * 1024 * 1024) {
        return \`\${(bytes / (1024 * 1024)).toFixed(1)} MB\`;
    } else if (bytes < 1024 * 1024 * 1024 * 1024) {
        return \`\${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB\`;
    } else {
        return \`\${(bytes / (1024 * 1024 * 1024 * 1024)).toFixed(1)} TB\`;
    }
}

// Format uptime from seconds to a human-readable string
function formatUptime(totalSeconds) {
    if (typeof totalSeconds !== 'number' || isNaN(totalSeconds) || totalSeconds < 0) {
        return '-';
    }

    const days = Math.floor(totalSeconds / (3600 * 24));
    totalSeconds %= (3600 * 24);
    const hours = Math.floor(totalSeconds / 3600);
    totalSeconds %= 3600;
    const minutes = Math.floor(totalSeconds / 60);

    let uptimeString = '';
    if (days > 0) {
        uptimeString += \`\${days}天 \`;
    }
    if (hours > 0) {
        uptimeString += \`\${hours}小时 \`;
    }
    if (minutes > 0 || (days === 0 && hours === 0)) { // Show minutes if it's the only unit or if other units are zero
        uptimeString += \`\${minutes}分钟\`;
    }
    
    return uptimeString.trim() || '0分钟'; // Default to 0 minutes if string is empty
}


// --- Website Status Functions ---

// Load all website statuses
async function loadAllSiteStatuses() {
    try {
        const response = await fetch('/api/sites/status');
        if (!response.ok) {
            throw new Error('Failed to get website status list');
        }
        const data = await response.json();
        const sites = data.sites || [];

        const noSitesAlert = document.getElementById('noSites');
        const siteStatusTableBody = document.getElementById('siteStatusTableBody');

        if (sites.length === 0) {
            noSitesAlert.classList.remove('d-none');
            siteStatusTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No websites are being monitored.</td></tr>'; // Colspan updated
            // 同时更新移动端卡片容器
            renderMobileSiteCards([]);
            return;
        } else {
            noSitesAlert.classList.add('d-none');
        }

        renderSiteStatusTable(sites);

    } catch (error) {
        console.error('Error loading website statuses:', error);
        const siteStatusTableBody = document.getElementById('siteStatusTableBody');
        siteStatusTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Failed to load website status data. Please refresh the page.</td></tr>'; // Colspan updated
        // 同时更新移动端卡片容器显示错误状态
        const mobileContainer = document.getElementById('mobileSiteContainer');
        if (mobileContainer) {
            mobileContainer.innerHTML = '<div class="text-center p-3 text-danger">加载网站数据失败，请刷新页面重试。</div>';
        }
    }
}

// Render the website status table
async function renderSiteStatusTable(sites) {
    const tableBody = document.getElementById('siteStatusTableBody');
    tableBody.innerHTML = ''; // Clear existing rows

    for (const site of sites) {
        const row = document.createElement('tr');
        const statusInfo = getSiteStatusBadge(site.last_status);
        const lastCheckTime = site.last_checked ? new Date(site.last_checked * 1000).toLocaleString() : '从未';
        const responseTime = site.last_response_time_ms !== null ? \`\${site.last_response_time_ms} ms\` : '-';

        const historyCell = document.createElement('td');
        historyCell.innerHTML = '<div class="history-bar-container"></div>'; // Placeholder

        row.innerHTML = \`
            <td>\${site.name || '-'}</td>
            <td><span class="badge \${statusInfo.class}">\${statusInfo.text}</span></td>
            <td>\${site.last_status_code || '-'}</td>
            <td>\${responseTime}</td>
            <td>\${lastCheckTime}</td>
        \`;
        row.appendChild(historyCell);
        tableBody.appendChild(row);

        // Asynchronously fetch and render history for this site
        fetchAndRenderSiteHistory(site.id, historyCell.querySelector('.history-bar-container'));
    }

    // 同时渲染移动端卡片
    renderMobileSiteCards(sites);
}

// Fetch and render 24h history for a site
async function fetchAndRenderSiteHistory(siteId, containerElement) {
    try {
        const response = await fetch(\`/api/sites/\${siteId}/history\`);
        if (!response.ok) {
            console.warn(\`Failed to fetch history for site \${siteId}\`);
            containerElement.innerHTML = '<small class="text-muted">Error fetching</small>';
            return;
        }
        const data = await response.json();
        const fetchedHistory = data.history || []; // API now returns newest first

        let historyHtml = '';
        const now = new Date();
        
        // Iterate over the last 24 hours, i=0 is current hour's slot, i=23 is 23 hours ago's slot
        for (let i = 0; i < 24; i++) {
            const slotTime = new Date(now);
            slotTime.setHours(now.getHours() - i); // Sets the hour for the slot (e.g., if now=4:30, i=0 -> 4:xx, i=1 -> 3:xx)

            const slotStart = new Date(slotTime);
            slotStart.setMinutes(0, 0, 0); // Start of that hour, e.g., 4:00:00

            const slotEnd = new Date(slotTime);
            slotEnd.setMinutes(59, 59, 999); // End of that hour, e.g., 4:59:59

            const slotStartTimestamp = Math.floor(slotStart.getTime() / 1000);
            const slotEndTimestamp = Math.floor(slotEnd.getTime() / 1000);

            // Find the most recent record within this hour slot
            // fetchedHistory is newest first, so the first match is the most recent in the slot
            const recordForHour = fetchedHistory.find(
                r => r.timestamp >= slotStartTimestamp && r.timestamp <= slotEndTimestamp
            );

            let barClass = 'history-bar-pending';
            // Display slot time, e.g., "04:00 - 05:00"
            let titleText = \`\${String(slotStart.getHours()).padStart(2, '0')}:00 - \${String((slotStart.getHours() + 1) % 24).padStart(2, '0')}:00: No record\`;

            if (recordForHour) {
                if (recordForHour.status === 'UP') {
                    barClass = 'history-bar-up';
                } else if (['DOWN', 'TIMEOUT', 'ERROR'].includes(recordForHour.status)) {
                    barClass = 'history-bar-down';
                }
                const recordDate = new Date(recordForHour.timestamp * 1000);
                // Keep detailed title if record exists
                titleText = \`\${recordDate.toLocaleString()}: \${recordForHour.status} (\${recordForHour.status_code || 'N/A'}), \${recordForHour.response_time_ms || '-'}ms\`;
            }
            // Append HTML. With flex-direction:row-reverse, first DOM element is rightmost.
            // i=0 (current hour slot) is added first, so it will be the rightmost.
            historyHtml += \`<div class="history-bar \${barClass}" title="\${titleText}"></div>\`;
        }
        
        if (!historyHtml) {
             containerElement.innerHTML = '<small class="text-muted">No records for last 24h</small>';
        } else {
             containerElement.innerHTML = historyHtml;
        }

    } catch (error) {
        console.error(\`Error fetching/rendering history for site \${siteId}:\`, error);
        containerElement.innerHTML = '<small class="text-muted">Error rendering</small>';
    }
}


// Get website status badge class and text (copied from admin.js for reuse)
function getSiteStatusBadge(status) {
    switch (status) {
        case 'UP': return { class: 'bg-success', text: '正常' };
        case 'DOWN': return { class: 'bg-danger', text: '故障' };
        case 'TIMEOUT': return { class: 'bg-warning text-dark', text: '超时' };
        case 'ERROR': return { class: 'bg-danger', text: '错误' };
        case 'PENDING': return { class: 'bg-secondary', text: '待检测' };
        default: return { class: 'bg-secondary', text: '未知' };
    }
}
`;
}

function getLoginJs() {
  return `// login.js - 登录页面的JavaScript逻辑

// --- Theme Management (copied from main.js) ---
const THEME_KEY = 'themePreference';
const LIGHT_THEME = 'light';
const DARK_THEME = 'dark';

function initializeTheme() {
    const themeToggler = document.getElementById('themeToggler');
    if (!themeToggler) return;

    const storedTheme = localStorage.getItem(THEME_KEY) || LIGHT_THEME;
    applyTheme(storedTheme);

    themeToggler.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === DARK_THEME ? LIGHT_THEME : DARK_THEME;
        applyTheme(newTheme);
        localStorage.setItem(THEME_KEY, newTheme);
    });
}

function applyTheme(theme) {
    document.title = \`Admin Panel - Theme: \${theme.toUpperCase()}\`; // Diagnostic line
    document.documentElement.setAttribute('data-bs-theme', theme);
    const themeTogglerIcon = document.querySelector('#themeToggler i');
    if (themeTogglerIcon) {
        if (theme === DARK_THEME) {
            themeTogglerIcon.classList.remove('bi-moon-stars-fill');
            themeTogglerIcon.classList.add('bi-sun-fill');
        } else {
            themeTogglerIcon.classList.remove('bi-sun-fill');
            themeTogglerIcon.classList.add('bi-moon-stars-fill');
        }
    }
}
// --- End Theme Management ---


// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme
    initializeTheme();

    // 获取登录表单元素
    const loginForm = document.getElementById('loginForm');
    const loginAlert = document.getElementById('loginAlert');

    // 添加表单提交事件监听
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();

        // 获取用户输入
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();

        // 验证输入
        if (!username || !password) {
            showLoginError('请输入用户名和密码');
            return;
        }

        // 执行登录
        login(username, password);
    });

    // 加载默认凭据信息
    loadDefaultCredentials();

    // 检查是否已登录
    checkLoginStatus();
});

// 加载默认凭据信息（本地显示，无需API调用）
function loadDefaultCredentials() {
    const credentialsInfo = document.getElementById('defaultCredentialsInfo');
    if (credentialsInfo) {
        credentialsInfo.innerHTML = '默认账号密码: <strong>admin</strong> / <strong>monitor2025!</strong><br><small class="text-danger fw-bold">建议首次登录后修改密码</small>';
    }
}

// 检查登录状态
async function checkLoginStatus() {
    try {
        // 从localStorage获取token
        const token = localStorage.getItem('auth_token');
        if (!token) {
            return;
        }
        
        const response = await fetch('/api/auth/status', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                // 已登录，重定向到管理后台
                window.location.href = 'admin.html';
            }
        }
    } catch (error) {
        console.error('检查登录状态错误:', error);
    }
}

// 登录函数
async function login(username, password) {
    try {
        // 显示加载状态
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 登录中...';
        
        // 发送登录请求
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        // 恢复按钮状态
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;
        
        if (response.ok) {
            const data = await response.json();
            // 保存token到localStorage
            localStorage.setItem('auth_token', data.token);

            // 直接跳转到管理后台
            window.location.href = 'admin.html';
        } else {
            // 登录失败
            const data = await response.json();
            showLoginError(data.message || '用户名或密码错误');
        }
    } catch (error) {
        console.error('登录错误:', error);
        showLoginError('登录请求失败，请稍后重试');
    }
}

// 显示登录错误
function showLoginError(message) {
    const loginAlert = document.getElementById('loginAlert');
    loginAlert.textContent = message;
    loginAlert.classList.remove('d-none');
    
    // 5秒后自动隐藏错误信息
    setTimeout(() => {
        loginAlert.classList.add('d-none');
    }, 5000);
}`;
}
// Helper functions for updating server/site settings are no longer needed for frequent notifications
// as that feature is removed.

function getAdminJs() {
  return `// admin.js - 管理后台的JavaScript逻辑

// Global variables for VPS data updates
let vpsUpdateInterval = null;
const DEFAULT_VPS_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for VPS data if backend setting fails

// Function to fetch VPS refresh interval and start periodic VPS data updates
async function initializeVpsDataUpdates() {
    console.log('initializeVpsDataUpdates() called in admin page');
    let vpsRefreshIntervalMs = DEFAULT_VPS_REFRESH_INTERVAL_MS;

    try {
        console.log('Fetching VPS refresh interval from API...');
        const response = await fetch('/api/admin/settings/vps-report-interval'); // This API is public for GET
        console.log('API response status:', response.status);

        if (response.ok) {
            const data = await response.json();
            console.log('API response data:', data);

            if (data && typeof data.interval === 'number' && data.interval > 0) {
                vpsRefreshIntervalMs = data.interval * 1000; // Convert seconds to milliseconds
                console.log(\`Using backend-defined VPS refresh interval: \${data.interval}s (\${vpsRefreshIntervalMs}ms)\`);
            } else {
                console.warn('Invalid VPS interval from backend, using default:', data);
            }
        } else {
            console.warn('Failed to fetch VPS refresh interval from backend, using default. Status:', response.status);
        }
    } catch (error) {
        console.error('Error fetching VPS refresh interval, using default:', error);
    }

    // Clear existing interval if any
    if (vpsUpdateInterval) {
        console.log('Clearing existing VPS update interval');
        clearInterval(vpsUpdateInterval);
    }

    // Set up new periodic updates for VPS data ONLY
    console.log('Setting up new VPS update interval with', vpsRefreshIntervalMs, 'ms');
    vpsUpdateInterval = setInterval(() => {
        console.log('VPS data refresh triggered by interval in admin page');
        // Reload server list to get updated data
        if (typeof loadServerList === 'function') {
            loadServerList();
        }
    }, vpsRefreshIntervalMs);

    console.log(\`VPS data will refresh every \${vpsRefreshIntervalMs / 1000} seconds. Interval ID: \${vpsUpdateInterval}\`);
}

// --- Theme Management (copied from main.js) ---
const THEME_KEY = 'themePreference';
const LIGHT_THEME = 'light';
const DARK_THEME = 'dark';

function initializeTheme() {
    const themeToggler = document.getElementById('themeToggler');
    if (!themeToggler) return;

    const storedTheme = localStorage.getItem(THEME_KEY) || LIGHT_THEME;
    applyTheme(storedTheme);

    themeToggler.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === DARK_THEME ? LIGHT_THEME : DARK_THEME;
        applyTheme(newTheme);
        localStorage.setItem(THEME_KEY, newTheme);
    });
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    const themeTogglerIcon = document.querySelector('#themeToggler i');
    if (themeTogglerIcon) {
        if (theme === DARK_THEME) {
            themeTogglerIcon.classList.remove('bi-moon-stars-fill');
            themeTogglerIcon.classList.add('bi-sun-fill');
        } else {
            themeTogglerIcon.classList.remove('bi-sun-fill');
            themeTogglerIcon.classList.add('bi-moon-stars-fill');
        }
    }
}
// --- End Theme Management ---


// 全局变量
let currentServerId = null;
let currentSiteId = null; // For site deletion
let serverList = [];
let siteList = []; // For monitored sites
let hasAddedNewServer = false; // 标记是否添加了新服务器

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme
    initializeTheme();

    // 检查登录状态
    checkLoginStatus();

    // 初始化事件监听
    initEventListeners();

    // 加载服务器列表
    loadServerList();
    // 加载监控网站列表
    loadSiteList();
    // 加载Telegram设置
    loadTelegramSettings();
    // 加载全局设置 (VPS Report Interval) - will use serverAlert for notifications
    loadGlobalSettings();

    // 初始化VPS数据自动更新
    initializeVpsDataUpdates();

    // 检查是否使用默认密码
    checkDefaultPasswordUsage();
});

// 检查登录状态
async function checkLoginStatus() {
    try {
        // 从localStorage获取token
        const token = localStorage.getItem('auth_token');
        if (!token) {
            // 未登录，重定向到登录页面
            window.location.href = 'login.html';
            return;
        }

        const response = await fetch('/api/auth/status', {
            headers: {
                'Authorization': 'Bearer ' + token
            }
        });

        if (response.ok) {
            const data = await response.json();
            if (!data.authenticated) {
                // 未登录，重定向到登录页面
                window.location.href = 'login.html';
            }
        } else {
            // 请求失败，重定向到登录页面
            window.location.href = 'login.html';
        }
    } catch (error) {
        console.error('检查登录状态错误:', error);
        window.location.href = 'login.html';
    }
}

// 检查是否使用默认密码
async function checkDefaultPasswordUsage() {
    try {
        // 从localStorage获取是否显示过默认密码提醒
        const hasShownDefaultPasswordWarning = localStorage.getItem('hasShownDefaultPasswordWarning');
        console.log('hasShownDefaultPasswordWarning:', hasShownDefaultPasswordWarning);
        if (hasShownDefaultPasswordWarning === 'true') {
            return; // 已经显示过提醒，不再显示
        }

        // 检查当前用户登录状态和默认密码使用情况
        const token = localStorage.getItem('auth_token');
        console.log('检查token:', token ? '存在' : '不存在');
        if (token) {
            const statusResponse = await fetch('/api/auth/status', {
                headers: {
                    'Authorization': 'Bearer ' + token
                }
            });

            console.log('状态检查响应:', statusResponse.status);
            if (statusResponse.ok) {
                const statusData = await statusResponse.json();
                console.log('状态数据:', statusData);
                if (statusData.authenticated && statusData.user && statusData.user.usingDefaultPassword) {
                    console.log('检测到使用默认密码，显示提醒');
                    // 显示默认密码提醒，5秒自动消失
                    showAlert('warning',
                        '<i class="bi bi-exclamation-triangle-fill"></i> ' +
                        '<strong>安全提醒：</strong>您正在使用默认密码登录。' +
                        '<br>为了您的账户安全，建议尽快修改密码。' +
                        '<br><small>点击右上角的"修改密码"按钮来更改密码。</small>'
                    , 'serverAlert', 5000); // 5秒自动隐藏

                    // 标记已显示过提醒
                    localStorage.setItem('hasShownDefaultPasswordWarning', 'true');
                } else {
                    console.log('未检测到使用默认密码');
                }
            }
        }
    } catch (error) {
        console.error('检查默认密码使用情况错误:', error);
    }
}

// 初始化事件监听
function initEventListeners() {
    // 添加服务器按钮
    document.getElementById('addServerBtn').addEventListener('click', function() {
        showServerModal();
    });
    
    // 保存服务器按钮
    document.getElementById('saveServerBtn').addEventListener('click', function() {
        saveServer();
    });

    // Helper function for copying text to clipboard and providing button feedback
    function copyToClipboard(textToCopy, buttonElement) {
        navigator.clipboard.writeText(textToCopy).then(() => {
            const originalHtml = buttonElement.innerHTML;
            buttonElement.innerHTML = '<i class="bi bi-check-lg"></i>'; // Using a larger check icon
            buttonElement.classList.add('btn-success');
            buttonElement.classList.remove('btn-outline-secondary');
            
            setTimeout(() => {
                buttonElement.innerHTML = originalHtml;
                buttonElement.classList.remove('btn-success');
                buttonElement.classList.add('btn-outline-secondary');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            // Optionally, show an error message to the user
            const originalHtml = buttonElement.innerHTML;
            buttonElement.innerHTML = '<i class="bi bi-x-lg"></i>'; // Error icon
            buttonElement.classList.add('btn-danger');
            buttonElement.classList.remove('btn-outline-secondary');
            setTimeout(() => {
                buttonElement.innerHTML = originalHtml;
                buttonElement.classList.remove('btn-danger');
                buttonElement.classList.add('btn-outline-secondary');
            }, 2000);
        });
    }
    
    // 复制API密钥按钮
    document.getElementById('copyApiKeyBtn').addEventListener('click', function() {
        const apiKeyInput = document.getElementById('apiKey');
        copyToClipboard(apiKeyInput.value, this);
    });

    // 复制服务器ID按钮
    document.getElementById('copyServerIdBtn').addEventListener('click', function() {
        const serverIdInput = document.getElementById('serverIdDisplay');
        copyToClipboard(serverIdInput.value, this);
    });

    // 复制Worker地址按钮
    document.getElementById('copyWorkerUrlBtn').addEventListener('click', function() {
        const workerUrlInput = document.getElementById('workerUrlDisplay');
        copyToClipboard(workerUrlInput.value, this);
    });
    
    // 确认删除按钮
    document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
        if (currentServerId) {
            deleteServer(currentServerId);
        }
    });
    
    // 修改密码按钮
    document.getElementById('changePasswordBtn').addEventListener('click', function() {
        showPasswordModal();
    });
    
    // 保存密码按钮
    document.getElementById('savePasswordBtn').addEventListener('click', function() {
        changePassword();
    });
    
    // 退出登录按钮
    document.getElementById('logoutBtn').addEventListener('click', function() {
        logout();
    });

    // --- Site Monitoring Event Listeners ---
    document.getElementById('addSiteBtn').addEventListener('click', function() {
        showSiteModal();
    });

    document.getElementById('saveSiteBtn').addEventListener('click', function() {
        saveSite();
    });

     document.getElementById('confirmDeleteSiteBtn').addEventListener('click', function() {
        if (currentSiteId) {
            deleteSite(currentSiteId);
        }
    });

    // 保存Telegram设置按钮
    document.getElementById('saveTelegramSettingsBtn').addEventListener('click', function() {
        saveTelegramSettings();
    });

    // Global Settings Event Listener
    document.getElementById('saveVpsReportIntervalBtn').addEventListener('click', function() {
        saveVpsReportInterval();
    });

    // 服务器模态框关闭事件监听器
    const serverModal = document.getElementById('serverModal');
    if (serverModal) {
        serverModal.addEventListener('hidden.bs.modal', function() {
            // 检查是否有新添加的服务器需要刷新列表
            if (hasAddedNewServer) {
                hasAddedNewServer = false; // 重置标记
                loadServerList(); // 刷新服务器列表
            }
        });
    }

    // 初始化排序下拉菜单默认选择
    setTimeout(() => {
        // 确保DOM已完全加载
        updateServerSortDropdownSelection('custom');
        updateSiteSortDropdownSelection('custom');
    }, 100);
}

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    };
}

// --- Server Management Functions ---

// 加载服务器列表
async function loadServerList() {
    try {
        const response = await fetch('/api/admin/servers', {
            headers: getAuthHeaders()
        });

        if (!response.ok) {
            throw new Error('获取服务器列表失败');
        }

        const data = await response.json();
        serverList = data.servers || [];

        renderServerTable(serverList);
    } catch (error) {
        console.error('加载服务器列表错误:', error);
        showAlert('danger', '加载服务器列表失败，请刷新页面重试。', 'serverAlert');
    }
}

// 渲染服务器表格
function renderServerTable(servers) {
    const tableBody = document.getElementById('serverTableBody');
    tableBody.innerHTML = '';

    if (servers.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="9" class="text-center">暂无服务器数据</td>'; // Updated colspan
        tableBody.appendChild(row);
        return;
    }

    servers.forEach((server, index) => {
        const row = document.createElement('tr');
        row.setAttribute('data-server-id', server.id);
        row.classList.add('server-row-draggable');
        row.draggable = true;

        // 格式化最后更新时间
        let lastUpdateText = '从未';
        let statusBadge = '<span class="badge bg-secondary">未知</span>';

        if (server.last_report) {
            const lastUpdate = new Date(server.last_report * 1000);
            lastUpdateText = lastUpdate.toLocaleString();

            // 检查是否在线（最后报告时间在5分钟内）
            const now = new Date();
            const diffMinutes = (now - lastUpdate) / (1000 * 60);

            if (diffMinutes <= 5) {
                statusBadge = '<span class="badge bg-success">在线</span>';
            } else {
                statusBadge = '<span class="badge bg-danger">离线</span>';
            }
        }

        row.innerHTML =
            '<td>' +
                '<div class="btn-group">' +
                    '<i class="bi bi-grip-vertical text-muted me-2" style="cursor: grab;" title="拖拽排序"></i>' +
                     '<button class="btn btn-sm btn-outline-secondary move-server-btn" data-id="' + server.id + '" data-direction="up" ' + (index === 0 ? 'disabled' : '') + '>' +
                        '<i class="bi bi-arrow-up"></i>' +
                    '</button>' +
                     '<button class="btn btn-sm btn-outline-secondary move-server-btn" data-id="' + server.id + '" data-direction="down" ' + (index === servers.length - 1 ? 'disabled' : '') + '>' +
                        '<i class="bi bi-arrow-down"></i>' +
                    '</button>' +
                '</div>' +
            '</td>' +
            '<td>' + server.id + '</td>' +
            '<td>' + server.name + '</td>' +
            '<td>' + (server.description || '-') + '</td>' +
            '<td>' + statusBadge + '</td>' +
            '<td>' + lastUpdateText + '</td>' +
            '<td>' +
                '<button class="btn btn-sm btn-outline-secondary view-key-btn" data-id="' + server.id + '">' +
                    '<i class="bi bi-key"></i> 查看密钥' +
                '</button>' +
            '</td>' +
            '<td>' +
                '<button class="btn btn-sm btn-outline-info copy-vps-script-btn" data-id="' + server.id + '" data-name="' + server.name + '" title="复制VPS安装脚本">' +
                    '<i class="bi bi-clipboard-plus"></i> 复制脚本' +
                '</button>' +
            '</td>' +
            '<!-- Removed frequent notification toggle column -->' +
            '<td>' +
                '<div class="btn-group">' +
                    '<button class="btn btn-sm btn-outline-primary edit-server-btn" data-id="' + server.id + '">' +
                        '<i class="bi bi-pencil"></i>' +
                    '</button>' +
                    '<button class="btn btn-sm btn-outline-danger delete-server-btn" data-id="' + server.id + '" data-name="' + server.name + '">' +
                        '<i class="bi bi-trash"></i>' +
                    '</button>' +
                '</div>' +
            '</td>';

        tableBody.appendChild(row);
    });

    // 初始化拖拽排序
    initializeServerDragSort();
    
    // 添加事件监听
    document.querySelectorAll('.view-key-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            viewApiKey(serverId);
        });
    });
    
    document.querySelectorAll('.edit-server-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            editServer(serverId);
        });
    });
    
    document.querySelectorAll('.delete-server-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            const serverName = this.getAttribute('data-name');
            showDeleteConfirmation(serverId, serverName);
        });
    });

    document.querySelectorAll('.move-server-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            const direction = this.getAttribute('data-direction');
            moveServer(serverId, direction);
        });
    });

    document.querySelectorAll('.copy-vps-script-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const serverId = this.getAttribute('data-id');
            const serverName = this.getAttribute('data-name');
            copyVpsInstallScript(serverId, serverName, this);
        });
    });

    // Removed event listener for server-frequent-notify-toggle as it's deleted from HTML
}

// 初始化服务器拖拽排序
function initializeServerDragSort() {
    const tableBody = document.getElementById('serverTableBody');
    if (!tableBody) return;

    let draggedElement = null;
    let draggedOverElement = null;

    // 为所有可拖拽行添加事件监听
    const draggableRows = tableBody.querySelectorAll('.server-row-draggable');

    draggableRows.forEach(row => {
        row.addEventListener('dragstart', function(e) {
            draggedElement = this;
            this.style.opacity = '0.5';
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/html', this.outerHTML);
        });

        row.addEventListener('dragend', function(e) {
            this.style.opacity = '';
            draggedElement = null;
            draggedOverElement = null;

            // 移除所有拖拽样式
            draggableRows.forEach(r => {
                r.classList.remove('drag-over-top', 'drag-over-bottom');
            });
        });

        row.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';

            if (this === draggedElement) return;

            draggedOverElement = this;

            // 移除其他行的拖拽样式
            draggableRows.forEach(r => {
                if (r !== this) {
                    r.classList.remove('drag-over-top', 'drag-over-bottom');
                }
            });

            // 确定插入位置
            const rect = this.getBoundingClientRect();
            const midpoint = rect.top + rect.height / 2;

            if (e.clientY < midpoint) {
                this.classList.add('drag-over-top');
                this.classList.remove('drag-over-bottom');
            } else {
                this.classList.add('drag-over-bottom');
                this.classList.remove('drag-over-top');
            }
        });

        row.addEventListener('drop', function(e) {
            e.preventDefault();

            if (this === draggedElement) return;

            const draggedServerId = draggedElement.getAttribute('data-server-id');
            const targetServerId = this.getAttribute('data-server-id');

            // 确定插入位置
            const rect = this.getBoundingClientRect();
            const midpoint = rect.top + rect.height / 2;
            const insertBefore = e.clientY < midpoint;

            // 执行拖拽排序
            performServerDragSort(draggedServerId, targetServerId, insertBefore);
        });
    });
}

// 执行服务器拖拽排序
async function performServerDragSort(draggedServerId, targetServerId, insertBefore) {
    try {
        // 获取当前服务器列表的ID顺序
        const currentOrder = serverList.map(server => server.id);

        // 计算新的排序
        const draggedIndex = currentOrder.indexOf(draggedServerId);
        const targetIndex = currentOrder.indexOf(targetServerId);

        if (draggedIndex === -1 || targetIndex === -1) {
            throw new Error('无法找到服务器');
        }

        // 创建新的排序数组
        const newOrder = [...currentOrder];
        newOrder.splice(draggedIndex, 1); // 移除拖拽的元素

        // 计算插入位置
        let insertIndex = targetIndex;
        if (draggedIndex < targetIndex) {
            insertIndex = targetIndex - 1;
        }
        if (!insertBefore) {
            insertIndex += 1;
        }

        newOrder.splice(insertIndex, 0, draggedServerId); // 插入到新位置

        // 发送批量排序请求
        const response = await fetch('/api/admin/servers/batch-reorder', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ serverIds: newOrder })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '拖拽排序失败');
        }

        // 重新加载服务器列表
        await loadServerList();
        showAlert('success', '服务器排序已更新', 'serverAlert');

    } catch (error) {
        console.error('拖拽排序错误:', error);
        showAlert('danger', '拖拽排序失败: ' + error.message, 'serverAlert');
        // 重新加载以恢复原始状态
        loadServerList();
    }
}


// Function to copy VPS installation script
async function copyVpsInstallScript(serverId, serverName, buttonElement) {
    const originalButtonHtml = buttonElement.innerHTML;
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 生成中...';

    try {
        // 直接从本地缓存的服务器列表中获取API密钥，避免API调用
        const server = serverList.find(s => s.id === serverId);
        if (!server || !server.api_key) {
            throw new Error('未找到服务器或API密钥，请刷新页面重试');
        }

        const apiKey = server.api_key;
        const workerUrl = window.location.origin;

        // 使用GitHub上的脚本地址
        const baseScriptUrl = "https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh";
        // 生成安装命令（让脚本自动从服务器获取上报间隔）
        const scriptCommand = 'wget ' + baseScriptUrl + ' -O cf-vps-monitor.sh && chmod +x cf-vps-monitor.sh && ./cf-vps-monitor.sh -i -k ' + apiKey + ' -s ' + serverId + ' -u ' + workerUrl;

        await navigator.clipboard.writeText(scriptCommand);

        buttonElement.innerHTML = '<i class="bi bi-check-lg"></i> 已复制!';
        buttonElement.classList.remove('btn-outline-info');
        buttonElement.classList.add('btn-success');

        showAlert('success', '服务器 "' + serverName + '" 的安装脚本已复制到剪贴板。', 'serverAlert');

    } catch (error) {
        console.error('复制VPS安装脚本错误:', error);
        showAlert('danger', '复制脚本失败: ' + error.message, 'serverAlert');
        buttonElement.innerHTML = '<i class="bi bi-x-lg"></i> 复制失败';
        buttonElement.classList.remove('btn-outline-info');
        buttonElement.classList.add('btn-danger');
    } finally {
        setTimeout(() => {
            buttonElement.disabled = false;
            buttonElement.innerHTML = originalButtonHtml;
            buttonElement.classList.remove('btn-success', 'btn-danger');
            buttonElement.classList.add('btn-outline-info');
        }, 3000); // Revert button state after 3 seconds
    }
}

// 移动服务器顺序
async function moveServer(serverId, direction) {
    try {
        const response = await fetch('/api/admin/servers/' + serverId + '/reorder', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ direction })
        });

        if (!response.ok) {
             const errorData = await response.json();
             throw new Error(errorData.message || '移动服务器失败');
        }

        // 重新加载列表以反映新顺序
        await loadServerList();
        showAlert('success', '服务器已成功' + (direction === 'up' ? '上移' : '下移'));

    } catch (error) {
        console.error('移动服务器错误:', error);
        showAlert('danger', '移动服务器失败: ' + error.message, 'serverAlert');
    }
}

// 显示服务器模态框（添加模式）
function showServerModal() {
    // 重置表单和标记
    document.getElementById('serverForm').reset();
    document.getElementById('serverId').value = '';
    document.getElementById('apiKeyGroup').classList.add('d-none');
    document.getElementById('serverIdDisplayGroup').classList.add('d-none');
    document.getElementById('workerUrlDisplayGroup').classList.add('d-none');
    hasAddedNewServer = false; // 重置新服务器标记

    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = '添加服务器';

    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 编辑服务器
function editServer(serverId) {
    const server = serverList.find(s => s.id === serverId);
    if (!server) return;
    
    // 填充表单
    document.getElementById('serverId').value = server.id;
    document.getElementById('serverName').value = server.name;
    document.getElementById('serverDescription').value = server.description || '';
    document.getElementById('apiKeyGroup').classList.add('d-none');
    document.getElementById('serverIdDisplayGroup').classList.add('d-none');
    document.getElementById('workerUrlDisplayGroup').classList.add('d-none');
    
    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = '编辑服务器';
    
    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 保存服务器
async function saveServer() {
    const serverId = document.getElementById('serverId').value;
    const serverName = document.getElementById('serverName').value.trim();
    const serverDescription = document.getElementById('serverDescription').value.trim();
    // const enableFrequentNotifications = document.getElementById('serverEnableFrequentNotifications').checked; // Removed
    
    if (!serverName) {
        showAlert('danger', '服务器名称不能为空', 'serverAlert'); // Added alertId
        return;
    }
    
    try {
        let response;
        let data;
        
        if (serverId) {
            // 更新服务器
            response = await fetch('/api/admin/servers/' + serverId, {
                method: 'PUT',
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription
                    // enable_frequent_down_notifications: enableFrequentNotifications // Removed
                })
            });
        } else {
            // 添加服务器
            response = await fetch('/api/admin/servers', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription
                    // enable_frequent_down_notifications: enableFrequentNotifications // Removed
                })
            });
        }
        
        if (!response.ok) {
            throw new Error('保存服务器失败');
        }
        
        data = await response.json();

        // 如果是新添加的服务器，流畅地切换到密钥显示（不隐藏模态框）
        if (!serverId && data.server && data.server.api_key) {
            hasAddedNewServer = true; // 标记已添加新服务器

            // 直接在当前模态框中显示密钥信息，提供流畅的用户体验
            // 不隐藏模态框，而是切换内容，让用户感觉是自然的过渡
            showApiKeyInCurrentModal(data.server);
            showAlert('success', '服务器添加成功');

            // 在后台异步刷新服务器列表
            loadServerList().catch(error => {
                console.error('后台刷新服务器列表失败:', error);
            });
        } else {
            // 编辑服务器的情况，正常隐藏模态框并刷新列表
            const serverModal = bootstrap.Modal.getInstance(document.getElementById('serverModal'));
            serverModal.hide();

            await loadServerList();
            showAlert('success', serverId ? '服务器更新成功' : '服务器添加成功');
        }
    } catch (error) {
        console.error('保存服务器错误:', error);
        showAlert('danger', '保存服务器失败，请稍后重试', 'serverAlert');
    }
}

// 查看API密钥（优化版本：直接从本地缓存获取）
function viewApiKey(serverId) {
    try {
        // 直接从本地缓存的服务器列表中获取服务器信息
        const server = serverList.find(s => s.id === serverId);
        if (server && server.api_key) {
            showApiKey(server);
        } else {
            showAlert('danger', '未找到服务器信息或API密钥，请刷新页面重试', 'serverAlert');
        }
    } catch (error) {
        console.error('查看API密钥错误:', error);
        showAlert('danger', '查看API密钥失败，请稍后重试', 'serverAlert');
    }
}

// 在当前模态框中显示API密钥（用于添加服务器后的流畅过渡）
function showApiKeyInCurrentModal(server) {
    // 填充表单数据
    document.getElementById('serverId').value = server.id;
    document.getElementById('serverName').value = server.name;
    document.getElementById('serverDescription').value = server.description || '';

    // 显示API密钥、服务器ID和Worker URL
    document.getElementById('apiKey').value = server.api_key;
    document.getElementById('apiKeyGroup').classList.remove('d-none');

    document.getElementById('serverIdDisplay').value = server.id;
    document.getElementById('serverIdDisplayGroup').classList.remove('d-none');

    document.getElementById('workerUrlDisplay').value = window.location.origin;
    document.getElementById('workerUrlDisplayGroup').classList.remove('d-none');

    // 更新模态框标题
    document.getElementById('serverModalTitle').textContent = '服务器详细信息与密钥';

    // 注意：不创建新的模态框，而是在当前模态框中切换内容
    // 这样用户感觉是自然的内容过渡，而不是突然弹出新窗口
}

// 显示API密钥（用于查看密钥按钮）
function showApiKey(server) {
    // 填充表单
    document.getElementById('serverId').value = server.id; // Hidden input for form submission if needed
    document.getElementById('serverName').value = server.name;
    document.getElementById('serverDescription').value = server.description || '';

    // Populate and show API Key, Server ID, and Worker URL
    document.getElementById('apiKey').value = server.api_key;
    document.getElementById('apiKeyGroup').classList.remove('d-none');

    document.getElementById('serverIdDisplay').value = server.id;
    document.getElementById('serverIdDisplayGroup').classList.remove('d-none');

    document.getElementById('workerUrlDisplay').value = window.location.origin;
    document.getElementById('workerUrlDisplayGroup').classList.remove('d-none');

    // 设置模态框标题
    document.getElementById('serverModalTitle').textContent = '服务器详细信息与密钥';

    // 显示模态框
    const serverModal = new bootstrap.Modal(document.getElementById('serverModal'));
    serverModal.show();
}

// 显示删除确认
function showDeleteConfirmation(serverId, serverName) {
    currentServerId = serverId;
    document.getElementById('deleteServerName').textContent = serverName;
    
    const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
    deleteModal.show();
}

// 删除服务器
async function deleteServer(serverId) {
    try {
        const response = await fetch('/api/admin/servers/' + serverId, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error('删除服务器失败');
        }
        
        // 隐藏模态框
        const deleteModal = bootstrap.Modal.getInstance(document.getElementById('deleteModal'));
        deleteModal.hide();
        
        // 重新加载服务器列表
        loadServerList();
        showAlert('success', '服务器删除成功');
    } catch (error) {
        console.error('删除服务器错误:', error);
        showAlert('danger', '删除服务器失败，请稍后重试', 'serverAlert');
    }
}


// --- Site Monitoring Functions (Continued) ---

// 移动网站顺序
async function moveSite(siteId, direction) {
    try {
        const response = await fetch('/api/admin/sites/' + siteId + '/reorder', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ direction })
        });

        if (!response.ok) {
             const errorData = await response.json().catch(() => ({}));
             throw new Error(errorData.message || '移动网站失败');
        }

        // 重新加载列表以反映新顺序
        await loadSiteList();
        showAlert('success', '网站已成功' + (direction === 'up' ? '上移' : '下移'), 'siteAlert');

    } catch (error) {
        console.error('移动网站错误:', error);
        showAlert('danger', '移动网站失败: ' + error.message, 'siteAlert');
    }
}


// --- Password Management Functions ---

// 显示密码修改模态框
function showPasswordModal() {
    // 重置表单
    document.getElementById('passwordForm').reset();
    document.getElementById('passwordAlert').classList.add('d-none');
    
    const passwordModal = new bootstrap.Modal(document.getElementById('passwordModal'));
    passwordModal.show();
}

// 修改密码
async function changePassword() {
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // 验证输入
    if (!currentPassword || !newPassword || !confirmPassword) {
        showPasswordAlert('danger', '所有密码字段都必须填写');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showPasswordAlert('danger', '新密码和确认密码不匹配');
        return;
    }
    
    try {
        const response = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        if (response.ok) {
            // 隐藏模态框
            const passwordModal = bootstrap.Modal.getInstance(document.getElementById('passwordModal'));
            passwordModal.hide();

            // 清除默认密码提醒标记，这样如果用户再次使用默认密码登录会重新提醒
            localStorage.removeItem('hasShownDefaultPasswordWarning');

            showAlert('success', '密码修改成功', 'serverAlert'); // Use main alert
        } else {
            const data = await response.json();
            showPasswordAlert('danger', data.message || '密码修改失败');
        }
    } catch (error) {
        console.error('修改密码错误:', error);
        showPasswordAlert('danger', '密码修改请求失败，请稍后重试');
    }
}


// --- Auth Functions ---

// 退出登录
function logout() {
    // 清除localStorage中的token和提醒标记
    localStorage.removeItem('auth_token');
    localStorage.removeItem('hasShownDefaultPasswordWarning');

    // 重定向到登录页面
    window.location.href = 'login.html';
}


// --- Site Monitoring Functions ---

// 加载监控网站列表
async function loadSiteList() {
    try {
        const response = await fetch('/api/admin/sites', {
            headers: getAuthHeaders()
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '获取监控网站列表失败');
        }
        const data = await response.json();
        siteList = data.sites || [];
        renderSiteTable(siteList);
    } catch (error) {
        console.error('加载监控网站列表错误:', error);
        showAlert('danger', '加载监控网站列表失败: ' + error.message, 'siteAlert');
    }
}

// 渲染监控网站表格
function renderSiteTable(sites) {
    const tableBody = document.getElementById('siteTableBody');
    tableBody.innerHTML = '';

    if (sites.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="9" class="text-center">暂无监控网站</td></tr>'; // Colspan updated
        return;
    }

    sites.forEach((site, index) => { // Added index for sorting buttons
        const row = document.createElement('tr');
        row.setAttribute('data-site-id', site.id);
        row.classList.add('site-row-draggable');
        row.draggable = true;

        const statusInfo = getSiteStatusBadge(site.last_status);
        const lastCheckTime = site.last_checked ? new Date(site.last_checked * 1000).toLocaleString() : '从未';
        const responseTime = site.last_response_time_ms !== null ? \`\${site.last_response_time_ms} ms\` : '-';

        row.innerHTML = \`
             <td>
                <div class="btn-group btn-group-sm">
                    <i class="bi bi-grip-vertical text-muted me-2" style="cursor: grab;" title="拖拽排序"></i>
                     <button class="btn btn-outline-secondary move-site-btn" data-id="\${site.id}" data-direction="up" \${index === 0 ? 'disabled' : ''} title="上移">
                        <i class="bi bi-arrow-up"></i>
                    </button>
                     <button class="btn btn-outline-secondary move-site-btn" data-id="\${site.id}" data-direction="down" \${index === sites.length - 1 ? 'disabled' : ''} title="下移">
                        <i class="bi bi-arrow-down"></i>
                    </button>
                </div>
            </td>
            <td>\${site.name || '-'}</td>
            <td><a href="\${site.url}" target="_blank" rel="noopener noreferrer">\${site.url}</a></td>
            <td><span class="badge \${statusInfo.class}">\${statusInfo.text}</span></td>
            <td>\${site.last_status_code || '-'}</td>
            <td>\${responseTime}</td>
            <td>\${lastCheckTime}</td>
            <!-- Removed frequent notification toggle column -->
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-primary edit-site-btn" data-id="\${site.id}" title="编辑">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger delete-site-btn" data-id="\${site.id}" data-name="\${site.name || site.url}" data-url="\${site.url}" title="删除">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        \`;
        tableBody.appendChild(row);
    });

    // 初始化拖拽排序
    initializeSiteDragSort();

    // Add event listeners for edit and delete buttons
    document.querySelectorAll('.edit-site-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const siteId = this.getAttribute('data-id');
            editSite(siteId);
        });
    });

    document.querySelectorAll('.delete-site-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const siteId = this.getAttribute('data-id');
            const siteName = this.getAttribute('data-name');
            const siteUrl = this.getAttribute('data-url');
            showDeleteSiteConfirmation(siteId, siteName, siteUrl);
        });
    });

    // Add event listeners for move buttons
    document.querySelectorAll('.move-site-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const siteId = this.getAttribute('data-id');
            const direction = this.getAttribute('data-direction');
            moveSite(siteId, direction);
        });
    });

    // Removed event listener for site-frequent-notify-toggle as it's deleted from HTML
}

// 初始化网站拖拽排序
function initializeSiteDragSort() {
    const tableBody = document.getElementById('siteTableBody');
    if (!tableBody) return;

    let draggedElement = null;
    let draggedOverElement = null;

    // 为所有可拖拽行添加事件监听
    const draggableRows = tableBody.querySelectorAll('.site-row-draggable');

    draggableRows.forEach(row => {
        row.addEventListener('dragstart', function(e) {
            draggedElement = this;
            this.style.opacity = '0.5';
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/html', this.outerHTML);
        });

        row.addEventListener('dragend', function(e) {
            this.style.opacity = '';
            draggedElement = null;
            draggedOverElement = null;

            // 移除所有拖拽样式
            draggableRows.forEach(r => {
                r.classList.remove('drag-over-top', 'drag-over-bottom');
            });
        });

        row.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';

            if (this === draggedElement) return;

            draggedOverElement = this;

            // 移除其他行的拖拽样式
            draggableRows.forEach(r => {
                if (r !== this) {
                    r.classList.remove('drag-over-top', 'drag-over-bottom');
                }
            });

            // 确定插入位置
            const rect = this.getBoundingClientRect();
            const midpoint = rect.top + rect.height / 2;

            if (e.clientY < midpoint) {
                this.classList.add('drag-over-top');
                this.classList.remove('drag-over-bottom');
            } else {
                this.classList.add('drag-over-bottom');
                this.classList.remove('drag-over-top');
            }
        });

        row.addEventListener('drop', function(e) {
            e.preventDefault();

            if (this === draggedElement) return;

            const draggedSiteId = draggedElement.getAttribute('data-site-id');
            const targetSiteId = this.getAttribute('data-site-id');

            // 确定插入位置
            const rect = this.getBoundingClientRect();
            const midpoint = rect.top + rect.height / 2;
            const insertBefore = e.clientY < midpoint;

            // 执行拖拽排序
            performSiteDragSort(draggedSiteId, targetSiteId, insertBefore);
        });
    });
}

// 执行网站拖拽排序
async function performSiteDragSort(draggedSiteId, targetSiteId, insertBefore) {
    try {
        // 获取当前网站列表的ID顺序
        const currentOrder = siteList.map(site => site.id);

        // 计算新的排序
        const draggedIndex = currentOrder.indexOf(draggedSiteId);
        const targetIndex = currentOrder.indexOf(targetSiteId);

        if (draggedIndex === -1 || targetIndex === -1) {
            throw new Error('无法找到网站');
        }

        // 创建新的排序数组
        const newOrder = [...currentOrder];
        newOrder.splice(draggedIndex, 1); // 移除拖拽的元素

        // 计算插入位置
        let insertIndex = targetIndex;
        if (draggedIndex < targetIndex) {
            insertIndex = targetIndex - 1;
        }
        if (!insertBefore) {
            insertIndex += 1;
        }

        newOrder.splice(insertIndex, 0, draggedSiteId); // 插入到新位置

        // 发送批量排序请求
        const response = await fetch('/api/admin/sites/batch-reorder', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ siteIds: newOrder })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '拖拽排序失败');
        }

        // 重新加载网站列表
        await loadSiteList();
        showAlert('success', '网站排序已更新', 'siteAlert');

    } catch (error) {
        console.error('拖拽排序错误:', error);
        showAlert('danger', '拖拽排序失败: ' + error.message, 'siteAlert');
        // 重新加载以恢复原始状态
        loadSiteList();
    }
}

// 获取网站状态对应的Badge样式和文本
function getSiteStatusBadge(status) {
    switch (status) {
        case 'UP': return { class: 'bg-success', text: '正常' };
        case 'DOWN': return { class: 'bg-danger', text: '故障' };
        case 'TIMEOUT': return { class: 'bg-warning text-dark', text: '超时' };
        case 'ERROR': return { class: 'bg-danger', text: '错误' };
        case 'PENDING': return { class: 'bg-secondary', text: '待检测' };
        default: return { class: 'bg-secondary', text: '未知' };
    }
}


// 显示添加/编辑网站模态框 (handles both add and edit)
function showSiteModal(siteIdToEdit = null) {
    const form = document.getElementById('siteForm');
    form.reset();
    const modalTitle = document.getElementById('siteModalTitle');
    const siteIdInput = document.getElementById('siteId');

    if (siteIdToEdit) {
        const site = siteList.find(s => s.id === siteIdToEdit);
        if (site) {
            modalTitle.textContent = '编辑监控网站';
            siteIdInput.value = site.id;
            document.getElementById('siteName').value = site.name || '';
            document.getElementById('siteUrl').value = site.url;
            // document.getElementById('siteEnableFrequentNotifications').checked = site.enable_frequent_down_notifications || false; // Removed
        } else {
            showAlert('danger', '未找到要编辑的网站信息。', 'siteAlert');
            return;
        }
    } else {
        modalTitle.textContent = '添加监控网站';
        siteIdInput.value = ''; // Clear ID for add mode
        // document.getElementById('siteEnableFrequentNotifications').checked = false; // Removed
    }

    const siteModal = new bootstrap.Modal(document.getElementById('siteModal'));
    siteModal.show();
}

// Function to call when edit button is clicked
function editSite(siteId) {
    showSiteModal(siteId);
}

// 保存网站（添加或更新）
async function saveSite() {
    const siteId = document.getElementById('siteId').value; // Get ID from hidden input
    const siteName = document.getElementById('siteName').value.trim();
    const siteUrl = document.getElementById('siteUrl').value.trim();
    // const enableFrequentNotifications = document.getElementById('siteEnableFrequentNotifications').checked; // Removed

    if (!siteUrl) {
        showAlert('warning', '请输入网站URL', 'siteAlert');
        return;
    }
    if (!siteUrl.startsWith('http://') && !siteUrl.startsWith('https://')) {
         showAlert('warning', 'URL必须以 http:// 或 https:// 开头', 'siteAlert');
         return;
    }

    const requestBody = {
        url: siteUrl,
        name: siteName
        // enable_frequent_down_notifications: enableFrequentNotifications // Removed
    };
    let apiUrl = '/api/admin/sites';
    let method = 'POST';

    if (siteId) { // If siteId exists, it's an update
        apiUrl = \`/api/admin/sites/\${siteId}\`;
        method = 'PUT';
    }

    try {
        const response = await fetch(apiUrl, {
            method: method,
            headers: getAuthHeaders(),
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`\${siteId ? '更新' : '添加'}网站失败 (\${response.status})\`);
        }
        
        const responseData = await response.json();

        const siteModalInstance = bootstrap.Modal.getInstance(document.getElementById('siteModal'));
        if (siteModalInstance) {
            siteModalInstance.hide();
        }
        
        await loadSiteList(); // Reload the list
        showAlert('success', \`监控网站\${siteId ? '更新' : '添加'}成功\`, 'siteAlert');

    } catch (error) {
        console.error('保存网站错误:', error);
        showAlert('danger', \`保存网站失败: \${error.message}\`, 'siteAlert');
    }
}

// 显示删除网站确认模态框
function showDeleteSiteConfirmation(siteId, siteName, siteUrl) {
    currentSiteId = siteId;
    document.getElementById('deleteSiteName').textContent = siteName;
    document.getElementById('deleteSiteUrl').textContent = siteUrl;
    const deleteModal = new bootstrap.Modal(document.getElementById('deleteSiteModal'));
    deleteModal.show();
}


// 删除网站监控
async function deleteSite(siteId) {
    try {
        const response = await fetch(\`/api/admin/sites/\${siteId}\`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        if (!response.ok) {
             const errorData = await response.json().catch(() => ({}));
             throw new Error(errorData.message || \`删除网站失败 (\${response.status})\`);
        }

        // Hide modal and reload list
        const deleteModal = bootstrap.Modal.getInstance(document.getElementById('deleteSiteModal'));
        deleteModal.hide();
        await loadSiteList(); // Reload list
        showAlert('success', '网站监控已删除', 'siteAlert');
        currentSiteId = null; // Reset current ID

    } catch (error) {
        console.error('删除网站错误:', error);
        showAlert('danger', \`删除网站失败: \${error.message}\`, 'siteAlert');
    }
}


// --- Utility Functions ---

// 显示警告信息 (specify alert element ID)
function showAlert(type, message, alertId = 'serverAlert', autoHideDelay = 5000) {
    const alertElement = document.getElementById(alertId);
    if (!alertElement) return; // Exit if alert element doesn't exist

    alertElement.className = \`alert alert-\${type} alert-dismissible\`;

    // 添加关闭按钮和消息内容
    alertElement.innerHTML = \`
        \${message}
        <button type="button" class="btn-close" aria-label="Close" onclick="this.parentElement.classList.add('d-none')"></button>
    \`;

    alertElement.classList.remove('d-none');

    // 如果autoHideDelay大于0，则自动隐藏
    if (autoHideDelay > 0) {
        setTimeout(() => {
            alertElement.classList.add('d-none');
        }, autoHideDelay);
    }
}

// 显示密码修改警告信息 (uses its own dedicated alert element)
function showPasswordAlert(type, message) {
    const alertElement = document.getElementById('passwordAlert');
    if (!alertElement) return;
    alertElement.className = \`alert alert-\${type}\`;
    alertElement.textContent = message;
    alertElement.classList.remove('d-none');
    // Auto-hide not typically needed for modal alerts, but can be added if desired
}

// --- Telegram Settings Functions ---

// 加载Telegram通知设置
async function loadTelegramSettings() {
    try {
        const response = await fetch('/api/admin/telegram-settings', {
            headers: getAuthHeaders()
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '获取Telegram设置失败');
        }
        const settings = await response.json();
        if (settings) {
            document.getElementById('telegramBotToken').value = settings.bot_token || '';
            document.getElementById('telegramChatId').value = settings.chat_id || '';
            document.getElementById('enableTelegramNotifications').checked = !!settings.enable_notifications;
        }
    } catch (error) {
        console.error('加载Telegram设置错误:', error);
        showAlert('danger', \`加载Telegram设置失败: \${error.message}\`, 'telegramSettingsAlert');
    }
}

// 保存Telegram通知设置
async function saveTelegramSettings() {
    const botToken = document.getElementById('telegramBotToken').value.trim();
    const chatId = document.getElementById('telegramChatId').value.trim();
    let enableNotifications = document.getElementById('enableTelegramNotifications').checked;

    // If Bot Token or Chat ID is empty, automatically disable notifications
    if (!botToken || !chatId) {
        enableNotifications = false;
        document.getElementById('enableTelegramNotifications').checked = false; // Update the checkbox UI
        if (document.getElementById('enableTelegramNotifications').checked && (botToken || chatId)) { // Only show warning if user intended to enable
             showAlert('warning', 'Bot Token 和 Chat ID 均不能为空才能启用通知。通知已自动禁用。', 'telegramSettingsAlert');
        }
    } else if (enableNotifications && (!botToken || !chatId)) { // This case should ideally not be hit due to above logic, but kept for safety
        showAlert('warning', '启用通知时，Bot Token 和 Chat ID 不能为空。', 'telegramSettingsAlert');
        return;
    }


    try {
        const response = await fetch('/api/admin/telegram-settings', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                bot_token: botToken,
                chat_id: chatId,
                enable_notifications: enableNotifications // Use the potentially modified value
            })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '保存Telegram设置失败');
        }
        
        await response.json(); // Consume response body
        showAlert('success', 'Telegram设置已成功保存。', 'telegramSettingsAlert');

    } catch (error) {
        console.error('保存Telegram设置错误:', error);
    showAlert('danger', \`保存Telegram设置失败: \${error.message}\`, 'telegramSettingsAlert');
    }
}

// --- Global Settings Functions (VPS Report Interval) ---
async function loadGlobalSettings() {
    try {
        const response = await fetch('/api/admin/settings/vps-report-interval', {
            headers: getAuthHeaders()
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '获取VPS报告间隔失败');
        }
        const settings = await response.json();
        if (settings && typeof settings.interval === 'number') {
            document.getElementById('vpsReportInterval').value = settings.interval;
        } else {
            document.getElementById('vpsReportInterval').value = 60; // Default if not set
        }
    } catch (error) {
        console.error('加载VPS报告间隔错误:', error);
        showAlert('danger', \`加载VPS报告间隔失败: \${error.message}\`, 'serverAlert'); // Changed to serverAlert
        document.getElementById('vpsReportInterval').value = 60; // Default on error
    }
}

async function saveVpsReportInterval() {
    const intervalInput = document.getElementById('vpsReportInterval');
    const interval = parseInt(intervalInput.value, 10);

    if (isNaN(interval) || interval < 1) { // Changed to interval < 1
        showAlert('warning', 'VPS报告间隔必须是一个大于或等于1的数字。', 'serverAlert'); // Changed to serverAlert and message
        return;
    }
    // Removed warning for interval < 10

    try {
        const response = await fetch('/api/admin/settings/vps-report-interval', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ interval: interval })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '保存VPS报告间隔失败');
        }
        
        await response.json(); // Consume response body
        showAlert('success', 'VPS数据更新频率已成功保存。前端刷新间隔已立即更新。', 'serverAlert'); // Changed to serverAlert

        // Immediately update the frontend refresh interval
        // Check if we're on a page that has VPS data updates running
        if (typeof initializeVpsDataUpdates === 'function') {
            try {
                await initializeVpsDataUpdates();
                console.log('VPS data refresh interval updated immediately');
            } catch (error) {
                console.error('Error updating VPS refresh interval:', error);
            }
        }
    } catch (error) {
        console.error('保存VPS报告间隔错误:', error);
        showAlert('danger', \`保存VPS报告间隔失败: \${error.message}\`, 'serverAlert'); // Changed to serverAlert
    }
}

// --- 自动排序功能 ---

// 服务器自动排序
async function autoSortServers(sortBy) {
    try {
        const response = await fetch('/api/admin/servers/auto-sort', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ sortBy: sortBy, order: 'asc' })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '自动排序失败');
        }

        // 更新下拉菜单选中状态
        updateServerSortDropdownSelection(sortBy);

        // 重新加载服务器列表
        await loadServerList();
        showAlert('success', \`服务器已按\${getSortDisplayName(sortBy)}排序\`, 'serverAlert');

    } catch (error) {
        console.error('服务器自动排序错误:', error);
        showAlert('danger', '服务器自动排序失败: ' + error.message, 'serverAlert');
    }
}

// 网站自动排序
async function autoSortSites(sortBy) {
    try {
        const response = await fetch('/api/admin/sites/auto-sort', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ sortBy: sortBy, order: 'asc' })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || '自动排序失败');
        }

        // 更新下拉菜单选中状态
        updateSiteSortDropdownSelection(sortBy);

        // 重新加载网站列表
        await loadSiteList();
        showAlert('success', \`网站已按\${getSortDisplayName(sortBy)}排序\`, 'siteAlert');

    } catch (error) {
        console.error('网站自动排序错误:', error);
        showAlert('danger', '网站自动排序失败: ' + error.message, 'siteAlert');
    }
}

// 获取排序字段的显示名称
function getSortDisplayName(sortBy) {
    const displayNames = {
        'custom': '自定义',
        'name': '名称',
        'status': '状态',
        'created_at': '创建时间',
        'added_at': '添加时间',
        'url': 'URL'
    };
    return displayNames[sortBy] || sortBy;
}

// 更新服务器排序下拉菜单选中状态
function updateServerSortDropdownSelection(selectedSortBy) {
    const dropdown = document.querySelector('#serverAutoSortDropdown + .dropdown-menu');
    if (!dropdown) return;

    // 移除所有active类
    dropdown.querySelectorAll('.dropdown-item').forEach(item => {
        item.classList.remove('active');
    });

    // 为选中的项添加active类
    const selectedItem = dropdown.querySelector(\`[onclick="autoSortServers('\${selectedSortBy}')"]\`);
    if (selectedItem) {
        selectedItem.classList.add('active');
    }
}

// 更新网站排序下拉菜单选中状态
function updateSiteSortDropdownSelection(selectedSortBy) {
    const dropdown = document.querySelector('#siteAutoSortDropdown + .dropdown-menu');
    if (!dropdown) return;

    // 移除所有active类
    dropdown.querySelectorAll('.dropdown-item').forEach(item => {
        item.classList.remove('active');
    });

    // 为选中的项添加active类
    const selectedItem = dropdown.querySelector(\`[onclick="autoSortSites('\${selectedSortBy}')"]\`);
    if (selectedItem) {
        selectedItem.classList.add('active');
    }
}
`;
}
