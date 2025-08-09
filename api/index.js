// VPS监控面板 - Cloudflare Worker解决方案
// 版本: 1.1.0
// ==================== 配置常量 ====================

// 默认管理员账户配置
const DEFAULT_ADMIN_CONFIG = {
  USERNAME: 'admin',
  PASSWORD: 'monitor2025!',
};

// 安全配置 - 增强验证
function getSecurityConfig(env) {
  // 验证关键安全配置
  if (!env.JWT_SECRET || env.JWT_SECRET === 'default-jwt-secret-please-set-in-worker-variables') {
    throw new Error('JWT_SECRET must be set in environment variables for security');
  }

  return {
    JWT_SECRET: env.JWT_SECRET,
    TOKEN_EXPIRY: 2 * 60 * 60 * 1000, // 2小时
    MAX_LOGIN_ATTEMPTS: 5,
    LOGIN_ATTEMPT_WINDOW: 15 * 60 * 1000, // 15分钟
    API_RATE_LIMIT: 60, // 每分钟60次
    MIN_PASSWORD_LENGTH: 8,
    ALLOWED_ORIGINS: env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : [],
  };
}

// ==================== 全局存储 ====================

const rateLimitStore = new Map();
const loginAttemptStore = new Map();

// VPS数据批量处理器
class VpsBatchProcessor {
  constructor() {
    this.batchBuffer = [];
    this.lastBatch = Math.floor(Date.now() / 1000);
    this.maxBatchSize = 100; // 最大批量大小
  }

  // 添加VPS上报数据到批量缓冲区
  addReport(serverId, reportData, batchInterval) {
    this.batchBuffer.push({
      serverId,
      timestamp: reportData.timestamp,
      cpu: JSON.stringify(reportData.cpu),
      memory: JSON.stringify(reportData.memory),
      disk: JSON.stringify(reportData.disk),
      network: JSON.stringify(reportData.network),
      uptime: reportData.uptime
    });

    // 检查是否需要立即刷新（时间到或缓冲区满）
    const now = Math.floor(Date.now() / 1000);
    if (now - this.lastBatch >= batchInterval || this.batchBuffer.length >= this.maxBatchSize) {
      return true; // 需要刷新
    }
    return false;
  }

  // 获取并清空批量数据
  getBatchData() {
    const data = [...this.batchBuffer];
    this.batchBuffer = [];
    this.lastBatch = Math.floor(Date.now() / 1000);
    return data;
  }

  // 检查是否需要定时刷新
  shouldFlush(batchInterval) {
    const now = Math.floor(Date.now() / 1000);
    return this.batchBuffer.length > 0 && (now - this.lastBatch >= batchInterval);
  }
}

// 全局批量处理器实例
const vpsBatchProcessor = new VpsBatchProcessor();

// 批量写入VPS数据到数据库
async function flushVpsBatchData(env) {
  const batchData = vpsBatchProcessor.getBatchData();
  if (batchData.length === 0) return;

  try {
    // 使用D1的batch操作进行批量写入
    const statements = [];
    
    batchData.forEach(report => {
      // 判断服务器状态（基于上报时间）
      const now = Math.floor(Date.now() / 1000);
      const diffMinutes = (now - report.timestamp) / 60;
      const status = diffMinutes <= 5 ? 'online' : 'offline';
      
      // 更新最新状态到metrics表（保持兼容性）
      statements.push(
        env.DB.prepare(`
          REPLACE INTO metrics (server_id, timestamp, cpu, memory, disk, network, uptime)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          report.serverId,
          report.timestamp,
          report.cpu,
          report.memory,
          report.disk,
          report.network,
          report.uptime
        )
      );
      
      // 同时写入历史记录表
      statements.push(
        env.DB.prepare(`
          INSERT INTO vps_status_history (server_id, timestamp, status, cpu, memory, disk, network, uptime)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          report.serverId,
          report.timestamp,
          status,
          report.cpu,
          report.memory,
          report.disk,
          report.network,
          report.uptime
        )
      );
    });

    await env.DB.batch(statements);
    console.log(`批量写入${batchData.length}条VPS数据（包含历史记录）`);
  } catch (error) {
    console.error('批量写入VPS数据失败:', error);
    // 如果批量写入失败，将数据重新加入缓冲区
    vpsBatchProcessor.batchBuffer.unshift(...batchData);
    throw error;
  }
}

// 定时刷新VPS批量数据（在主请求处理中调用）
async function scheduleVpsBatchFlush(env, ctx) {
  try {
    const batchInterval = await getVpsReportInterval(env);
    if (vpsBatchProcessor.shouldFlush(batchInterval)) {
      ctx.waitUntil(flushVpsBatchData(env));
    }
  } catch (error) {
    // 使用默认间隔60秒
    if (vpsBatchProcessor.shouldFlush(60)) {
      ctx.waitUntil(flushVpsBatchData(env));
    }
  }
}

// ==================== 实时数据缓存系统 ====================

// 服务器最新数据缓存 - 直接存储agent上报的最新数据
const realtimeDataCache = new Map();
const REALTIME_CACHE_TTL = 5 * 60 * 1000; // 5分钟过期

// 存储agent上报的实时数据
function storeRealtimeData(serverId, metrics) {
  realtimeDataCache.set(serverId, {
    metrics: metrics,
    timestamp: Date.now(),
    lastUpdate: new Date().toISOString()
  });
}

// 获取实时数据
function getRealtimeData(serverId) {
  const cached = realtimeDataCache.get(serverId);
  if (!cached) return null;
  
  // 检查是否过期
  if (Date.now() - cached.timestamp > REALTIME_CACHE_TTL) {
    realtimeDataCache.delete(serverId);
    return null;
  }
  
  return cached;
}

// 清理过期的实时数据缓存
function cleanupRealtimeCache() {
  const now = Date.now();
  for (const [serverId, data] of realtimeDataCache.entries()) {
    if (now - data.timestamp > REALTIME_CACHE_TTL) {
      realtimeDataCache.delete(serverId);
    }
  }
}

// ==================== 配置缓存系统 ====================

class ConfigCache {
  constructor() {
    this.cache = new Map();
    this.CACHE_TTL = {
      TELEGRAM: 5 * 60 * 1000,    // 5分钟
      MONITORING: 5 * 60 * 1000,  // 5分钟
      SERVERS: 2 * 60 * 1000      // 2分钟
    };
  }

  set(key, value, ttl) {
    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      ttl
    });
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.value;
  }

  async getTelegramConfig(db) {
    const cached = this.get('telegram_config');
    if (cached) return cached;

    const config = await db.prepare(
      'SELECT bot_token, chat_id, enable_notifications FROM telegram_config WHERE id = 1'
    ).first();

    if (config) {
      this.set('telegram_config', config, this.CACHE_TTL.TELEGRAM);
    }

    return config;
  }

  async getMonitoringSettings(db) {
    const cached = this.get('monitoring_settings');
    if (cached) return cached;

    const settings = await db.prepare(
      'SELECT * FROM app_config WHERE key IN ("vps_report_interval", "site_check_interval")'
    ).all();

    if (settings?.results) {
      this.set('monitoring_settings', settings.results, this.CACHE_TTL.MONITORING);
      return settings.results;
    }

    return [];
  }

  async getServerList(db, isAdmin = false) {
    const cacheKey = isAdmin ? 'servers_admin' : 'servers_public';
    const cached = this.get(cacheKey);
    if (cached) return cached;

    let query = 'SELECT id, name, description,realtime_endpoint FROM servers';
    if (!isAdmin) {
      query += ' WHERE is_public = 1';
    }
    query += ' ORDER BY sort_order ASC NULLS LAST, name ASC';

    const { results } = await db.prepare(query).all();
    const servers = results || [];

    this.set(cacheKey, servers, this.CACHE_TTL.SERVERS);
    return servers;
  }

  clear() {
    this.cache.clear();
  }

  clearKey(key) {
    this.cache.delete(key);
  }
}

// 全局配置缓存实例
const configCache = new ConfigCache();

 

// ==================== 工具函数 ====================

// 计算VPS服务器在线率
async function calculateVpsUptime(env, serverId, hours = 24) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const startTime = now - (hours * 60 * 60);
    
    // 获取服务器的创建时间
    const serverInfo = await env.DB.prepare(
      'SELECT created_at FROM servers WHERE id = ?'
    ).bind(serverId).first();
    
    // 获取指定时间范围内的历史数据
    const { results } = await env.DB.prepare(`
      SELECT timestamp, status
      FROM vps_status_history
      WHERE server_id = ? AND timestamp >= ?
      ORDER BY timestamp ASC
    `).bind(serverId, startTime).all();
    
    // 计算实际的总时间（考虑服务器创建时间）
    const serverCreatedAt = serverInfo?.created_at ? Math.floor(new Date(serverInfo.created_at).getTime() / 1000) : startTime;
    const actualStartTime = Math.max(serverCreatedAt, startTime);
    if (!results || results.length === 0) { 
      return { 
        uptime: 0, 
        totalTime: 0,  
        onlineTime: 0 
      };
    }
    
    let onlineTime = 0;
    let lastTimestamp = actualStartTime;
    let lastStatus = '';
     
    for (const record of results) {
      // 如果上个状态是online，累计时间
      if (record.status === 'online') {
        onlineTime += record.timestamp - lastTimestamp;
      }
      lastTimestamp = record.timestamp;
      lastStatus = record.status;
    }
    
    const actualTotalTime = Math.max(0, lastTimestamp - actualStartTime);
    // 处理最后一个状态到现在的时间
    //if (lastStatus === 'online') {
    //  onlineTime += now - lastTimestamp;
    //}
    
    
    let uptimePercentage = 100;
    if(onlineTime===actualTotalTime) {
		uptimePercentage=100;
	}
	else {
	    uptimePercentage= actualTotalTime > 0 ? Math.min(100, (onlineTime / actualTotalTime) * 100) : 0;
		uptimePercentage= Math.round(uptimePercentage * 100) / 100;
	}
    return {
      uptime: uptimePercentage, // 保留两位小数
      totalTime: Math.round(actualTotalTime / 60), // 转换为分钟
      onlineTime: Math.round(onlineTime / 60) // 转换为分钟
    };
  } catch (error) {
    console.error('计算VPS在线率失败:', error);
    return { uptime: 0, totalTime: 0, onlineTime: 0 };
  }
}

// 格式化时间duration（秒）为可读格式
function formatDuration(seconds) {
  if (seconds < 60) {
    return `${seconds}秒`;
  } else if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return remainingSeconds > 0 
      ? `${minutes}分${remainingSeconds}秒` 
      : `${minutes}分钟`;
  } else if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const remainingMinutes = Math.floor((seconds % 3600) / 60);
    return remainingMinutes > 0 
      ? `${hours}小时${remainingMinutes}分钟` 
      : `${hours}小时`;
  } else {
    const days = Math.floor(seconds / 86400);
    const remainingHours = Math.floor((seconds % 86400) / 3600);
    return remainingHours > 0 
      ? `${days}天${remainingHours}小时` 
      : `${days}天`;
  }
}

// 计算网站在线率
async function calculateSiteUptime(env, siteId, hours = 24) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const startTime = now - (hours * 60 * 60);
    
    // 获取网站的创建时间
    const siteInfo = await env.DB.prepare(
      'SELECT added_at FROM monitored_sites WHERE id = ?'
    ).bind(siteId).first();
    
    // 获取指定时间范围内的历史数据
    const { results } = await env.DB.prepare(`
      SELECT timestamp, status
      FROM site_status_history
      WHERE site_id = ? AND timestamp >= ?
      ORDER BY timestamp ASC
    `).bind(siteId, startTime).all();
    
    if (!results || results.length === 0) {
      // 计算网站实际监控时间
      const siteCreatedAt = siteInfo?.added_at ? Math.floor(new Date(siteInfo.added_at).getTime() / 1000) : startTime;
      const actualStartTime = Math.max(siteCreatedAt, startTime);
      const actualTotalTime = Math.max(0, now - actualStartTime);
      
      // 如果没有历史数据，检查网站当前状态
      try {
        const currentSiteStatus = await env.DB.prepare(
          'SELECT last_status FROM monitored_sites WHERE id = ?'
        ).bind(siteId).first();
        
        // 如果网站当前状态是在线且有监控时间，则认为整个时间段都在线
        if (currentSiteStatus?.last_status === 'UP' && actualTotalTime > 0) {
          return {
            uptime: 100.0,
            totalTime: Math.round(actualTotalTime / 60),
            onlineTime: Math.round(actualTotalTime / 60),
			
			startTime: siteInfo?.added_at
          };
        }
      } catch (statusError) {
        console.error('获取网站当前状态失败:', statusError);
      }
      
      return { 
        uptime: 0, 
        totalTime: Math.round(actualTotalTime / 60), // 转换为分钟
        onlineTime: 0 ,
		startTime: siteInfo?.added_at
      };
    }
    
    let onlineTime = 0;
    let onlineCount = 0;
    let checkCount = 0;
    let lastTimestamp = startTime;
    let lastStatus = 'UP';
    
    // 如果有网站创建时间，且创建时间晚于查询开始时间，则从创建时间开始计算
    if (siteInfo?.added_at) {
      const siteCreatedAt = Math.floor(new Date(siteInfo.added_at).getTime() / 1000);
      if (siteCreatedAt > startTime) {
        lastTimestamp = siteCreatedAt;
      }
    }
    
    for (const record of results) {
      // 如果上个状态是online，累计时间
      if (lastStatus === 'UP') {
	    onlineCount +=1;
        onlineTime += record.timestamp - lastTimestamp;
      }
	  checkCount +=1;
      lastTimestamp = record.timestamp;
      lastStatus = record.status;
    }
    
    // 处理最后一个状态到现在的时间
    if (lastStatus === 'UP') {
      onlineTime += now - lastTimestamp;
	  onlineCount +=1;
	  checkCount +=1;
    }
    
    // 计算实际的总时间（考虑网站创建时间）
    const siteCreatedAt = siteInfo?.added_at ? Math.floor(new Date(siteInfo.added_at).getTime() / 1000) : startTime;
    const actualStartTime = Math.max(siteCreatedAt, startTime);
    const actualTotalTime = Math.max(0, now - actualStartTime);
    
    const uptimePercentage = checkCount > 0 ? Math.min(100, (onlineCount / checkCount) * 100) : 0;
    if (onlineCount===checkCount) {
		return {
		  uptime: 100, // 保留两位小数
		  totalTime: Math.round(actualTotalTime / 60), // 转换为分钟
		  onlineTime: Math.round(onlineTime / 60), // 转换为分钟
		  me: 2
		};
	}
    return {
      uptime: Math.round(uptimePercentage * 100) / 100, // 保留两位小数
      totalTime: Math.round(actualTotalTime / 60), // 转换为分钟
      onlineTime: Math.round(onlineTime / 60), // 转换为分钟
	  me: 3
    };
  } catch (error) {
    console.error('计算网站在线率失败:', error);
    return { uptime: 0, totalTime: 0, onlineTime: 0 };
  }
}

// SQL安全验证 - 防止注入攻击
function validateSqlIdentifier(value, type) {
  const whitelist = {
    column: ['id', 'name', 'url', 'description', 'sort_order', 'is_public', 'last_checked', 'last_status', 'timestamp', 'cpu', 'memory', 'disk', 'network', 'uptime'],
    table: ['servers', 'monitored_sites', 'metrics', 'site_status_history', 'vps_status_history'],
    order: ['ASC', 'DESC']
  };

  const allowed = whitelist[type];
  if (!allowed || !allowed.includes(value)) {
    throw new Error(`Invalid ${type}: ${value}`);
  }
  return value;
}

// 敏感信息脱敏
function maskSensitive(value, type = 'key') {
  if (!value || typeof value !== 'string') return value;
  return type === 'key' && value.length > 8 ? value.substring(0, 8) + '***' : '***';
}

// 增强的令牌撤销机制 - 修复JWT缓存安全问题
const revokedTokens = new Map(); // 改为Map存储撤销时间

function revokeToken(token) {
  revokedTokens.set(token, Date.now());
  // 清理JWT缓存中的对应令牌
  jwtCache.delete(token);

  // 定期清理过期的撤销记录（24小时后清理）
  if (Math.random() < 0.01) {
    const expireTime = Date.now() - 24 * 60 * 60 * 1000;
    for (const [revokedToken, revokeTime] of revokedTokens.entries()) {
      if (revokeTime < expireTime) {
        revokedTokens.delete(revokedToken);
      }
    }
  }
}

function isTokenRevoked(token) {
  return revokedTokens.has(token);
}

// 安全的JSON解析 - 限制大小
async function parseJsonSafely(request, maxSize = 1024 * 1024) {
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength) > maxSize) {
    throw new Error('Request body too large');
  }

  const text = await request.text();
  if (text.length > maxSize) {
    throw new Error('Request body too large');
  }

  return JSON.parse(text);
}

// 增强的管理员认证 - 修复权限检查问题
async function authenticateAdmin(request, env) {
  const user = await authenticateRequest(request, env);
  if (!user) return null;

  // 验证用户确实存在于管理员表中且未被锁定
  const adminUser = await env.DB.prepare(
    'SELECT username, locked_until FROM admin_credentials WHERE username = ?'
  ).bind(user.username).first();

  if (!adminUser || (adminUser.locked_until && Date.now() < adminUser.locked_until)) {
    return null;
  }

  return user;
}

// 严格的管理员权限检查装饰器
function requireAdmin(handler) {
  return async (request, env, corsHeaders, ...args) => {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }
    return handler(request, env, corsHeaders, user, ...args);
  };
}

// 路径参数验证
function extractPathSegment(path, index) {
  const segments = path.split('/');

  // 支持负数索引（从末尾开始）
  if (index < 0) {
    index = segments.length + index;
  }

  if (index < 0 || index >= segments.length) return null;

  const segment = segments[index];
  return segment && /^[a-zA-Z0-9_-]{1,50}$/.test(segment) ? segment : null;
}

// 生成随机ID
function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// 生成安全的API密钥
function generateSecureApiKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 提取服务器ID的便捷函数
function extractAndValidateServerId(path) {
  return extractPathSegment(path, -1);
}

// 增强的输入验证 - 修复SSRF漏洞
function validateInput(input, type, maxLength = 255) {
  if (!input || typeof input !== 'string' || input.length > maxLength) {
    return false;
  }

  const cleaned = input.trim();

  const validators = {
    serverName: () => {
      if (!/^[\w\s\u4e00-\u9fa5.-]{2,50}$/.test(cleaned)) return false;
      const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'SCRIPT', 'UNION', 'OR', 'AND'];
      return !sqlKeywords.some(keyword => cleaned.toUpperCase().includes(keyword));
    },
    description: () => {
      if (cleaned.length > 500) return false;
      return !/<[^>]*>|javascript:|on\w+\s*=|<script/i.test(cleaned);
    },
    direction: () => ['up', 'down'].includes(input),
    url: () => {
      try {
        const url = new URL(input);
        if (!['http:', 'https:'].includes(url.protocol)) return false;

        // 增强的内网地址检查 - 修复SSRF
        const hostname = url.hostname.toLowerCase();

        // IPv4内网检查
        if (hostname === 'localhost' || hostname === '0.0.0.0' ||
            hostname.startsWith('127.') || hostname.startsWith('10.') ||
            hostname.startsWith('192.168.') || hostname.startsWith('169.254.') ||
            (hostname.startsWith('172.') &&
             parseInt(hostname.split('.')[1]) >= 16 &&
             parseInt(hostname.split('.')[1]) <= 31)) {
          return false;
        }

        // IPv6内网检查 - 修复方括号处理
        if (hostname.includes(':')) {
          // 移除方括号（如果存在）
          const cleanHostname = hostname.replace(/^\[|\]$/g, '');
          if (cleanHostname === '::1' || cleanHostname.startsWith('fc') ||
              cleanHostname.startsWith('fd') || cleanHostname.startsWith('fe80')) {
            return false;
          }
        }

        // 域名黑名单检查
        const blockedDomains = ['internal', 'local', 'intranet', 'corp'];
        if (blockedDomains.some(domain => hostname.includes(domain))) {
          return false;
        }

        // 端口限制 - 只允许标准HTTP/HTTPS端口
        const port = url.port;
        if (port && !['80', '443', '8080', '8443'].includes(port)) {
          return false;
        }

        return input.length <= 2048;
      } catch {
        return false;
      }
    }
  };

  return validators[type] ? validators[type]() : cleaned.length > 0;
}

// ==================== 统一响应处理工具 ====================

// 创建标准API响应
function createApiResponse(data, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 创建错误响应
function createErrorResponse(error, message, status = 500, corsHeaders = {}, details = null) {
  const errorData = {
    error,
    message,
    timestamp: Date.now()
  };
  if (details) errorData.details = details;

  return createApiResponse(errorData, status, corsHeaders);
}

// 创建成功响应
function createSuccessResponse(data, corsHeaders = {}) {
  return createApiResponse({ success: true, ...data }, 200, corsHeaders);
}

// ==================== 统一验证工具 ====================

// 获取Telegram配置（已移至ConfigCache类）

// 服务器认证验证
async function validateServerAuth(path, request, env) {
  const serverId = extractAndValidateServerId(path);
  if (!serverId) {
    return { error: 'Invalid server ID', message: '无效的服务器ID格式' };
  }

  const apiKey = request.headers.get('X-API-Key');
  if (!apiKey) {
    return { error: 'API key required', message: '需要API密钥' };
  }

  try {
    const serverData = await env.DB.prepare(
      'SELECT id, name, api_key FROM servers WHERE id = ?'
    ).bind(serverId).first();

    if (!serverData || serverData.api_key !== apiKey) {
      return { error: 'Invalid credentials', message: '无效的服务器ID或API密钥' };
    }

    return { success: true, serverId, serverData };
  } catch (error) {
    return { error: 'Database error', message: '数据库查询失败' };
  }
}

// ==================== 统一数据库错误处理 ====================

function handleDbError(error, corsHeaders, operation = 'database operation') {
  console.error(`数据库错误在 \${operation}:`, error);
  
  if (error.message.includes('no such table')) {
    return createErrorResponse(
      'Database table missing',
      `数据库表不存在，请联系管理员初始化系统。操作: ${operation}`,
      503,
      corsHeaders
    );
  }

  if (error.message.includes('SQLITE_BUSY') || error.message.includes('database is locked')) {
    return createErrorResponse(
      'Database busy',
      '数据库忙碌，请稍后重试',
      503,
      corsHeaders
    );
  }

  return createErrorResponse(
    'Internal server error',
    `系统暂时不可用，请稍后重试。数据库操作: ${operation}`,
    500,
    corsHeaders
  );
}

// ==================== 缓存查询工具 ====================

// VPS上报间隔缓存
let vpsIntervalCache = {
  value: null,
  timestamp: 0,
  ttl: 60000 // 1分钟缓存
};

// 获取VPS上报间隔（带缓存）
async function getVpsReportInterval(env) {
  const now = Date.now();

  // 检查缓存是否有效
  if (vpsIntervalCache.value !== null && (now - vpsIntervalCache.timestamp) < vpsIntervalCache.ttl) {
    return vpsIntervalCache.value;
  }

  try {
    const result = await env.DB.prepare(
      'SELECT value FROM app_config WHERE key = ?'
    ).bind('vps_report_interval_seconds').first();

    const interval = result?.value ? parseInt(result.value, 10) : 60;
    if (!isNaN(interval) && interval > 0) {
      // 更新缓存
      vpsIntervalCache.value = interval;
      vpsIntervalCache.timestamp = now;
      return interval;
    }
  } catch (error) {
    // 静默处理错误，使用默认值
  }

  // 默认值也缓存
  vpsIntervalCache.value = 60;
  vpsIntervalCache.timestamp = now;
  return 60;
}

// 清除VPS间隔缓存（当设置更新时调用）
function clearVpsIntervalCache() {
  vpsIntervalCache.value = null;
  vpsIntervalCache.timestamp = 0;
}

// ==================== VPS数据验证工具 ====================

// VPS数据默认值配置
const VPS_DATA_DEFAULTS = {
  cpu: { usage_percent: 0, load_avg: [0, 0, 0] },
  memory: { total: 0, used: 0, free: 0, usage_percent: 0 },
  disk: { total: 0, used: 0, free: 0, usage_percent: 0 },
  network: { upload_speed: 0, download_speed: 0, total_upload: 0, total_download: 0 }
};

// 简化的VPS数据验证和转换
function validateAndFixVpsField(data, field) {
  if (!data || typeof data !== 'object') return VPS_DATA_DEFAULTS[field];

  // 转换字符串数字为数字
  const converted = {};
  for (const [key, value] of Object.entries(data)) {
    converted[key] = typeof value === 'string' ? (parseFloat(value) || 0) : (value || 0);
  }

  return converted;
}

// 简化的VPS数据验证
function validateAndFixVpsData(reportData) {
  const requiredFields = ['timestamp', 'cpu', 'memory', 'disk', 'network', 'uptime'];

  // 检查必需字段
  for (const field of requiredFields) {
    if (!reportData[field]) {
      return { error: 'Invalid data format', message: `缺少字段: ${field}` };
    }
  }

  // 修复数据类型
  ['cpu', 'memory', 'disk', 'network'].forEach(field => {
    reportData[field] = validateAndFixVpsField(reportData[field], field);
  });

  // 修复时间戳和uptime
  reportData.timestamp = parseInt(reportData.timestamp) || Math.floor(Date.now() / 1000);
  reportData.uptime = parseInt(reportData.uptime) || 0;

  return { success: true, data: reportData };
}

// ==================== 密码处理 ====================

async function hashPassword(password) {
  // 生成16字节随机盐值
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  // 组合密码和盐值，进行1000次迭代（平衡安全性和性能）
  const encoder = new TextEncoder();
  let hash = encoder.encode(password + saltHex);

  for (let i = 0; i < 1000; i++) {
    hash = new Uint8Array(await crypto.subtle.digest('SHA-256', hash));
  }

  const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}$${hashHex}`;
}

async function verifyPassword(password, hashedPassword) {
  // 兼容新旧哈希格式
  if (hashedPassword.includes('$')) {
    // 新格式：salt$hash
    const [saltHex, expectedHash] = hashedPassword.split('$');

    const encoder = new TextEncoder();
    let hash = encoder.encode(password + saltHex);

    for (let i = 0; i < 1000; i++) {
      hash = new Uint8Array(await crypto.subtle.digest('SHA-256', hash));
    }

    const computedHash = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    return computedHash === expectedHash;
  } else {
    // 旧格式：纯SHA-256（向后兼容）
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const computedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return computedHash === hashedPassword;
  }
}

// ==================== JWT处理 ====================

// JWT验证缓存
const jwtCache = new Map();
const JWT_CACHE_TTL = 60000; // 1分钟缓存
const MAX_CACHE_SIZE = 1000; // 最大缓存条目数

// 清理过期的缓存条目
function cleanupJWTCache() {
  const now = Date.now();
  for (const [key, value] of jwtCache.entries()) {
    if (now - value.timestamp > JWT_CACHE_TTL) {
      jwtCache.delete(key);
    }
  }

  // 如果缓存过大，删除最旧的条目
  if (jwtCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(jwtCache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toDelete = entries.slice(0, jwtCache.size - MAX_CACHE_SIZE);
    toDelete.forEach(([key]) => jwtCache.delete(key));
  }
}

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

// 安全的JWT验证函数 - 修复缓存安全问题
async function verifyJWTCached(token, env) {
  // 首先检查令牌是否被撤销
  if (isTokenRevoked(token)) {
    jwtCache.delete(token);
    return null;
  }

  // 检查缓存
  const cached = jwtCache.get(token);
  if (cached && Date.now() - cached.timestamp < JWT_CACHE_TTL) {
    // 检查token是否过期
    if (cached.payload.exp && Date.now() > cached.payload.exp) {
      jwtCache.delete(token);
      return null;
    }
    // 再次检查撤销状态（防止缓存期间被撤销）
    if (isTokenRevoked(token)) {
      jwtCache.delete(token);
      return null;
    }
    return cached.payload;
  }

  // 缓存未命中，执行实际验证
  const payload = await verifyJWT(token, env);
  if (payload && !isTokenRevoked(token)) {
    // 定期清理缓存
    if (Math.random() < 0.01) {
      cleanupJWTCache();
    }

    // 存入缓存
    jwtCache.set(token, {
      payload,
      timestamp: Date.now()
    });
  }

  return payload;
}

// 原始JWT验证函数（不使用缓存）
async function verifyJWT(token, env) {
  try {
    // 检查令牌是否被撤销
    if (isTokenRevoked(token)) return null;

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
      last_notified_down_at INTEGER DEFAULT NULL,
      is_public INTEGER DEFAULT 1
    );`,

  metrics: `
    CREATE TABLE IF NOT EXISTS metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      cpu TEXT,
      memory TEXT,
      disk TEXT,
      network TEXT,
      uptime INTEGER,
      FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_metrics_server_id_timestamp ON metrics (server_id, timestamp DESC);`,

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
      last_notified_down_at INTEGER DEFAULT NULL,
      is_public INTEGER DEFAULT 1
    );`,

  site_status_history: `
    CREATE TABLE IF NOT EXISTS site_status_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      status TEXT NOT NULL,
      status_code INTEGER,
      response_time_ms INTEGER,
	  note TEXT,
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
    INSERT OR IGNORE INTO app_config (key, value) VALUES ('vps_report_interval_seconds', '60');
    INSERT OR IGNORE INTO app_config (key, value) VALUES ('custom_background_enabled', 'false');
    INSERT OR IGNORE INTO app_config (key, value) VALUES ('custom_background_url', '');
    INSERT OR IGNORE INTO app_config (key, value) VALUES ('page_opacity', '80');`,

  vps_status_history: `
    CREATE TABLE IF NOT EXISTS vps_status_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      status TEXT NOT NULL,
      cpu TEXT,
      memory TEXT,
      disk TEXT,
      network TEXT,
      uptime INTEGER,
      FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_vps_status_history_server_id_timestamp ON vps_status_history (server_id, timestamp DESC);`
};

// ==================== 数据库初始化 ====================

async function ensureTablesExist(db, env) {
  try {
    const createTableStatements = Object.values(D1_SCHEMAS).map(sql => db.prepare(sql));
    await db.batch(createTableStatements);
  } catch (error) {
    // 静默处理数据库创建错误
  }

  await createDefaultAdmin(db, env);
  await applySchemaAlterations(db);
}

async function applySchemaAlterations(db) {
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
    "ALTER TABLE admin_credentials ADD COLUMN password_changed_at INTEGER DEFAULT NULL",
    "ALTER TABLE servers ADD COLUMN is_public INTEGER DEFAULT 1",
    "ALTER TABLE monitored_sites ADD COLUMN is_public INTEGER DEFAULT 1",
    "ALTER TABLE site_status_history ADD COLUMN note TEXT",
    "ALTER TABLE servers ADD COLUMN realtime_endpoint TEXT DEFAULT NULL"
  ];

  for (const alterSql of alterStatements) {
    try {
      await db.exec(alterSql);
    } catch (e) {
      // 静默处理重复列错误
    }
  }
}

async function isUsingDefaultPassword(username, password) {
  return username === DEFAULT_ADMIN_CONFIG.USERNAME && password === DEFAULT_ADMIN_CONFIG.PASSWORD;
}

async function createDefaultAdmin(db, env) {
  try {
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
    }
  } catch (error) {
    if (!error.message.includes('no such table')) {
      throw error;
    }
  }
}


// ==================== 身份验证 ====================

// 优化的认证函数，使用JWT缓存和智能数据库查询
async function authenticateRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.substring(7);
  const payload = await verifyJWTCached(token, env);
  if (!payload) return null;

  // 只有在token需要刷新时才查询数据库验证用户状态
  // 这大大减少了数据库查询次数
  if (payload.shouldRefresh) {
    const user = await env.DB.prepare(
      'SELECT username, locked_until FROM admin_credentials WHERE username = ?'
    ).bind(payload.username).first();

    if (!user || (user.locked_until && Date.now() < user.locked_until)) {
      return null;
    }
  }

  return payload;
}

// 可选认证函数 - 用于前台API，支持游客和管理员两种模式
async function authenticateRequestOptional(request, env) {
  try {
    return await authenticateRequest(request, env);
  } catch (error) {
    return null; // 未登录或认证失败返回null
  }
}

// ==================== CORS处理 ====================

function getSecureCorsHeaders(origin, env) {
  const config = getSecurityConfig(env);
  const allowedOrigins = config.ALLOWED_ORIGINS;

  let allowedOrigin = 'null';  // 默认拒绝所有跨域请求

  // 只有明确配置了允许的域名才允许跨域
  if (allowedOrigins.length > 0 && origin) {
    // 精确匹配
    if (allowedOrigins.includes(origin)) {
      allowedOrigin = origin;
    } else {
      // 子域名匹配 (*.example.com)
      for (const allowed of allowedOrigins) {
        if (allowed.startsWith('*.')) {
          const domain = allowed.substring(2);
          if (origin === domain || origin.endsWith(`.${domain}`)) {
            allowedOrigin = origin;
            break;
          }
        }
      }
    }
  }

  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Allow-Credentials': allowedOrigin !== 'null' ? 'true' : 'false',
    'Access-Control-Max-Age': '86400',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
  };
}

// ==================== API路由模块 ====================

// 认证路由处理器
async function handleAuthRoutes(path, method, request, env, corsHeaders, clientIP) {
  // 登录处理
  if (path === '/api/auth/login' && method === 'POST') {
    try {
      if (!checkLoginAttempts(clientIP, env)) {
        return createErrorResponse(
          'Too many login attempts',
          '登录尝试次数过多，请15分钟后再试',
          429,
          corsHeaders
        );
      }

      const { username, password } = await parseJsonSafely(request);
      if (!username || !password) {
        recordLoginAttempt(clientIP);
        return createErrorResponse(
          'Missing credentials',
          '用户名和密码不能为空',
          400,
          corsHeaders
        );
      }

      const user = await env.DB.prepare(
        'SELECT username, password_hash, locked_until, failed_attempts FROM admin_credentials WHERE username = ?'
      ).bind(username).first();

      if (!user) {
        recordLoginAttempt(clientIP);
        return createErrorResponse(
          'Invalid credentials',
          '用户名或密码错误',
          401,
          corsHeaders
        );
      }

      if (user.locked_until && Date.now() < user.locked_until) {
        return createErrorResponse(
          'Account locked',
          '账户已被锁定，请稍后再试',
          423,
          corsHeaders
        );
      }

      const isValidPassword = await verifyPassword(password, user.password_hash);
      if (!isValidPassword) {
        recordLoginAttempt(clientIP);

        const newFailedAttempts = (user.failed_attempts || 0) + 1;
        const config = getSecurityConfig(env);
        let lockedUntil = null;

        if (newFailedAttempts >= config.MAX_LOGIN_ATTEMPTS) {
          lockedUntil = Date.now() + config.LOGIN_ATTEMPT_WINDOW;
        }

        await env.DB.prepare(
          'UPDATE admin_credentials SET failed_attempts = ?, locked_until = ? WHERE username = ?'
        ).bind(newFailedAttempts, lockedUntil, username).run();

        return createErrorResponse(
          'Invalid credentials',
          '用户名或密码错误',
          401,
          corsHeaders
        );
      }

      // 登录成功，重置失败次数
      await env.DB.prepare(
        'UPDATE admin_credentials SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?'
      ).bind(Date.now(), username).run();

      const isUsingDefault = await isUsingDefaultPassword(username, password);
      const token = await createJWT({ username, usingDefaultPassword: isUsingDefault }, env);

      return createSuccessResponse({
        token,
        user: { username, usingDefaultPassword: isUsingDefault }
      }, corsHeaders);

    } catch (error) {
      return handleDbError(error, corsHeaders, '登录');
    }
  }

  // 认证状态检查
  if (path === '/api/auth/status' && method === 'GET') {
    try {
      const user = await authenticateRequest(request, env);
      if (!user) {
        return createApiResponse({ authenticated: false }, 200, corsHeaders);
      }

      const dbUser = await env.DB.prepare(
        'SELECT username FROM admin_credentials WHERE username = ?'
      ).bind(user.username).first();

      if (!dbUser) {
        return createApiResponse({ authenticated: false }, 200, corsHeaders);
      }

      return createApiResponse({
        authenticated: true,
        user: {
          username: user.username,
          usingDefaultPassword: user.usingDefaultPassword || false
        }
      }, 200, corsHeaders);

    } catch (error) {
      return createApiResponse({ authenticated: false }, 200, corsHeaders);
    }
  }

  // 修改密码
  if (path === '/api/auth/change-password' && method === 'POST') {
    try {
      const user = await authenticateRequest(request, env);
      if (!user) {
        return createErrorResponse('Unauthorized', '需要登录', 401, corsHeaders);
      }

      const { current_password, new_password } = await parseJsonSafely(request);
      if (!current_password || !new_password) {
        return createErrorResponse(
          'Missing fields',
          '当前密码和新密码不能为空',
          400,
          corsHeaders
        );
      }

      const config = getSecurityConfig(env);
      if (new_password.length < config.MIN_PASSWORD_LENGTH) {
        return createErrorResponse(
          'Password too short',
          `密码长度至少为${config.MIN_PASSWORD_LENGTH}位`,
          400,
          corsHeaders
        );
      }

      const dbUser = await env.DB.prepare(
        'SELECT password_hash FROM admin_credentials WHERE username = ?'
      ).bind(user.username).first();

      if (!dbUser || !await verifyPassword(current_password, dbUser.password_hash)) {
        return createErrorResponse(
          'Invalid current password',
          '当前密码错误',
          400,
          corsHeaders
        );
      }

      const newPasswordHash = await hashPassword(new_password);
      await env.DB.prepare(
        'UPDATE admin_credentials SET password_hash = ?, password_changed_at = ?, must_change_password = 0 WHERE username = ?'
      ).bind(newPasswordHash, Date.now(), user.username).run();

      // 撤销当前令牌，强制重新登录
      const authHeader = request.headers.get('Authorization');
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const currentToken = authHeader.substring(7);
        revokeToken(currentToken);
      }

      return createSuccessResponse({
        message: '密码修改成功，请重新登录',
        requireReauth: true
      }, corsHeaders);

    } catch (error) {
      return handleDbError(error, corsHeaders, '修改密码');
    }
  }

  return null; // 不匹配此模块的路由
}

// 服务器管理路由处理器
async function handleServerRoutes(path, method, request, env, corsHeaders) {
  // 获取服务器列表（公开，支持管理员和游客模式）
  if (path === '/api/servers' && method === 'GET') {
    try {
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;

      // 使用缓存机制获取服务器列表
      const servers = await configCache.getServerList(env.DB, isAdmin);
      return createApiResponse({ servers }, 200, corsHeaders);

    } catch (error) {
      return handleDbError(error, corsHeaders, '获取服务器列表');
    }
  }

  // 管理员获取服务器列表（包含详细信息）
  if (path === '/api/admin/servers' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const { results } = await env.DB.prepare(`
        SELECT s.id, s.name, s.description, s.created_at, s.sort_order,
               s.last_notified_down_at, s.api_key, s.is_public, s.realtime_endpoint, 
               m.timestamp as last_report
        FROM servers s
        LEFT JOIN metrics m ON s.id = m.server_id
        ORDER BY s.sort_order ASC NULLS LAST, s.name ASC
      `).all();

      // 检查是否需要完整密钥（用于查看密钥和复制脚本功能）
      const url = new URL(request.url);
      const showFullKey = url.searchParams.get('full_key') === 'true';

      // 根据参数决定是否脱敏API密钥
      const servers = (results || []).map(server => ({
        ...server,
        api_key: showFullKey ? server.api_key : maskSensitive(server.api_key)
      }));

      return createApiResponse({ servers }, 200, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '获取管理员服务器列表');
    }
  }

  // 添加服务器（管理员）
  if (path === '/api/admin/servers' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const { name, description } = await parseJsonSafely(request);
      if (!validateInput(name, 'serverName')) {
        return createErrorResponse(
          'Invalid server name',
          '服务器名称格式无效',
          400,
          corsHeaders
        );
      }

      const serverId = Math.random().toString(36).substring(2, 8);
      // 生成32字节强随机API密钥
      const apiKey = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
      const now = Math.floor(Date.now() / 1000);

      await env.DB.prepare(`
        INSERT INTO servers (id, name, description, api_key, created_at, sort_order, is_public)
        VALUES (?, ?, ?, ?, ?, 0, 1)
      `).bind(serverId, name, description || '', apiKey, now).run();

      // 清除服务器列表缓存
      configCache.clearKey('servers_admin');
      configCache.clearKey('servers_public');

      return createSuccessResponse({
        server: {
          id: serverId,
          name,
          description: description || '',
          api_key: maskSensitive(apiKey),
          created_at: now
        }
      }, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '添加服务器');
    }
  }

  // 更新服务器（管理员） - 修复权限检查
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'PUT') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return createErrorResponse(
          'Invalid server ID',
          '无效的服务器ID格式',
          400,
          corsHeaders
        );
      }

      const { name, description, realtime_endpoint } = await request.json();
      if (!validateInput(name, 'serverName')) {
        return createErrorResponse(
          'Invalid server name',
          '服务器名称格式无效',
          400,
          corsHeaders
        );
      }

      // 验证实时监控端点URL格式
      let realtimeEndpoint = null;
      if (realtime_endpoint && realtime_endpoint.trim()) {
        const endpoint = realtime_endpoint.trim();
        try {
          const url = new URL(endpoint);
          if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            return createErrorResponse(
              'Invalid endpoint URL',
              '实时监控端点必须是有效的HTTP/HTTPS URL',
              400,
              corsHeaders
            );
          }
          realtimeEndpoint = endpoint;
        } catch (urlError) {
          return createErrorResponse(
            'Invalid endpoint URL',
            '实时监控端点URL格式无效',
            400,
            corsHeaders
          );
        }
      }

      const info = await env.DB.prepare(`
        UPDATE servers SET name = ?, description = ?, realtime_endpoint = ? WHERE id = ?
      `).bind(name, description || '', realtimeEndpoint, serverId).run();

      if (info.changes === 0) {
        return createErrorResponse('Server not found', '服务器不存在', 404, corsHeaders);
      }

      // 清除服务器列表缓存
      configCache.clearKey('servers_admin');
      configCache.clearKey('servers_public');

      return createSuccessResponse({
        id: serverId,
        name,
        description: description || '',
        message: '服务器更新成功'
      }, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '更新服务器');
    }
  }

  // 删除服务器（管理员）
  if (path.match(/\/api\/admin\/servers\/[^\/]+$/) && method === 'DELETE') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const serverId = extractAndValidateServerId(path);
      if (!serverId) {
        return createErrorResponse(
          'Invalid server ID',
          '无效的服务器ID格式',
          400,
          corsHeaders
        );
      }

      // 危险操作需要确认
      const url = new URL(request.url);
      const confirmed = url.searchParams.get('confirm') === 'true';
      if (!confirmed) {
        return createErrorResponse(
          'Confirmation required',
          '删除操作需要确认，请添加 ?confirm=true 参数',
          400,
          corsHeaders
        );
      }

      const info = await env.DB.prepare('DELETE FROM servers WHERE id = ?').bind(serverId).run();
      if (info.changes === 0) {
        return createErrorResponse('Server not found', '服务器不存在', 404, corsHeaders);
      }

      // 同时删除相关的监控数据
      await env.DB.prepare('DELETE FROM metrics WHERE server_id = ?').bind(serverId).run();

      // 清除服务器列表缓存
      configCache.clearKey('servers_admin');
      configCache.clearKey('servers_public');

      return createSuccessResponse({ message: '服务器已删除' }, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '删除服务器');
    }
  }

  // 获取VPS服务器在线率（管理员和公开API）
  if (path.match(/\/api\/servers\/([^\/]+)\/uptime$/) && method === 'GET') {
    try {
      const serverId = path.split('/')[3];
      
      // 检查权限：管理员或公开服务器
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;
      
      if (!isAdmin) {
        // 检查服务器是否公开
        const server = await env.DB.prepare(
          'SELECT is_public FROM servers WHERE id = ?'
        ).bind(serverId).first();
        
        if (!server || !server.is_public) {
          return createErrorResponse('Not Found', '服务器不存在或未公开', 404, corsHeaders);
        }
      }
      
      // 解析时间参数
      const url = new URL(request.url);
      const period = url.searchParams.get('period') || '24h';
      
      let hours;
      switch (period) {
        case '24h': hours = 24; break;
        case '3d': hours = 24 * 3; break;
        case '30d': hours = 24 * 30; break;
        case '90d': hours = 24 * 90; break;
        case '180d': hours = 24 * 180; break;
        case '365d': hours = 24 * 365; break;
        default: hours = 24;
      }
      
      // 计算在线率
      const uptimeData = await calculateVpsUptime(env, serverId, hours);
      
      return createApiResponse({
        serverId,
        period,
        uptime: uptimeData.uptime,
        totalTime: uptimeData.totalTime,
        onlineTime: uptimeData.onlineTime
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取服务器在线率');
    }
  }

  // 获取所有VPS服务器在线率（管理员）
  if (path === '/api/admin/servers/uptime' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      // 解析时间参数
      const url = new URL(request.url);
      const period = url.searchParams.get('period') || '24h';
      
      let hours;
      switch (period) {
        case '24h': hours = 24; break;
        case '3d': hours = 24 * 3; break;
        case '30d': hours = 24 * 30; break;
        case '90d': hours = 24 * 90; break;
        case '180d': hours = 24 * 180; break;
        case '365d': hours = 24 * 365; break;
        default: hours = 24;
      }
      
      // 获取所有服务器
      const { results } = await env.DB.prepare(
        'SELECT id, name FROM servers ORDER BY sort_order ASC NULLS LAST, name ASC'
      ).all();
      
      const uptimeResults = [];
      
      // 为每个服务器计算在线率
      for (const server of results || []) {
        const uptimeData = await calculateVpsUptime(env, server.id, hours);
        uptimeResults.push({
          id: server.id,  // 使用 id 而不是 serverId
          serverName: server.name,
          uptime: uptimeData.uptime,
          totalTime: uptimeData.totalTime,
          onlineTime: uptimeData.onlineTime
        });
      }
      
      return createApiResponse({
        period,
        servers: uptimeResults
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取所有服务器在线率');
    }
  }

  return null; // 不匹配此模块的路由
}

// VPS监控路由处理器
async function handleVpsRoutes(path, method, request, env, corsHeaders, ctx) {
  // VPS配置获取（使用API密钥认证）
  if (path.startsWith('/api/config/') && method === 'GET') {
    try {
      const authResult = await validateServerAuth(path, request, env);
      if (!authResult.success) {
        return createErrorResponse(authResult.error, authResult.message,
          authResult.error === 'Invalid server ID' ? 400 : 401, corsHeaders);
      }

      const { serverId, serverData } = authResult;
      const reportInterval = await getVpsReportInterval(env);

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

      return createApiResponse(configData, 200, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '配置获取');
    }
  }

  // VPS数据上报
  if (path.startsWith('/api/report/') && method === 'POST') {
    try {
      const authResult = await validateServerAuth(path, request, env);
      if (!authResult.success) {
        return createErrorResponse(authResult.error, authResult.message,
          authResult.error === 'Invalid server ID' ? 400 : 401, corsHeaders);
      }

      const { serverId } = authResult;

      // 解析和验证上报数据
      let reportData;
      try {
        const rawBody = await request.text();
        reportData = JSON.parse(rawBody);
      } catch (parseError) {
        return createErrorResponse(
          'Invalid JSON format',
          `JSON解析失败: ${parseError.message}`,
          400,
          corsHeaders,
          '请检查上报的JSON格式是否正确'
        );
      }

      const validationResult = validateAndFixVpsData(reportData);
      if (!validationResult.success) {
        return createErrorResponse(
          validationResult.error,
          validationResult.message,
          400,
          corsHeaders,
          validationResult.details
        );
      }

      reportData = validationResult.data;

      // 存储到实时数据缓存（优先级高，立即存储）
      storeRealtimeData(serverId, {
        cpu: reportData.cpu,
        memory: reportData.memory,
        disk: reportData.disk,
        network: reportData.network,
        uptime: reportData.uptime,
        timestamp: reportData.timestamp
      });

      // 获取当前的批量写入间隔（与VPS上报间隔一致）
      const currentInterval = await getVpsReportInterval(env);

      // 使用批量处理器处理VPS数据
      const shouldFlush = vpsBatchProcessor.addReport(serverId, reportData, currentInterval);

      // 如果需要刷新或使用ctx.waitUntil进行异步刷新
      if (shouldFlush) {
        ctx.waitUntil(flushVpsBatchData(env));
      } else {
        // 检查是否有定时需要刷新的数据
        if (vpsBatchProcessor.shouldFlush(currentInterval)) {
          ctx.waitUntil(flushVpsBatchData(env));
        }
      }

      return createSuccessResponse({ interval: currentInterval }, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '数据上报');
    }
  }

  // 批量VPS状态查询（公开，支持管理员和游客模式）
  if (path === '/api/status/batch' && method === 'GET') {
    try {
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;

      // 使用JOIN查询一次性获取所有VPS状态
      const { results } = await env.DB.prepare(`
        SELECT s.id, s.name, s.description,s.realtime_endpoint,
               m.timestamp, m.cpu, m.memory, m.disk, m.network, m.uptime
        FROM servers s
        LEFT JOIN metrics m ON s.id = m.server_id
        WHERE s.is_public = 1 OR ? = 1
        ORDER BY s.sort_order ASC NULLS LAST, s.name ASC
      `).bind(isAdmin ? 1 : 0).all();

      // 处理数据格式，保持与单个查询API的兼容性
      const servers = (results || []).map(row => {
        const server = { id: row.id, name: row.name, description: row.description ,realtime_endpoint: row.realtime_endpoint};
        let metrics = null;

        if (row.timestamp) {
          metrics = {
            timestamp: row.timestamp,
            uptime: row.uptime
          };

          // 解析JSON字段
          try {
            if (row.cpu) metrics.cpu = JSON.parse(row.cpu);
            if (row.memory) metrics.memory = JSON.parse(row.memory);
            if (row.disk) metrics.disk = JSON.parse(row.disk);
            if (row.network) metrics.network = JSON.parse(row.network);
          } catch (parseError) {
            // 静默处理JSON解析错误
          }
        }

        return { server, metrics, error: false };
      });

      return createApiResponse({ servers }, 200, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '批量状态查询');
    }
  }
 
  // 实时VPS状态查询（ 无需认证） 
    if (path.startsWith('/api/realtime/') && method === 'GET') {
      const serverId = path.split('/')[3]; 
      if (!serverId || serverId === '') {
        return createErrorResponse('Invalid server ID', '无效的服务器ID', 400, corsHeaders);
      }

      // 验证服务器是否存在，并获取实时监控端点配置
      const serverResult = await env.DB.prepare('SELECT id, name, realtime_endpoint FROM servers WHERE id = ?').bind(serverId).first();
      if (!serverResult) {
        return createErrorResponse('Server not found', '服务器不存在', 404, corsHeaders);
      } 

	// 如果配置了实时端点，尝试直接访问VPS
	if (serverResult.realtime_endpoint) {
	
		try {
		  const response = await fetch(serverResult.realtime_endpoint, {
			method: 'GET',
			headers: {
			  'Accept': 'application/json',
			  'User-Agent': 'VPS-Monitor/1.0'
			},
			signal: AbortSignal.timeout(5000) // 5秒超时
		  });

  return createApiResponse({
				success: true,
				source: 'real',
				data: await response.json()
			  }, 200, corsHeaders);
		  if (response.ok) {
			const data = await response.json();
			if (data.success && data.data) {
			  return createApiResponse({
				success: true,
				source: 'real',
				data: data.data
			  }, 200, corsHeaders);
			}
		  }
		} catch (fetchError) { 
		return createApiResponse({
				success: false,
				source: 'real',
				data: 'vps接口数据获取失败'
			  }, 200, corsHeaders); 
		}         
	}  
	else{
		return createApiResponse({
			success: false,
			source: 'real',
			data: '未配置实时监控api'
		  }, 200, corsHeaders);
	}
  }

  // VPS状态查询（公开，无需认证）
  if (path.startsWith('/api/status/') && method === 'GET') {
    try {
      const serverId = path.split('/')[3]; // 从 /api/status/{serverId} 提取ID
      if (!serverId) {
        return createErrorResponse('Invalid server ID', '无效的服务器ID', 400, corsHeaders);
      }

      // 查询服务器信息（移除权限限制，让前台能正常显示）
      const serverData = await env.DB.prepare(
        'SELECT id, name, description FROM servers WHERE id = ?'
      ).bind(serverId).first();

      if (!serverData) {
        return createErrorResponse('Server not found', '服务器不存在', 404, corsHeaders);
      }

      // 查询最新的VPS监控数据
      const metricsData = await env.DB.prepare(`
        SELECT * FROM metrics
        WHERE server_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
      `).bind(serverId).first();

      // 解析JSON字符串为对象
      if (metricsData) {
        try {
          if (metricsData.cpu) metricsData.cpu = JSON.parse(metricsData.cpu);
          if (metricsData.memory) metricsData.memory = JSON.parse(metricsData.memory);
          if (metricsData.disk) metricsData.disk = JSON.parse(metricsData.disk);
          if (metricsData.network) metricsData.network = JSON.parse(metricsData.network);
        } catch (parseError) {
          // 静默处理JSON解析错误
        }
      }

      // 返回完整的监控数据（保持前端兼容性）
      const publicInfo = {
        server: serverData,
        metrics: metricsData || null,
        error: false
      };

      return createApiResponse(publicInfo, 200, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, 'VPS状态查询');
    }
  }

  // VPS状态变化通知API
  if (path === '/api/notify/offline' && method === 'POST') {
    try {
      const { serverId, serverName } = await request.json();

      // 检查是否已发送过离线通知
      const server = await env.DB.prepare('SELECT last_notified_down_at FROM servers WHERE id = ?').bind(serverId).first();
      if (server?.last_notified_down_at) {
        return createApiResponse({ success: true, message: 'Already notified' }, 200, corsHeaders);
      }

      const message = `🔴 VPS故障: 服务器 *${serverName}* 已离线超过5分钟`;

      // 记录离线时间并发送通知
      await env.DB.prepare('UPDATE servers SET last_notified_down_at = ? WHERE id = ?')
        .bind(Math.floor(Date.now() / 1000), serverId).run();
      ctx.waitUntil(sendTelegramNotificationOptimized(env.DB, message, 'high'));

      return createApiResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
            return createErrorResponse('Notification failed', '通知发送失败', 500, corsHeaders);
    }
  }

  if (path === '/api/notify/recovery' && method === 'POST') {
    try {
      const { serverId, serverName } = await request.json();
      const message = `✅ VPS恢复: 服务器 *${serverName}* 已恢复在线`;

      // 清除离线记录
      await env.DB.prepare('UPDATE servers SET last_notified_down_at = NULL WHERE id = ?')
        .bind(serverId).run();

      // 发送通知
      ctx.waitUntil(sendTelegramNotificationOptimized(env.DB, message, 'high'));

      return createApiResponse({ success: true }, 200, corsHeaders);
    } catch (error) {
            return createErrorResponse('Notification failed', '通知发送失败', 500, corsHeaders);
    }
  }

  return null; // 不匹配此模块的路由
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
    return createErrorResponse(
      'Rate limit exceeded',
      '请求过于频繁，请稍后再试',
      429,
      corsHeaders
    );
  }

  // ==================== 路由分发 ====================

  // 认证相关路由
  if (path.startsWith('/api/auth/')) {
    const authResult = await handleAuthRoutes(path, method, request, env, corsHeaders, clientIP);
    if (authResult) return authResult;
  }

  // 服务器管理路由
  if (path.startsWith('/api/servers') || path.startsWith('/api/admin/servers')) {
    const serverResult = await handleServerRoutes(path, method, request, env, corsHeaders);
    if (serverResult) return serverResult;
  }



  // VPS监控路由
  if (path.startsWith('/api/config/') || path.startsWith('/api/report/') ||
      path.startsWith('/api/status/') || path.startsWith('/api/notify/')|| path.startsWith('/api/realtime/')) {
    const vpsResult = await handleVpsRoutes(path, method, request, env, corsHeaders, ctx);
    if (vpsResult) return vpsResult;
  }

  // 数据库初始化API（无需认证）
  if (path === '/api/init-db' && ['POST', 'GET'].includes(method)) {
    try {
      await ensureTablesExist(env.DB, env);
      return createSuccessResponse({
        message: '数据库初始化完成'
      }, corsHeaders);
    } catch (error) {
      return createErrorResponse(
        'Database initialization failed',
        `数据库初始化失败: ${error.message}`,
        500,
        corsHeaders
      );
    }
  }




  // ==================== 高级排序功能 ====================

  // 批量服务器排序（管理员） - 修复权限检查
  if (path === '/api/admin/servers/batch-reorder' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
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
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 自动服务器排序（管理员） - 修复权限检查
  if (path === '/api/admin/servers/auto-sort' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
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

      // 获取所有服务器并排序 - 安全验证
      const safeOrder = validateSqlIdentifier(order.toUpperCase(), 'order');
      let orderClause = '';
      if (sortBy === 'name') {
        orderClause = `ORDER BY name ${safeOrder}`;
      } else if (sortBy === 'status') {
        orderClause = `ORDER BY (CASE WHEN m.timestamp IS NULL OR (strftime('%s', 'now') - m.timestamp) > 300 THEN 1 ELSE 0 END) ${safeOrder}, name ASC`;
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
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 导出服务器列表（管理员）
  if (path === '/api/admin/servers/export' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const { results } = await env.DB.prepare(`
        SELECT id, name, description, sort_order, is_public, created_at, api_key
        FROM servers
        ORDER BY sort_order ASC NULLS LAST, name ASC
      `).all();

      const exportData = {
        type: 'servers',
        version: '1.0',
        exportTime: new Date().toISOString(),
        data: (results || []).map(server => ({
          id: server.id,
          name: server.name,
          description: server.description || '',
          sort_order: server.sort_order,
          is_public: server.is_public || 1,
          api_key: server.api_key,
          created_at: server.created_at
        }))
      };

      return createApiResponse(exportData, 200, corsHeaders);
    } catch (error) {
      return handleDbError(error, corsHeaders, '导出服务器列表');
    }
  }

  // 导入服务器列表（管理员）
  if (path === '/api/admin/servers/import' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const importData = await request.json();
      
      // 验证导入数据格式
      if (!importData || importData.type !== 'servers' || !Array.isArray(importData.data)) {
        return createErrorResponse('Invalid format', '导入数据格式无效', 400, corsHeaders);
      }

      const servers = importData.data;
      let importedCount = 0;
      let skippedCount = 0;
      const errors = [];

      for (const server of servers) {
        try {
          // 验证必要字段
          if (!server.name || typeof server.name !== 'string') {
            errors.push(`服务器名称无效: ${JSON.stringify(server)}`);
            continue;
          }

          // 检查是否已存在同ID或同名服务器
          let existing = null;
          if (server.id) {
            existing = await env.DB.prepare(
              'SELECT id FROM servers WHERE id = ?'
            ).bind(server.id).first();
          }
          
          if (!existing && server.name) {
            existing = await env.DB.prepare(
              'SELECT id FROM servers WHERE name = ?'
            ).bind(server.name).first();
          }

          if (existing) {
            skippedCount++;
            continue;
          }

          // 使用导出的ID和API密钥，如果没有则生成新的
          const serverId = server.id || generateId();
          const apiKey = server.api_key || generateSecureApiKey();
          const now = server.created_at ? Math.floor(new Date(server.created_at).getTime() / 1000) : Math.floor(Date.now() / 1000);

          await env.DB.prepare(`
            INSERT INTO servers (id, name, description, api_key, created_at, sort_order, is_public)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).bind(
            serverId,
            server.name,
            server.description || '',
            apiKey,
            now,
            server.sort_order || null,
            server.is_public !== undefined ? server.is_public : 1
          ).run();

          importedCount++;
        } catch (serverError) {
          errors.push(`导入服务器 "${server.name}" 失败: ${serverError.message}`);
        }
      }

      // 清除缓存
      configCache.clearKey('servers_admin');
      configCache.clearKey('servers_public');

      return createApiResponse({
        success: true,
        message: `导入完成: ${importedCount} 个服务器已导入, ${skippedCount} 个已跳过`,
        imported: importedCount,
        skipped: skippedCount,
        errors: errors
      }, 200, corsHeaders);

    } catch (error) {
      return handleDbError(error, corsHeaders, '导入服务器列表');
    }
  }

  // 初始化所有服务器在线率（管理员）
  if (path === '/api/admin/servers/init-uptime' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      // 获取所有服务器
      const { results } = await env.DB.prepare(
        'SELECT id FROM servers'
      ).all();
      
      let count = 0;
      const now = Math.floor(Date.now() / 1000);
      
      // 为每个服务器创建初始在线率记录
      for (const server of results || []) {
        // 清除历史数据
        await env.DB.prepare(
          'DELETE FROM vps_status_history WHERE server_id = ?'
        ).bind(server.id).run();
        
        // 更新服务器的创建时间为当前时间（作为在线率计算的起始点）
        await env.DB.prepare(
          'UPDATE servers SET created_at = ? WHERE id = ?'
        ).bind(new Date().toISOString(), server.id).run();
        
        // 插入初始在线状态记录
        await env.DB.prepare(`
          INSERT INTO vps_status_history (server_id, timestamp, status)
          VALUES (?, ?, 'online')
        `).bind(server.id, now).run();
        
        count++;
      }
      
      return createApiResponse({
        success: true,
        message: `已初始化 ${count} 个服务器的在线率`,
        count
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '初始化服务器在线率');
    }
  }

  // 获取VPS服务器详细在线率历史（管理员和公开API）
  if (path.match(/\/api\/servers\/([^\/]+)\/uptime\/history$/) && method === 'GET') {
    try {
      const serverId = path.split('/')[3];
      
      // 检查权限：管理员或公开服务器
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;
      
      if (!isAdmin) {
        // 检查服务器是否公开
        const server = await env.DB.prepare(
          'SELECT is_public FROM servers WHERE id = ?'
        ).bind(serverId).first();
        
        if (!server || !server.is_public) {
          return createErrorResponse('Not Found', '服务器不存在或未公开', 404, corsHeaders);
        }
      }
      
      // 解析时间参数
      const url = new URL(request.url);
      const period = url.searchParams.get('period') || '24h';
      
      let hours;
      switch (period) {
        case '24h': hours = 24; break;
        case '3d': hours = 24 * 3; break;
        case '30d': hours = 24 * 30; break;
        case '90d': hours = 24 * 90; break;
        case '180d': hours = 24 * 180; break;
        case '365d': hours = 24 * 365; break;
        default: hours = 24;
      }
      
      const now = Math.floor(Date.now() / 1000);
      const startTime = now - (hours * 60 * 60);
      
      // 获取服务器信息
      const serverInfo = await env.DB.prepare(
        'SELECT name, created_at FROM servers WHERE id = ?'
      ).bind(serverId).first();
      
      if (!serverInfo) {
        return createErrorResponse('Not Found', '服务器不存在', 404, corsHeaders);
      }
      
      // 获取历史状态变化记录
      const { results } = await env.DB.prepare(`
        SELECT timestamp, status
        FROM vps_status_history
        WHERE server_id = ? AND timestamp >= ?
        ORDER BY timestamp ASC
      `).bind(serverId, startTime).all();
      
      // 分析断开时间段
      const downtimes = [];
      let lastStatus = 'online';
      let lastTimestamp = startTime;
      let offlineStart = null;
      
      // 考虑服务器创建时间
      const serverCreatedAt = serverInfo.created_at ? Math.floor(new Date(serverInfo.created_at).getTime() / 1000) : startTime;
      const actualStartTime = Math.max(serverCreatedAt, startTime);
	  if ( (now-actualStartTime)/3600 < hours ) {
		hours=Math.floor((now-actualStartTime)/3600);
	  } 
      for (const record of results || []) {
        if (lastStatus === 'online' && record.status === 'offline') {
          // 开始断开
          offlineStart = record.timestamp;
        } else if (lastStatus === 'offline' && record.status === 'online') {
          // 恢复在线
          if (offlineStart) {
            const duration = record.timestamp - offlineStart;
            downtimes.push({
              startTime: offlineStart,
              endTime: record.timestamp,
              duration: duration,
              startTimeFormatted: offlineStart ,
              endTimeFormatted: record.timestamp ,
              durationFormatted: formatDuration(duration)
            });
          }
        }
        lastStatus = record.status;
        lastTimestamp = record.timestamp;
      }
      
      // 如果当前仍然离线，添加到断开记录
      if (lastStatus === 'offline' && offlineStart) {
        const duration = now - offlineStart;
        downtimes.push({
          startTime: offlineStart,
          endTime: null, // 当前仍离线
          duration: duration,
          startTimeFormatted: offlineStart ,
          endTimeFormatted: '仍离线',
          durationFormatted: formatDuration(duration)
        });
      }
      
      // 计算总体统计
      const uptimeData = await calculateVpsUptime(env, serverId, hours);
      
      // 生成图表数据点 (每小时一个数据点)
      const chartDataPoints = [];
      const dataPointInterval = Math.max(1, Math.floor(hours / 72)); // 最多72个数据点
      
      for (let i = 0; i < hours; i += dataPointInterval) {
        const pointStartTime = actualStartTime + (i * 60 * 60);
        const pointEndTime = Math.min(actualStartTime + ((i + dataPointInterval) * 60 * 60), now);
        
        // 检查这个时间段内是否在线
        let isOnline = true;
        for (const downtime of downtimes) {
          const downtimeStart = downtime.startTime;
          const downtimeEnd = downtime.endTime || now;
          
          if (!(pointEndTime <= downtimeStart || pointStartTime >= downtimeEnd)) {
            isOnline = false;
            break;
          }
        }
        
        chartDataPoints.push({
          timestamp: pointStartTime,
          timeFormatted: pointStartTime ,
          status: isOnline ? 'online' : 'offline'
        });
      }
      
      return createApiResponse({
        serverId,
        serverName: serverInfo.name,
        period,
        periodHours: hours,
        actualStartTime: actualStartTime,
        startTimeFormatted: actualStartTime ,
        uptime: uptimeData.uptime,
        totalTime: uptimeData.totalTime,
        onlineTime: uptimeData.onlineTime,
        downtimeCount: downtimes.length,
        downtimes: downtimes,
        chartData: chartDataPoints
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取服务器在线率历史');
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
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 更新服务器显示状态（管理员）
  if (path.match(/^\/api\/admin\/servers\/([^\/]+)\/visibility$/) && method === 'POST') {
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
      const serverId = path.split('/')[4];
      const { is_public } = await request.json();

      // 验证输入
      if (typeof is_public !== 'boolean') {
        return new Response(JSON.stringify({
          error: 'Invalid input',
          message: '显示状态必须为布尔值'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 更新服务器显示状态
      await env.DB.prepare(`
        UPDATE servers SET is_public = ? WHERE id = ?
      `).bind(is_public ? 1 : 0, serverId).run();

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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
               last_response_time_ms, sort_order, last_notified_down_at, is_public
        FROM monitored_sites
        ORDER BY sort_order ASC NULLS LAST, name ASC, url ASC
      `).all();

      return new Response(JSON.stringify({ sites: results || [] }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
            if (error.message.includes('no such table')) {
                try {
          await env.DB.exec(D1_SCHEMAS.monitored_sites);
          return new Response(JSON.stringify({ sites: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
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
      const { url, name } = await parseJsonSafely(request);

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

      } else {
        checkWebsiteStatus(newSiteForCheck, env.DB, ctx).catch(e => {
          // 静默处理站点检查错误
        });
      }

      return new Response(JSON.stringify({ site: siteData }), {
        status: 201,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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
    const user = await authenticateRequest(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const siteId = path.split('/').pop();
      if (!siteId) {
        return createErrorResponse('Invalid site ID', '无效的网站ID', 400, corsHeaders);
      }

      const { url, name } = await request.json();
      if (!url || !url.trim()) {
        return createErrorResponse('Invalid URL', 'URL不能为空', 400, corsHeaders);
      }

      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return createErrorResponse('Invalid URL format', 'URL必须以http://或https://开头', 400, corsHeaders);
      }

      const info = await env.DB.prepare(`
        UPDATE monitored_sites SET url = ?, name = ? WHERE id = ?
      `).bind(url.trim(), name?.trim() || '', siteId).run();

      if (info.changes === 0) {
        return createErrorResponse('Site not found', '网站不存在', 404, corsHeaders);
      }

      return createSuccessResponse({
        id: siteId,
        url: url.trim(),
        name: name?.trim() || '',
        message: '网站更新成功'
      }, corsHeaders);

    } catch (error) {
            return handleDbError(error, corsHeaders, '更新监控站点');
    }
  }

  // 删除监控站点（管理员）
  if (path.match(/\/api\/admin\/sites\/[^\/]+$/) && method === 'DELETE') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const siteId = extractAndValidateServerId(path);
      if (!siteId) {
        return createErrorResponse('Invalid site ID', '无效的站点ID格式', 400, corsHeaders);
      }

      // 危险操作需要确认
      const url = new URL(request.url);
      const confirmed = url.searchParams.get('confirm') === 'true';
      if (!confirmed) {
        return createErrorResponse(
          'Confirmation required',
          '删除操作需要确认，请添加 ?confirm=true 参数',
          400,
          corsHeaders
        );
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

      // 获取所有站点并排序 - 安全验证
      const safeSortBy = validateSqlIdentifier(sortBy, 'column');
      const safeOrder = validateSqlIdentifier(order.toUpperCase(), 'order');

      const { results: sites } = await env.DB.prepare(`
        SELECT id FROM monitored_sites
        ORDER BY ${safeSortBy} ${safeOrder}
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
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 导出网站列表（管理员）
  if (path === '/api/admin/sites/export' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const { results } = await env.DB.prepare(`
        SELECT id, name, url, description, sort_order, is_public
        FROM monitored_sites
        ORDER BY sort_order ASC NULLS LAST, name ASC
      `).all();

      const exportData = {
        type: 'sites',
        version: '1.0',
        exportTime: new Date().toISOString(),
        data: (results || []).map(site => ({
          name: site.name || '',
          url: site.url,
          description: site.description || '',
          sort_order: site.sort_order,
          is_public: site.is_public || 1
        }))
      };

      return createApiResponse(exportData, 200, corsHeaders);
    } catch (error) {
      return handleDbError(error, corsHeaders, '导出网站列表');
    }
  }

  // 导入网站列表（管理员）
  if (path === '/api/admin/sites/import' && method === 'POST') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      const importData = await request.json();
      
      // 验证导入数据格式
      if (!importData || importData.type !== 'sites' || !Array.isArray(importData.data)) {
        return createErrorResponse('Invalid format', '导入数据格式无效', 400, corsHeaders);
      }

      const sites = importData.data;
      let importedCount = 0;
      let skippedCount = 0;
      const errors = [];

      for (const site of sites) {
        try {
          // 验证必要字段
          if (!site.url || typeof site.url !== 'string') {
            errors.push(`网站URL无效: ${JSON.stringify(site)}`);
            continue;
          }

          // 验证URL格式
          if (!isValidHttpUrl(site.url)) {
            errors.push(`无效的URL格式: ${site.url}`);
            continue;
          }

          // 检查是否已存在相同URL的网站
          const existing = await env.DB.prepare(
            'SELECT id FROM monitored_sites WHERE url = ?'
          ).bind(site.url).first();

          if (existing) {
            skippedCount++;
            continue;
          }

          // 生成新的网站ID
          const siteId = generateId();

          await env.DB.prepare(`
            INSERT INTO monitored_sites (id, name, url, description, sort_order, is_public, last_checked, last_status)
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
          `).bind(
            siteId,
            site.name || '',
            site.url,
            site.description || '',
            site.sort_order || null,
            site.is_public !== undefined ? site.is_public : 1
          ).run();

          importedCount++;
        } catch (siteError) {
          errors.push(`导入网站 "${site.url}" 失败: ${siteError.message}`);
        }
      }

      return createApiResponse({
        success: true,
        message: `导入完成: ${importedCount} 个网站已导入, ${skippedCount} 个已跳过`,
        imported: importedCount,
        skipped: skippedCount,
        errors: errors
      }, 200, corsHeaders);

    } catch (error) {
      return handleDbError(error, corsHeaders, '导入网站列表');
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
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 更新网站显示状态（管理员）
  if (path.match(/^\/api\/admin\/sites\/([^\/]+)\/visibility$/) && method === 'POST') {
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
      const siteId = path.split('/')[4];
      const { is_public } = await request.json();

      // 验证输入
      if (typeof is_public !== 'boolean') {
        return new Response(JSON.stringify({
          error: 'Invalid input',
          message: '显示状态必须为布尔值'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 更新网站显示状态
      await env.DB.prepare(`
        UPDATE monitored_sites SET is_public = ? WHERE id = ?
      `).bind(is_public ? 1 : 0, siteId).run();

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // 获取所有网站在线率（管理员）
  if (path === '/api/admin/sites/uptime' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      // 解析时间参数
      const url = new URL(request.url);
      const period = url.searchParams.get('period') || '24h';
      
      let hours;
      switch (period) {
        case '24h': hours = 24; break;
        case '3d': hours = 24 * 3; break;
        case '30d': hours = 24 * 30; break;
        case '90d': hours = 24 * 90; break;
        case '180d': hours = 24 * 180; break;
        case '365d': hours = 24 * 365; break;
        default: hours = 24;
      }
      
      // 获取所有网站
      const { results } = await env.DB.prepare(
        'SELECT id, name FROM monitored_sites ORDER BY sort_order ASC NULLS LAST, name ASC'
      ).all();
      
      const uptimeResults = [];
      
      // 为每个网站计算在线率
      for (const site of results || []) {
        const uptimeData = await calculateSiteUptime(env, site.id, hours);
        uptimeResults.push({
          id: site.id,
          siteName: site.name,
          uptime: uptimeData.uptime,
          totalTime: uptimeData.totalTime,
          onlineTime: uptimeData.onlineTime ,
		  me: uptimeData.me 
        });
      }
      
      return createApiResponse({
        period,
        sites: uptimeResults
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取所有网站在线率');
    }
  }

  // 调试端点：检查网站监控状态
  if (path === '/api/admin/sites/debug' && method === 'GET') {
    const user = await authenticateAdmin(request, env);
    if (!user) {
      return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
    }

    try {
      // 检查监控网站的状态
      const { results: sites } = await env.DB.prepare(`
        SELECT id, name, url, last_status, last_checked, last_status_code, 
               last_response_time_ms, created_at
        FROM monitored_sites 
        ORDER BY sort_order ASC NULLS LAST, name ASC
      `).all();

      // 检查历史数据
      const debugInfo = [];
      for (const site of sites || []) {
        const { results: historyCount } = await env.DB.prepare(
          'SELECT COUNT(*) as count FROM site_status_history WHERE site_id = ?'
        ).bind(site.id).all();

        const { results: recentHistory } = await env.DB.prepare(`
          SELECT timestamp, status, status_code, response_time_ms 
          FROM site_status_history 
          WHERE site_id = ? 
          ORDER BY timestamp DESC 
          LIMIT 5
        `).bind(site.id).all();

        debugInfo.push({
          ...site,
          historyRecordCount: historyCount[0]?.count || 0,
          recentHistory: recentHistory || []
        });
      }

      return createApiResponse({
        totalSites: sites.length,
        sites: debugInfo,
        currentTime: new Date().toISOString(),
        timestamp: Math.floor(Date.now() / 1000)
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取网站调试信息');
    }
  }

  // 获取网站详细在线率历史（管理员和公开API）
  if (path.match(/\/api\/sites\/([^\/]+)\/uptime\/history$/) && method === 'GET') {
    try {
      const siteId = path.split('/')[3];
      
      // 检查权限：管理员或公开网站
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;
      
      if (!isAdmin) {
        // 检查网站是否公开
        const site = await env.DB.prepare(
          'SELECT is_public FROM monitored_sites WHERE id = ?'
        ).bind(siteId).first();
        
        if (!site || !site.is_public) {
          return createErrorResponse('Not Found', '网站不存在或未公开', 404, corsHeaders);
        }
      }
      
      // 解析时间参数
      const url = new URL(request.url);
      const period = url.searchParams.get('period') || '24h';
      
      let hours;
      switch (period) {
        case '24h': hours = 24; break;
        case '3d': hours = 24 * 3; break;
        case '30d': hours = 24 * 30; break;
        case '90d': hours = 24 * 90; break;
        case '180d': hours = 24 * 180; break;
        case '365d': hours = 24 * 365; break;
        default: hours = 24;
      }
      
      const now = Math.floor(Date.now() / 1000);
      const startTime = now - (hours * 60 * 60);
      
      // 获取网站信息
      const siteInfo = await env.DB.prepare(
        'SELECT name, url, added_at FROM monitored_sites WHERE id = ?'
      ).bind(siteId).first();
      
      if (!siteInfo) {
        return createErrorResponse('Not Found', '网站不存在', 404, corsHeaders);
      }
      
      // 获取历史状态变化记录
      const { results } = await env.DB.prepare(`
        SELECT timestamp, status, status_code, response_time_ms, note
        FROM site_status_history
        WHERE site_id = ? AND timestamp >= ?
        ORDER BY timestamp ASC
      `).bind(siteId, startTime).all();
      
      // 分析断开时间段
      const downtimes = [];
      let lastStatus = 'UP';
      let lastTimestamp = startTime;
      let offlineStart = null;
      let offlineStartRecord = null;
      
      // 考虑网站创建时间
      const siteCreatedAt = siteInfo.added_at ? Math.floor(new Date(siteInfo.added_at).getTime() / 1000) : startTime;
      const actualStartTime = Math.max(siteCreatedAt, startTime);
      
      for (const record of results || []) {
        if (lastStatus === 'UP' && record.status === 'DOWN') {
          // 开始断开
          offlineStart = record.timestamp;
          offlineStartRecord = record;
        } else if (lastStatus === 'DOWN' && record.status === 'UP') {
          // 恢复在线
          if (offlineStart && offlineStartRecord) {
            const duration = record.timestamp - offlineStart;
            downtimes.push({
              id: '${siteId}_${offlineStart}', // 用于编辑 删除
              startTime: offlineStart,
              endTime: record.timestamp,
              duration: duration,
              startTimeFormatted: offlineStart,
              endTimeFormatted: record.timestamp ,
              durationFormatted: formatDuration(duration),
              statusCode: offlineStartRecord.status_code || '-',
              responseTimeMs: offlineStartRecord.response_time_ms || '-',
              note: offlineStartRecord.note || ''
            });
          }
        }
        lastStatus = record.status;
        lastTimestamp = record.timestamp;
      }
      
      // 如果当前仍然离线，添加到断开记录
      if (lastStatus === 'offline' && offlineStart && offlineStartRecord) {
        const duration = now - offlineStart;
        downtimes.push({
          id: '${siteId}_${offlineStart}',
          startTime: offlineStart,
          endTime: null, // 当前仍离线
          duration: duration,
          startTimeFormatted: offlineStart,
          endTimeFormatted: '仍离线',
          durationFormatted: formatDuration(duration),
          statusCode: offlineStartRecord.status_code || '-',
          responseTimeMs: offlineStartRecord.response_time_ms || '-',
          note: offlineStartRecord.note || ''
        });
      }
      
      // 计算总体统计
      const uptimeData = await calculateSiteUptime(env, siteId, hours);
      
      return createApiResponse({
        siteId,
        siteName: siteInfo.name,
        siteUrl: siteInfo.url,
        period,
        periodHours: hours,
        actualStartTime: actualStartTime,
        startTimeFormatted: actualStartTime,
        uptime: uptimeData.uptime,
        totalTime: uptimeData.totalTime,
        onlineTime: uptimeData.onlineTime,
        downtimeCount: downtimes.length,
        downtimes: downtimes
      }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '获取网站在线率历史');
    }
  }

  // 更新断开记录备注
  if (path.match(/\/api\/sites\/downtime\/([^\/]+)\/note$/) && method === 'PUT') {
    try {
      const downtimeId = path.split('/')[4];
      const [siteId, timestamp] = downtimeId.split('_');
      
      // 验证权限
      const user = await authenticateAdmin(request, env);
      if (!user) {
        return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
      }
      
      const { note } = await request.json();
      
      // 更新断开记录的备注
      await env.DB.prepare(
        'UPDATE site_status_history SET note = ? WHERE site_id = ? AND timestamp = ? AND status = ?'
      ).bind(note || null, siteId, parseInt(timestamp), 'offline').run();
      
      return createApiResponse({ success: true, message: '备注已更新' }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '更新断开记录备注');
    }
  }

  // 删除断开记录
  if (path.match(/\/api\/sites\/downtime\/([^\/]+)$/) && method === 'DELETE') {
    try {
      const downtimeId = path.split('/')[4];
      const [siteId, timestamp] = downtimeId.split('_');
      
      // 验证权限
      const user = await authenticateAdmin(request, env);
      if (!user) {
        return createErrorResponse('Unauthorized', '需要管理员权限', 401, corsHeaders);
      }
      
      // 删除断开记录
      await env.DB.prepare(
        'DELETE FROM site_status_history WHERE site_id = ? AND timestamp = ? AND status = ?'
      ).bind(siteId, parseInt(timestamp), 'offline').run();
      
      return createApiResponse({ success: true, message: '断开记录已删除' }, 200, corsHeaders);
      
    } catch (error) {
      return handleDbError(error, corsHeaders, '删除断开记录');
    }
  }


  // ==================== 公共API ====================

  // 获取所有监控站点状态（公开，支持管理员和游客模式）
  if (path === '/api/sites/status' && method === 'GET') {
    try {
      // 检查是否为管理员登录状态
      const user = await authenticateRequestOptional(request, env);
      const isAdmin = user !== null;

      let query = `
        SELECT id, name, last_checked, last_status, last_status_code, last_response_time_ms
        FROM monitored_sites
      `;
      if (!isAdmin) {
        query += ` WHERE is_public = 1`;
      }
      query += ` ORDER BY sort_order ASC NULLS LAST, name ASC, id ASC`;

      const { results } = await env.DB.prepare(query).all();
      const sites = results || [];

      // 为每个站点附加24小时历史数据
      const nowSeconds = Math.floor(Date.now() / 1000);
      const twentyFourHoursAgoSeconds = nowSeconds - (24 * 60 * 60);

      for (const site of sites) {
        try {
          const { results: historyResults } = await env.DB.prepare(`
            SELECT timestamp, status, status_code, response_time_ms
            FROM site_status_history
            WHERE site_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
          `).bind(site.id, twentyFourHoursAgoSeconds).all();

          site.history = historyResults || [];
        } catch (historyError) {
          site.history = [];
        }
      }

      return new Response(JSON.stringify({ sites }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
            if (error.message.includes('no such table')) {
                try {
          await env.DB.exec(D1_SCHEMAS.monitored_sites);
          return new Response(JSON.stringify({ sites: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
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
      // 使用统一的缓存查询函数
      const interval = await getVpsReportInterval(env);

      return new Response(JSON.stringify({ interval }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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

      // 清除相关缓存
      configCache.clearKey('monitoring_settings');
      vpsIntervalCache.value = null; // 清除VPS间隔缓存

      return new Response(JSON.stringify({ success: true, interval }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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
      const settings = await configCache.getTelegramConfig(env.DB);

      return new Response(JSON.stringify(
        settings || { bot_token: null, chat_id: null, enable_notifications: 0 }
      ), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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

      // 清除缓存，确保下次获取最新配置
      configCache.clearKey('telegram_config');

      // 发送测试通知（高优先级，立即发送）
      if (enableNotifValue === 1 && bot_token && chat_id) {
        const testMessage = "✅ Telegram通知已在此监控面板激活。这是一条测试消息。";
        if (ctx?.waitUntil) {
          ctx.waitUntil(sendTelegramNotificationOptimized(env.DB, testMessage, 'high'));
        } else {
                    sendTelegramNotificationOptimized(env.DB, testMessage, 'high').catch(e => {
            // 静默处理测试通知错误
          });
        }
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
            return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }

  // ==================== 背景设置API ====================

  // 获取背景设置（公开API - 所有用户可访问）
  if (path === '/api/background-settings' && method === 'GET') {
    try {
      // 查询三个背景配置项
      const { results } = await env.DB.prepare(`
        SELECT key, value FROM app_config
        WHERE key IN ('custom_background_enabled', 'custom_background_url', 'page_opacity')
      `).all();

      // 转换为对象格式
      const settings = {
        enabled: false,
        url: '',
        opacity: 80
      };

      results.forEach(row => {
        switch (row.key) {
          case 'custom_background_enabled':
            settings.enabled = row.value === 'true';
            break;
          case 'custom_background_url':
            settings.url = row.value || '';
            break;
          case 'page_opacity':
            settings.opacity = parseInt(row.value, 10) || 80;
            break;
        }
      });

      return new Response(JSON.stringify(settings), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
            return new Response(JSON.stringify({
        enabled: false,
        url: '',
        opacity: 80
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }



  // 设置背景配置（管理员）
  if (path === '/api/admin/background-settings' && method === 'POST') {
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
      const { enabled, url, opacity } = await request.json();

      // 验证输入参数
      if (typeof enabled !== 'boolean') {
        return new Response(JSON.stringify({
          error: 'Invalid enabled value',
          message: 'enabled必须是布尔值'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (enabled && url) {
        if (typeof url !== 'string' || !url.startsWith('https://')) {
          return new Response(JSON.stringify({
            error: 'Invalid URL format',
            message: '背景图片URL必须以https://开头'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      if (typeof opacity !== 'number' || opacity < 0 || opacity > 100) {
        return new Response(JSON.stringify({
          error: 'Invalid opacity value',
          message: '透明度必须是0-100之间的数字'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // 更新配置到数据库
      await env.DB.batch([
        env.DB.prepare('REPLACE INTO app_config (key, value) VALUES (?, ?)').bind(
          'custom_background_enabled',
          enabled.toString()
        ),
        env.DB.prepare('REPLACE INTO app_config (key, value) VALUES (?, ?)').bind(
          'custom_background_url',
          url || ''
        ),
        env.DB.prepare('REPLACE INTO app_config (key, value) VALUES (?, ?)').bind(
          'page_opacity',
          opacity.toString()
        )
      ]);

      // 清除监控设置缓存（背景设置也在app_config表中）
      configCache.clearKey('monitoring_settings');

      return new Response(JSON.stringify({
        success: true,
        settings: { enabled, url: url || '', opacity }
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (error) {
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
            if (error.message.includes('no such table')) {
                try {
          await env.DB.exec(D1_SCHEMAS.site_status_history);
          return new Response(JSON.stringify({ history: [] }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (createError) {
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

// ==================== Telegram通知（已移至优化版本） ====================

// 旧的单服务器状态检查函数已移除，改为前端状态变化检测

// 旧的VPS离线检查函数已移除，改为前端状态变化检测 + 定时提醒


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
  } catch (error) {
        // 静默处理错误
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
      ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
      newSiteLastNotifiedDownAt = checkTime;

    } else {
      // Site is still down, check if 1-hour interval has passed for resend
      const shouldResend = siteLastNotifiedDownAt === null || (checkTime - siteLastNotifiedDownAt > NOTIFICATION_INTERVAL_SECONDS);
      if (shouldResend) {
        const message = `🔴 网站持续故障: *${siteDisplayName}* 状态 ${newStatus.toLowerCase()} (状态码: ${newStatusCode || '无'}).\n网址: ${url}`;
        ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
        newSiteLastNotifiedDownAt = checkTime;
      }
    }
  } else if (newStatus === 'UP' && ['DOWN', 'TIMEOUT', 'ERROR'].includes(previousStatus)) {
    // Site just came back up
    const message = `✅ 网站恢复: *${siteDisplayName}* 已恢复在线!\n网址: ${url}`;
    ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
    newSiteLastNotifiedDownAt = null; // Clear notification timestamp as site is up
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
  } catch (dbError) {
    // 静默处理数据库更新错误
  }
}

// ==================== 优化版本函数 ====================

// 优化版网站状态检查 - 减少超时时间，使用缓存
async function checkWebsiteStatusOptimized(site, db, ctx) {
  const { id, url, name } = site;
  const startTime = Date.now();
  let newStatus = 'PENDING';
  let newStatusCode = null;
  let newResponseTime = null;

  // 获取当前状态
  let previousStatus = 'PENDING';
  let siteLastNotifiedDownAt = null;

  try {
    const siteDetailsResult = await db.prepare(
      'SELECT last_status, last_notified_down_at FROM monitored_sites WHERE id = ?'
    ).bind(id).first();

    if (siteDetailsResult) {
      previousStatus = siteDetailsResult.last_status || 'PENDING';
      siteLastNotifiedDownAt = siteDetailsResult.last_notified_down_at;
    }
  } catch (error) {
        // 静默处理错误
    }

  const NOTIFICATION_INTERVAL_SECONDS = 1 * 60 * 60; // 1小时

  try {
    // 优化：超时时间从15秒减少到10秒
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000) // 10秒超时
    });

    newResponseTime = Date.now() - startTime;
    newStatusCode = response.status;

    if (response.ok || (response.status >= 300 && response.status < 500)) {
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
    }
  }

  const checkTime = Math.floor(Date.now() / 1000);
  const siteDisplayName = name || url;
  let newSiteLastNotifiedDownAt = siteLastNotifiedDownAt;

  // 通知逻辑保持不变
  if (['DOWN', 'TIMEOUT', 'ERROR'].includes(newStatus)) {
    const isFirstTimeDown = !['DOWN', 'TIMEOUT', 'ERROR'].includes(previousStatus);
    if (isFirstTimeDown) {
      const message = `🔴 网站故障: *${siteDisplayName}* 当前状态 ${newStatus.toLowerCase()} (状态码: ${newStatusCode || '无'}).\n网址: ${url}`;
      ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
      newSiteLastNotifiedDownAt = checkTime;
    } else {
      const shouldResend = siteLastNotifiedDownAt === null || (checkTime - siteLastNotifiedDownAt > NOTIFICATION_INTERVAL_SECONDS);
      if (shouldResend) {
        const message = `🔴 网站持续故障: *${siteDisplayName}* 状态 ${newStatus.toLowerCase()} (状态码: ${newStatusCode || '无'}).\n网址: ${url}`;
        ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
        newSiteLastNotifiedDownAt = checkTime;
      }
    }
  } else if (newStatus === 'UP' && ['DOWN', 'TIMEOUT', 'ERROR'].includes(previousStatus)) {
    const message = `✅ 网站恢复: *${siteDisplayName}* 已恢复在线!\n网址: ${url}`;
    ctx.waitUntil(sendTelegramNotificationOptimized(db, message));
    newSiteLastNotifiedDownAt = null;
  }

  // 批量更新数据库
  try {
    await db.batch([
      db.prepare('UPDATE monitored_sites SET last_checked = ?, last_status = ?, last_status_code = ?, last_response_time_ms = ?, last_notified_down_at = ? WHERE id = ?')
        .bind(checkTime, newStatus, newStatusCode, newResponseTime, newSiteLastNotifiedDownAt, id),
      db.prepare('INSERT INTO site_status_history (site_id, timestamp, status, status_code, response_time_ms) VALUES (?, ?, ?, ?, ?)')
        .bind(id, checkTime, newStatus, newStatusCode, newResponseTime)
    ]);
  } catch (dbError) {
    // 静默处理数据库更新错误
  }
}

// 简化版VPS离线提醒检查 - 只负责持续离线提醒
async function checkVpsOfflineReminder(env, ctx) {
  try {
    const telegramConfig = await configCache.getTelegramConfig(env.DB);

    if (!telegramConfig?.enable_notifications || !telegramConfig.bot_token || !telegramConfig.chat_id) {
      return;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const offlineThreshold = 5 * 60; // 5分钟
    const reminderInterval = 60 * 60; // 1小时

    // 查询持续离线的VPS（已有离线记录且仍然离线）
    const { results: offlineServers } = await env.DB.prepare(`
      SELECT s.id, s.name, s.last_notified_down_at, m.timestamp as last_report
      FROM servers s
      LEFT JOIN metrics m ON s.id = m.server_id
      WHERE s.last_notified_down_at IS NOT NULL
        AND (m.timestamp IS NULL OR m.timestamp < ?)
        AND s.last_notified_down_at < ?
    `).bind(currentTime - offlineThreshold, currentTime - reminderInterval).all();

    for (const server of offlineServers) {
      const serverDisplayName = server.name || server.id;
      const offlineHours = Math.floor((currentTime - server.last_notified_down_at) / 3600);

      const message = `🔴 VPS持续离线: 服务器 *${serverDisplayName}* 已离线${offlineHours}小时（每小时提醒）`;
      ctx.waitUntil(sendTelegramNotificationOptimized(env.DB, message));

      // 更新最后通知时间
      ctx.waitUntil(env.DB.prepare('UPDATE servers SET last_notified_down_at = ? WHERE id = ?')
        .bind(currentTime, server.id).run());
    }

  } catch (error) {
    // 静默处理VPS离线提醒错误
  }
}

// 简化版Telegram通知 - 直接发送
async function sendTelegramNotificationOptimized(db, message, priority = 'normal') {
  try {
    const telegramConfig = await configCache.getTelegramConfig(db);

    if (!telegramConfig?.enable_notifications || !telegramConfig.bot_token || !telegramConfig.chat_id) {
      return;
    }

    const telegramUrl = `https://api.telegram.org/bot${telegramConfig.bot_token}/sendMessage`;
    const payload = {
      chat_id: telegramConfig.chat_id,
      text: message,
      parse_mode: 'Markdown'
    };

    const response = await fetch(telegramUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

  } catch (error) {
    // 静默处理Telegram通知错误
  }
}

// ==================== 数据库维护系统 ====================

// 简洁的数据库维护函数
async function performDatabaseMaintenance(db) {
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60);

  try {
    // 清理30天前的网站状态历史
    await db.prepare(
      'DELETE FROM site_status_history WHERE timestamp < ?'
    ).bind(thirtyDaysAgo).run();

    // 清理30天前的VPS状态历史
    await db.prepare(
      'DELETE FROM vps_status_history WHERE timestamp < ?'
    ).bind(thirtyDaysAgo).run();

    // 清理JWT缓存
    cleanupJWTCache();

  } catch (error) {
    // 静默处理数据库维护错误
  }
}

// ==================== 主函数导出 ====================
// ==================== Vercel Edge Functions 配置 ====================
export const config = { runtime: 'edge' }

// 全局变量
let dbInitialized = false;
let taskCounter = 0;

// ==================== 主函数导出 ====================
export default async function handler(request) {
  // 模拟 env 对象 - 需要通过环境变量获取
  const env = {
    DB: process.env.DATABASE_URL, // 你需要配置数据库连接
    // 其他环境变量...
  };
  
  // 模拟 ctx 对象
  const ctx = {
    waitUntil: (promise) => {
      // Vercel Edge Functions 中可以直接 await
      // 或者使用其他方式处理异步任务
      return promise;
    }
  };

  // 优化：仅在必要时初始化数据库表
  if (!dbInitialized) {
    try {
      await ensureTablesExist(env.DB, env);
      dbInitialized = true;
    } catch (error) {
      // 静默处理数据库初始化失败
      console.log('Database initialization failed:', error.message);
    }
  }

  // 定时刷新VPS批量数据（在每个请求中检查）
  scheduleVpsBatchFlush(env, ctx);
  
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
}

// ==================== 替代定时任务的方案 ====================
// 方案1: 创建单独的API端点来触发定时任务
export async function scheduledTasks(request) {
  // 验证请求来源（可选）
  const authHeader = request.headers.get('authorization');
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const env = {
    DB: process.env.DATABASE_URL,
    // 其他环境变量...
  };

  const ctx = {
    waitUntil: (promise) => promise
  };

  taskCounter++;

  try {
    // 智能数据库初始化 - 仅在必要时执行
    if (!dbInitialized || taskCounter % 10 === 1) {
      await ensureTablesExist(env.DB, env);
      dbInitialized = true;
    }

    // ==================== 网站监控部分 ====================
    const { results: sitesToCheck } = await env.DB.prepare(
      'SELECT id, url, name FROM monitored_sites'
    ).all();

    if (sitesToCheck?.length > 0) {
      // 限制并发数量为5个，优化资源使用
      const siteConcurrencyLimit = 5;
      const sitePromises = [];
      
      for (const site of sitesToCheck) {
        sitePromises.push(checkWebsiteStatusOptimized(site, env.DB, ctx));
        if (sitePromises.length >= siteConcurrencyLimit) {
          await Promise.all(sitePromises);
          sitePromises.length = 0;
        }
      }
      
      if (sitePromises.length > 0) {
        await Promise.all(sitePromises);
      }
    }

    // ==================== VPS离线提醒检查 ====================
    // 每小时执行一次，发送持续离线提醒
    await checkVpsOfflineReminder(env, ctx);

    // ==================== 数据库维护检查 ====================
    // 每天执行一次数据库维护
    if (taskCounter % 1440 === 0) {
      await performDatabaseMaintenance(env.DB);
    }

    // ==================== 实时缓存清理 ====================
    // 每15分钟执行一次实时缓存清理
    if (taskCounter % 15 === 0) {
      cleanupRealtimeCache();
    }

    return new Response(JSON.stringify({ 
      success: true, 
      message: 'Scheduled tasks completed',
      taskCounter 
    }), {
      headers: { 'content-type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: error.message 
    }), {
      status: 500,
      headers: { 'content-type': 'application/json' }
    });
  }
}


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
          }

    // 使用统一的缓存查询函数
    const interval = await getVpsReportInterval(env);
    vpsReportInterval = interval.toString();
  } catch (e) {
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
    '/js/admin.js': () => new Response(getAdminJs(), { headers: { 'Content-Type': 'application/javascript' } }),
    '/favicon.svg': () => new Response(getFaviconSvg(), { headers: { 'Content-Type': 'image/svg+xml' } })
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
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <script>
        // 立即设置主题，避免闪烁
        (function() {
            const theme = localStorage.getItem('vps-monitor-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', theme);
        })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" integrity="sha384-4LISF5TTJX/fLmGSxO53rV4miRxdg84mZsxmO8Rx5jGtp/LbrixFETvWa5a6sESd" crossorigin="anonymous">
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
            background-color: rgba(248, 249, 250, var(--page-opacity, 0.8)); /* Light background for details with transparency */
        }
        .server-details-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .detail-item {
            background-color: rgba(233, 236, 239, var(--page-opacity, 0.8));
            padding: 0.75rem;
            border-radius: 0.25rem;
            border: 1px solid rgba(0, 0, 0, 0.1);
        }

        /* 暗色主题下的详细信息项 */
        [data-bs-theme="dark"] .detail-item {
            background-color: rgba(52, 58, 64, var(--page-opacity, 0.8));
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e0e0e0;
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

        /* Center alignment for front-end monitoring tables */
        /* Front-end server monitoring table headers and data */
        .table > thead > tr > th:nth-child(1), /* 名称 */
        .table > thead > tr > th:nth-child(2), /* 状态 */
        .table > thead > tr > th:nth-child(3), /* CPU */
        .table > thead > tr > th:nth-child(4), /* 内存 */
        .table > thead > tr > th:nth-child(5), /* 硬盘 */
        .table > thead > tr > th:nth-child(6), /* 上传 */
        .table > thead > tr > th:nth-child(7), /* 下载 */
        .table > thead > tr > th:nth-child(8), /* 总上传 */
        .table > thead > tr > th:nth-child(9), /* 总下载 */
        .table > thead > tr > th:nth-child(10), /* 运行时长 */
        .table > thead > tr > th:nth-child(11), /* 最后更新 */
        #serverTableBody tr > td:nth-child(1), /* 名称 */
        #serverTableBody tr > td:nth-child(2), /* 状态 */
        #serverTableBody tr > td:nth-child(3), /* CPU */
        #serverTableBody tr > td:nth-child(4), /* 内存 */
        #serverTableBody tr > td:nth-child(5), /* 硬盘 */
        #serverTableBody tr > td:nth-child(6), /* 上传 */
        #serverTableBody tr > td:nth-child(7), /* 下载 */
        #serverTableBody tr > td:nth-child(8), /* 总上传 */
        #serverTableBody tr > td:nth-child(9), /* 总下载 */
        #serverTableBody tr > td:nth-child(10), /* 运行时长 */
        #serverTableBody tr > td:nth-child(11) { /* 最后更新 */
            text-align: center;
        }

        /* Front-end site monitoring table headers and data */
        .table > thead > tr > th:nth-child(1), /* 名称 (site table) */
        .table > thead > tr > th:nth-child(2), /* 状态 (site table) */
        .table > thead > tr > th:nth-child(3), /* 状态码 (site table) */
        .table > thead > tr > th:nth-child(4), /* 响应时间 (site table) */
        .table > thead > tr > th:nth-child(5), /* 最后检查 (site table) */
        .table > thead > tr > th:nth-child(6), /* 24h记录 (site table) */
        #siteStatusTableBody tr > td:nth-child(1), /* 名称 */
        #siteStatusTableBody tr > td:nth-child(2), /* 状态 */
        #siteStatusTableBody tr > td:nth-child(3), /* 状态码 */
        #siteStatusTableBody tr > td:nth-child(4), /* 响应时间 */
        #siteStatusTableBody tr > td:nth-child(5), /* 最后检查 */
        #siteStatusTableBody tr > td:nth-child(6) { /* 24h记录 */
            text-align: center;
        }

        /* Backend admin tables - center align headers and data columns */
        /* Admin server table headers */
        .table thead tr th:nth-child(2), /* ID */
        .table thead tr th:nth-child(3), /* 名称 */
        .table thead tr th:nth-child(4), /* 描述 */
        .table thead tr th:nth-child(5), /* 状态 */
        .table thead tr th:nth-child(6), /* 最后更新 */
        .table thead tr th:nth-child(9), /* 显示开关 */
        /* Admin server table data */
        #serverTableBody tr > td:nth-child(2), /* ID */
        #serverTableBody tr > td:nth-child(3), /* 名称 */
        #serverTableBody tr > td:nth-child(4), /* 描述 */
        #serverTableBody tr > td:nth-child(5), /* 状态 */
        #serverTableBody tr > td:nth-child(6), /* 最后更新 */
        #serverTableBody tr > td:nth-child(9) { /* 显示开关 */
            text-align: center;
        }

        /* Admin site table headers */
        .table thead tr th:nth-child(2), /* 名称 */
        .table thead tr th:nth-child(4), /* 状态 */
        .table thead tr th:nth-child(5), /* 状态码 */
        .table thead tr th:nth-child(6), /* 响应时间 */
        .table thead tr th:nth-child(7), /* 最后检查 */
        .table thead tr th:nth-child(8), /* 显示开关 */
        /* Admin site table data */
        #siteTableBody tr > td:nth-child(2), /* 名称 */
        #siteTableBody tr > td:nth-child(4), /* 状态 */
        #siteTableBody tr > td:nth-child(5), /* 状态码 */
        #siteTableBody tr > td:nth-child(6), /* 响应时间 */
        #siteTableBody tr > td:nth-child(7), /* 最后检查 */
        #siteTableBody tr > td:nth-child(8) { /* 显示开关 */
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
            background-color: rgba(33, 37, 41, var(--page-opacity, 0.8)); /* Darker details background with transparency */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .detail-item {
            background-color: rgba(52, 58, 64, var(--page-opacity, 0.8)); /* Darker detail item background with transparency */
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e0e0e0; /* Consistent text color */
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
        /* 已移至统一的底部版权样式中 */
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
        /* 通用text-muted主题适配 */
        .text-muted { color: #212529 !important; }
        [data-bs-theme="dark"] .text-muted { color: #ffffff !important; }
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
    <!-- Toast容器 -->
    <div id="toastContainer" class="toast-container"></div>

    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <svg class="me-2" width="32" height="32" viewBox="0 0 32 32">
                    <defs>
                        <radialGradient id="navBg1" cx="0.3" cy="0.3">
                            <stop offset="0%" stop-color="#fff" stop-opacity="0.9"/>
                            <stop offset="100%" stop-color="#0277bd" stop-opacity="0.8"/>
                        </radialGradient>
                        <linearGradient id="navEcg1" x1="0%" x2="100%">
                            <stop offset="0%" stop-color="#f08"/>
                            <stop offset="50%" stop-color="#0f8"/>
                            <stop offset="100%" stop-color="#80f"/>
                        </linearGradient>
                    </defs>
                    <circle cx="16" cy="16" r="15" fill="url(#navBg1)" stroke="#0277bd" stroke-width="1.5"/>
                    <circle cx="16" cy="16" r="13" fill="none" stroke="#fff" stroke-width="1" opacity="0.4"/>
                    <line x1="4" y1="16" x2="28" y2="16" stroke="#b3e5fc" stroke-width="0.5" opacity="0.8"/>
                    <path id="navP1" d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="url(#navEcg1)" stroke-width="2.8"/>
                    <path d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="#fff" stroke-width="1.2" opacity="0.7"/>
                    <circle r="1.5" fill="#fff">
                        <animateMotion dur="2s" repeatCount="indefinite">
                            <mpath href="#navP1"/>
                        </animateMotion>
                    </circle>
                    <circle cx="16" cy="16" r="8" fill="none" stroke="#f08" stroke-width="0.5" opacity="0.6">
                        <animate attributeName="r" values="8;12;8" dur="3s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite"/>
                    </circle>
                </svg>
                VPS监控面板
            </a>
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

    <!-- 单一主卡片容器 -->
    <div class="container mt-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <!-- 服务器监控部分 -->
                <div class="mb-4">
                    <h5 class="card-title mb-3">
                        <i class="bi bi-server me-2"></i>服务器监控
                    </h5>

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
                                    <th>在线率</th>
                                    <th>最后更新</th>
                                </tr>
                            </thead>
                            <tbody id="serverTableBody">
                                <tr>
                                    <td colspan="12" class="text-center">加载中...</td>
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

                <!-- 分隔线 -->
                <hr class="my-4">

                <!-- 网站监控部分 -->
                <div>
                    <h5 class="card-title mb-3">
                        <i class="bi bi-globe me-2"></i>网站在线状态
                    </h5>

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
                                    <th>在线率</th>
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
            </div>
        </div>
    </div>
    <!-- End Website Status Section -->

    <!-- Server Detailed row template (hidden by default) -->
    <template id="serverDetailsTemplate">
        <tr class="server-details-row d-none">
            <td colspan="12">
                <div class="server-details-content">
                    <!-- Detailed metrics will be populated here by JavaScript -->
                </div>
            </td>
        </tr>
    </template>

    <footer class="footer fixed-bottom py-2 bg-light border-top">
        <div class="container text-center">
            <span class="text-muted small">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github"></i>
            </a>
        </div>
    </footer>

    <!-- 在线率历史模态框 -->
    <div class="modal fade" id="uptimeHistoryModal" tabindex="-1" aria-labelledby="uptimeHistoryModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="uptimeHistoryModalLabel">
                        <i class="bi bi-graph-up me-2"></i>在线率历史详情
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="uptimeHistoryContent">
                        <div class="text-center">
                            <div class="spinner-border" role="status">
                                <span class="visually-hidden">加载中...</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <div class="btn-group" role="group" id="uptimePeriodButtons">
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period24h" value="24h" checked>
                        <label class="btn btn-outline-primary" for="period24h">24小时</label>
                        
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period3d" value="3d">
                        <label class="btn btn-outline-primary" for="period3d">3天</label>
                        
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period30d" value="30d">
                        <label class="btn btn-outline-primary" for="period30d">1个月</label>
                        
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period90d" value="90d">
                        <label class="btn btn-outline-primary" for="period90d">3个月</label>
                        
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period180d" value="180d">
                        <label class="btn btn-outline-primary" for="period180d">6个月</label>
                        
                        <input type="radio" class="btn-check" name="uptimePeriod" id="period365d" value="365d">
                        <label class="btn btn-outline-primary" for="period365d">1年</label>
                    </div>
                    <button type="button" class="btn btn-secondary ms-auto" data-bs-dismiss="modal">关闭</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 网站在线率历史模态框 -->
    <div class="modal fade" id="siteUptimeHistoryModal" tabindex="-1" aria-labelledby="siteUptimeHistoryModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="siteUptimeHistoryModalLabel">
                        <i class="bi bi-globe me-2"></i>网站在线率历史详情
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="siteUptimeHistoryContent">
                        <div class="text-center">
                            <div class="spinner-border" role="status">
                                <span class="visually-hidden">加载中...</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <div class="btn-group" role="group">
                        <input type="radio" class="btn-check" name="siteUptimePeriod" id="sitePeriod24h" value="24h" checked>
                        <label class="btn btn-outline-primary" for="sitePeriod24h">24小时</label>
                        
                        <input type="radio" class="btn-check" name="siteUptimePeriod" id="sitePeriod7d" value="7d">
                        <label class="btn btn-outline-primary" for="sitePeriod7d">7天</label>
                        
                        <input type="radio" class="btn-check" name="siteUptimePeriod" id="sitePeriod30d" value="30d">
                        <label class="btn btn-outline-primary" for="sitePeriod30d">30天</label>
                    </div>
                    <button type="button" class="btn btn-secondary ms-auto" data-bs-dismiss="modal">关闭</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
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
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <script>
        // 立即设置主题，避免闪烁
        (function() {
            const theme = localStorage.getItem('vps-monitor-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', theme);
        })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" integrity="sha384-4LISF5TTJX/fLmGSxO53rV4miRxdg84mZsxmO8Rx5jGtp/LbrixFETvWa5a6sESd" crossorigin="anonymous">
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
            background-color: rgba(248, 249, 250, var(--page-opacity, 0.8)); /* Light background for details with transparency */
        }

        /* 暗色主题下的服务器详细信息行 */
        [data-bs-theme="dark"] .server-details-row td {
            background-color: rgba(33, 37, 41, var(--page-opacity, 0.8));
        }
        .server-details-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .detail-item {
            background-color: rgba(233, 236, 239, var(--page-opacity, 0.8));
            padding: 0.75rem;
            border-radius: 0.25rem;
            border: 1px solid rgba(0, 0, 0, 0.1);
        }

        /* 暗色主题下的详细信息项 */
        [data-bs-theme="dark"] .detail-item {
            background-color: rgba(52, 58, 64, var(--page-opacity, 0.8));
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e0e0e0;
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
            background-color: rgba(33, 37, 41, var(--page-opacity, 0.8)); /* Darker details background with transparency */
            border-top: 1px solid #495057;
        }
        [data-bs-theme="dark"] .detail-item {
            background-color: rgba(52, 58, 64, var(--page-opacity, 0.8)); /* Darker detail item background with transparency */
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e0e0e0; /* Consistent text color */
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
        /* 已移至统一的底部版权样式中 */
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
        /* 已移至统一的通用text-muted样式中 */
        [data-bs-theme="dark"] span[style*="color: #000"] { /* For inline styled black text */
            color: #ffffff !important; /* Change to white */
        }
    </style>
</head>
<body>
    <!-- Toast容器 -->
    <div id="toastContainer" class="toast-container"></div>

    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <svg class="me-2" width="32" height="32" viewBox="0 0 32 32">
                    <defs>
                        <radialGradient id="navBg2" cx="0.3" cy="0.3">
                            <stop offset="0%" stop-color="#fff" stop-opacity="0.9"/>
                            <stop offset="100%" stop-color="#0277bd" stop-opacity="0.8"/>
                        </radialGradient>
                        <linearGradient id="navEcg2" x1="0%" x2="100%">
                            <stop offset="0%" stop-color="#f08"/>
                            <stop offset="50%" stop-color="#0f8"/>
                            <stop offset="100%" stop-color="#80f"/>
                        </linearGradient>
                    </defs>
                    <circle cx="16" cy="16" r="15" fill="url(#navBg2)" stroke="#0277bd" stroke-width="1.5"/>
                    <circle cx="16" cy="16" r="13" fill="none" stroke="#fff" stroke-width="1" opacity="0.4"/>
                    <line x1="4" y1="16" x2="28" y2="16" stroke="#b3e5fc" stroke-width="0.5" opacity="0.8"/>
                    <path id="navP2" d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="url(#navEcg2)" stroke-width="2.8"/>
                    <path d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="#fff" stroke-width="1.2" opacity="0.7"/>
                    <circle r="1.5" fill="#fff">
                        <animateMotion dur="2s" repeatCount="indefinite">
                            <mpath href="#navP2"/>
                        </animateMotion>
                    </circle>
                    <circle cx="16" cy="16" r="8" fill="none" stroke="#f08" stroke-width="0.5" opacity="0.6">
                        <animate attributeName="r" values="8;12;8" dur="3s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite"/>
                    </circle>
                </svg>
                VPS监控面板
            </a>
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

    <footer class="footer fixed-bottom py-2 bg-light border-top">
        <div class="container text-center">
            <span class="text-muted small">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github"></i>
            </a>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
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
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <script>
        // 立即设置主题，避免闪烁
        (function() {
            const theme = localStorage.getItem('vps-monitor-theme') || 'light';
            document.documentElement.setAttribute('data-bs-theme', theme);
        })();
    </script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet" integrity="sha384-4LISF5TTJX/fLmGSxO53rV4miRxdg84mZsxmO8Rx5jGtp/LbrixFETvWa5a6sESd" crossorigin="anonymous">
    <link href="/css/style.css" rel="stylesheet">
</head>
<body>
    <!-- Toast容器 -->
    <div id="toastContainer" class="toast-container"></div>

    <nav class="navbar navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <svg class="me-2" width="32" height="32" viewBox="0 0 32 32">
                    <defs>
                        <radialGradient id="navBg3" cx="0.3" cy="0.3">
                            <stop offset="0%" stop-color="#fff" stop-opacity="0.9"/>
                            <stop offset="100%" stop-color="#0277bd" stop-opacity="0.8"/>
                        </radialGradient>
                        <linearGradient id="navEcg3" x1="0%" x2="100%">
                            <stop offset="0%" stop-color="#f08"/>
                            <stop offset="50%" stop-color="#0f8"/>
                            <stop offset="100%" stop-color="#80f"/>
                        </linearGradient>
                    </defs>
                    <circle cx="16" cy="16" r="15" fill="url(#navBg3)" stroke="#0277bd" stroke-width="1.5"/>
                    <circle cx="16" cy="16" r="13" fill="none" stroke="#fff" stroke-width="1" opacity="0.4"/>
                    <line x1="4" y1="16" x2="28" y2="16" stroke="#b3e5fc" stroke-width="0.5" opacity="0.8"/>
                    <path id="navP3" d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="url(#navEcg3)" stroke-width="2.8"/>
                    <path d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="#fff" stroke-width="1.2" opacity="0.7"/>
                    <circle r="1.5" fill="#fff">
                        <animateMotion dur="2s" repeatCount="indefinite">
                            <mpath href="#navP3"/>
                        </animateMotion>
                    </circle>
                    <circle cx="16" cy="16" r="8" fill="none" stroke="#f08" stroke-width="0.5" opacity="0.6">
                        <animate attributeName="r" values="8;12;8" dur="3s" repeatCount="indefinite"/>
                        <animate attributeName="opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite"/>
                    </circle>
                </svg>
                VPS监控面板
            </a>
            <div class="d-flex align-items-center flex-wrap">
                <a class="nav-link text-light me-2" href="/" style="white-space: nowrap;">返回首页</a>

                <!-- PC端直接显示的按钮 -->
                <a href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="btn btn-outline-light btn-sm me-2 desktop-only" title="GitHub Repository">
                    <i class="bi bi-github"></i>
                </a>

                <button id="themeToggler" class="btn btn-outline-light btn-sm me-2" title="切换主题">
                    <i class="bi bi-moon-stars-fill"></i>
                </button>

                <button class="btn btn-outline-light btn-sm me-1 desktop-only" id="changePasswordBtnDesktop" title="修改密码">
                    <i class="bi bi-key"></i>
                </button>

                <!-- 移动端下拉菜单 -->
                <div class="dropdown me-1 mobile-only">
                    <button class="btn btn-outline-light btn-sm dropdown-toggle" type="button" id="adminMenuDropdown" data-bs-toggle="dropdown" aria-expanded="false" title="更多选项">
                        <i class="bi bi-three-dots"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="adminMenuDropdown">
                        <li><a class="dropdown-item" href="https://github.com/kadidalax/cf-vps-monitor" target="_blank" rel="noopener noreferrer">
                            <i class="bi bi-github me-2"></i>GitHub
                        </a></li>
                        <li><button class="dropdown-item" id="changePasswordBtn">
                            <i class="bi bi-key me-2"></i>修改密码
                        </button></li>
                    </ul>
                </div>

                <button id="logoutBtn" class="btn btn-outline-light btn-sm" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">退出</button>
            </div>
        </div>
    </nav>

    <!-- 单一主管理卡片容器 -->
    <div class="container mt-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <!-- 服务器管理部分 -->
                <div class="mb-4">
                    <div class="admin-header-row mb-3">
                        <div class="admin-header-title">
                            <h5 class="card-title mb-0">
                                <i class="bi bi-server me-2"></i>服务器管理
                            </h5>
                        </div>
                        <div class="admin-header-content">
                            <!-- VPS Data Update Frequency Form -->
                            <form id="globalSettingsFormPartial" class="admin-settings-form">
                                <div class="settings-group">
                                    <label for="vpsReportInterval" class="form-label">VPS数据更新频率 (秒):</label>
                                    <div class="input-group">
                                        <input type="number" class="form-control form-control-sm" id="vpsReportInterval" placeholder="例如: 60" min="1" style="width: 100px;">
                                        <button type="button" id="saveVpsReportIntervalBtn" class="btn btn-info btn-sm">保存频率</button>
                                    </div>
                                </div>
                            </form>

                            <!-- Action Buttons Group -->
                            <div class="admin-actions-group">
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
                                
                                <!-- Export/Import Buttons -->
                                <div class="btn-group ms-2">
                                    <button id="exportServersBtn" class="btn btn-outline-success">
                                        <i class="bi bi-download"></i> 导出
                                    </button>
                                    <button id="importServersBtn" class="btn btn-outline-info">
                                        <i class="bi bi-upload"></i> 导入
                                    </button>
                                    <button id="initUptimeBtn" class="btn btn-outline-warning">
                                        <i class="bi bi-arrow-clockwise"></i> 初始化在线率
                                    </button>
                                </div>
                                
                                <!-- Hidden file input for import -->
                                <input type="file" id="serverImportFile" accept=".json" style="display: none;">
                            </div>
                        </div>
                    </div>



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
                                    <th>显示 <i class="bi bi-question-circle text-muted" data-bs-toggle="tooltip" data-bs-placement="top" data-bs-title="是否对游客展示此服务器"></i></th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="serverTableBody">
                                <tr>
                                    <td colspan="12" class="text-center">加载中...</td>
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

                <!-- 分隔线 -->
                <hr class="my-4">

                <!-- 网站监控管理部分 -->
                <div>
                    <div class="admin-header-row mb-3">
                        <div class="admin-header-title">
                            <h5 class="card-title mb-0">
                                <i class="bi bi-globe me-2"></i>网站监控管理
                            </h5>
                        </div>
                        <div class="admin-header-content">
                            <!-- Action Buttons Group - 桌面端隐藏，移动端显示居中按钮 -->
                            <div class="admin-actions-group desktop-only">
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
                                
                                <!-- Export/Import Buttons -->
                                <div class="btn-group ms-2">
                                    <button id="exportSitesBtn" class="btn btn-outline-success">
                                        <i class="bi bi-download"></i> 导出
                                    </button>
                                    <button id="importSitesBtn" class="btn btn-outline-info">
                                        <i class="bi bi-upload"></i> 导入
                                    </button>
                                </div>
                                
                                <!-- Hidden file input for import -->
                                <input type="file" id="siteImportFile" accept=".json" style="display: none;">
                            </div>
                        </div>
                    </div>


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
                                    <th>显示 <i class="bi bi-question-circle text-muted" data-bs-toggle="tooltip" data-bs-placement="top" data-bs-title="是否对游客展示此网站"></i></th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="siteTableBody">
                                <tr>
                                    <td colspan="9" class="text-center">加载中...</td>
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

                <!-- 分隔线 -->
                <hr class="my-4">

                <!-- Telegram 通知设置部分 -->
                <div>
                    <h5 class="card-title mb-3">
                        <i class="bi bi-telegram me-2"></i>Telegram 通知设置
                    </h5>



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

                <!-- 分隔线 -->
                <hr class="my-4">

                <!-- 背景设置部分 -->
                <div>
                    <h5 class="card-title mb-3">
                        <i class="bi bi-image me-2"></i>背景设置
                    </h5>



                    <form id="backgroundSettingsForm">
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" id="enableCustomBackground">
                            <label class="form-check-label" for="enableCustomBackground">
                                启用自定义背景
                            </label>
                        </div>
                        <div class="mb-3">
                            <label for="backgroundImageUrl" class="form-label">背景图片URL</label>
                            <input type="url" class="form-control" id="backgroundImageUrl" placeholder="请输入背景图片URL (必须以https://开头)">
                            <div class="form-text">建议使用高质量图片，支持JPG、PNG格式</div>
                        </div>
                        <div class="mb-3">
                            <label for="pageOpacity" class="form-label">页面透明度: <span id="opacityValue">80</span>%</label>
                            <input type="range" class="form-range" id="pageOpacity" min="0" max="100" value="80" step="1">
                            <div class="form-text">调整页面元素的透明度，数值越小越透明</div>
                        </div>
                        <button type="button" id="saveBackgroundSettingsBtn" class="btn btn-info">保存背景设置</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

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

                        <div class="mb-3">
                            <label for="vpsRealApi" class="form-label">实时监控vps api（ http://IP:8999）</label>
                            <input type="text" class="form-control" id="vpsRealApi"   >
                        </div>
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

    <footer class="footer fixed-bottom py-2 bg-light border-top">
        <div class="container text-center">
            <span class="text-muted small">VPS监控面板 &copy; 2025</span>
            <a href="https://github.com/fanbang/cf-vps-monitor" target="_blank" rel="noopener noreferrer" class="ms-3 text-muted" title="GitHub Repository">
                <i class="bi bi-github"></i>
            </a>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
    <script src="/js/admin.js"></script>
</body>
</html>`;
}

function getFaviconSvg() {
  return `<svg width="32" height="32" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <radialGradient id="bg" cx="0.3" cy="0.3">
      <stop offset="0%" stop-color="#fff" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#0277bd" stop-opacity="0.8"/>
    </radialGradient>
    <linearGradient id="ecg" x1="0%" x2="100%">
      <stop offset="0%" stop-color="#f08"/>
      <stop offset="50%" stop-color="#0f8"/>
      <stop offset="100%" stop-color="#80f"/>
    </linearGradient>
  </defs>
  <circle cx="16" cy="16" r="15" fill="url(#bg)" stroke="#0277bd" stroke-width="1.5"/>
  <circle cx="16" cy="16" r="13" fill="none" stroke="#fff" stroke-width="1" opacity="0.4"/>
  <line x1="4" y1="16" x2="28" y2="16" stroke="#b3e5fc" stroke-width="0.5" opacity="0.8"/>
  <path id="p" d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="url(#ecg)" stroke-width="2.8"/>
  <path d="M4 16L8 16L9 15L10 17L11 14L12 18L13 10L14 22L15 16L28 16" fill="none" stroke="#fff" stroke-width="1.2" opacity="0.7"/>
  <circle r="1.5" fill="#fff">
    <animateMotion dur="2s" repeatCount="indefinite">
      <mpath href="#p"/>
    </animateMotion>
  </circle>
  <circle cx="16" cy="16" r="8" fill="none" stroke="#f08" stroke-width="0.5" opacity="0.6">
    <animate attributeName="r" values="8;12;8" dur="3s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.6;0;0.6" dur="3s" repeatCount="indefinite"/>
  </circle>
</svg>`;
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

    /* 移动端隐藏桌面端按钮 */
    .desktop-only {
        display: none !important;
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

    /* 移动端导航栏下拉菜单优化 - 精简版 */
    .dropdown-menu {
        font-size: 0.875rem;
        min-width: 150px;
        z-index: 10000 !important; /* 统一使用最高层级 */
        position: absolute !important; /* 使用absolute定位确保正确显示 */
        /* 移除position: fixed，让Bootstrap自动处理定位 */
    }

    /* 确保导航栏有合适的层级但不创建层叠上下文 */
    .navbar {
        position: relative;
        z-index: 1000; /* 给导航栏一个中等层级 */
    }

    .navbar .dropdown-item {
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
    }

    .navbar .dropdown-item i {
        width: 1.2rem;
    }

    /* 移动端管理区域标题行优化 */
    .admin-header-row {
        display: flex;
        flex-direction: column;
        gap: 0.75rem; /* 减少移动端间隔 */
    }

    .admin-header-title h2 {
        font-size: 1.5rem;
        margin-bottom: 0;
    }

    .admin-header-content {
        display: flex;
        flex-direction: column;
        gap: 0.5rem; /* 减少移动端间隔 */
    }

    .admin-settings-form {
        order: 2; /* 设置表单在移动端显示在按钮组下方 */
    }

    .admin-actions-group {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        order: 1; /* 按钮组在移动端显示在上方 */
    }

    .settings-group {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .settings-group .form-label {
        font-size: 0.875rem;
        margin-bottom: 0;
        font-weight: 500;
    }

    .settings-group .input-group {
        max-width: 250px;
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

/* 桌面端隐藏卡片容器和移动端菜单 */
@media (min-width: 769px) {
    .mobile-card-container {
        display: none !important;
    }

    .mobile-only {
        display: none !important;
    }
}

    /* 桌面端管理区域标题行样式 */
    .admin-header-row {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 0.75rem; /* 减少桌面端间隔 */
    }

    .admin-header-title {
        flex: 0 0 auto;
    }

    .admin-header-content {
        display: flex;
        align-items: center;
        gap: 1rem;
        flex: 1 1 auto;
        justify-content: flex-end;
    }

    .admin-settings-form {
        order: 1;
        margin-right: auto; /* 推送到左侧 */
    }

    .admin-actions-group {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        order: 2;
    }

    .settings-group {
        display: flex;
        flex-direction: row;
        align-items: center;
        gap: 0.5rem;
    }

    .settings-group .form-label {
        margin-bottom: 0;
        white-space: nowrap;
        font-size: 0.875rem;
    }
}

/* 单一卡片布局样式 */
.card.shadow-sm {
    border: none;
    box-shadow: 0 0.125rem 0.5rem rgba(0, 0, 0, 0.1) !important;
}

.card-title {
    color: var(--bs-primary);
    font-weight: 600;
}

.card-title i {
    color: var(--bs-primary);
}

/* 分隔线样式 */
hr.my-4 {
    border-color: var(--bs-border-color-translucent);
    opacity: 0.5;
}

/* 暗色主题下的单一卡片样式 */
[data-bs-theme="dark"] .card.shadow-sm {
    background-color: var(--bs-dark);
    box-shadow: 0 0.125rem 0.5rem rgba(0, 0, 0, 0.3) !important;
}

[data-bs-theme="dark"] .card-title {
    color: #86b7fe;
}

[data-bs-theme="dark"] .card-title i {
    color: #86b7fe;
}

/* VPS监控面板标题 - 蓝色加粗 */
.navbar-brand {
    color: var(--bs-primary) !important;
    font-weight: 600 !important;
}
[data-bs-theme="dark"] .navbar-brand {
    color: #86b7fe !important;
}

/* 导航栏主题跟随 - 精简版 */
[data-bs-theme="light"] .navbar { background-color: #f8f9fa !important; }
[data-bs-theme="dark"] .navbar { background-color: #212529 !important; }

/* 导航栏文字主题跟随 */
[data-bs-theme="light"] .navbar .nav-link, [data-bs-theme="light"] .navbar a { color: #212529 !important; }
[data-bs-theme="dark"] .navbar .nav-link, [data-bs-theme="dark"] .navbar a { color: #ffffff !important; }

/* 导航栏按钮主题跟随 */
[data-bs-theme="light"] .navbar .btn-outline-light { border-color: #212529 !important; color: #212529 !important; }
[data-bs-theme="dark"] .navbar .btn-outline-light { border-color: #ffffff !important; color: #ffffff !important; }

/* 导航栏图标主题跟随 */
[data-bs-theme="light"] .navbar i { color: #212529 !important; }
[data-bs-theme="dark"] .navbar i { color: #ffffff !important; }

/* 底部版权信息 - 主题跟随调大 */
.footer .text-muted { font-size: 0.95rem !important; font-weight: 500; }
.footer a.text-muted { font-size: 1.1rem !important; }
.footer .text-muted { color: #212529 !important; }
[data-bs-theme="dark"] .footer .text-muted { color: #ffffff !important; }

[data-bs-theme="dark"] hr.my-4 {
    border-color: rgba(255, 255, 255, 0.2);
}

/* 固定底部页脚样式 */
body {
    padding-bottom: 60px; /* 为固定页脚留出空间 */
}

.footer.fixed-bottom {
    height: 35px;
    background-color: var(--bs-light) !important;
    border-top: 1px solid var(--bs-border-color);
    display: flex;
    align-items: center;
}

/* 暗色主题下的页脚 */
[data-bs-theme="dark"] .footer.fixed-bottom {
    background-color: var(--bs-dark) !important;
    border-top-color: var(--bs-border-color);
}

/* 移动端卡片样式 */
.mobile-card-container {
    display: none; /* 默认隐藏，通过媒体查询控制 */
    position: relative;
    z-index: 0; /* 降低容器层级，确保下拉菜单在上方 */
}

.mobile-server-card, .mobile-site-card {
    background: var(--bs-card-bg, #fff);
    border: 1px solid var(--bs-border-color, rgba(0,0,0,.125));
    border-radius: 0.5rem;
    margin-bottom: 0.75rem;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    overflow: hidden;
    transition: box-shadow 0.15s ease-in-out, transform 0.15s ease-in-out;
    position: relative;
    z-index: 0; /* 降低卡片层级，确保下拉菜单在上方 */
}

@media (max-width: 768px) {
    .mobile-server-card:hover, .mobile-site-card:hover {
        box-shadow: 0 0.25rem 0.5rem rgba(0, 0, 0, 0.1);
    }
}

.mobile-card-header {
    padding: 0.75rem;
    background-color: var(--bs-card-cap-bg, rgba(0,0,0,.03));
    border-bottom: 1px solid var(--bs-border-color, rgba(0,0,0,.125));
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: relative;
    z-index: 0; /* 降低卡片头部层级，确保下拉菜单在上方 */
}

.mobile-card-header-left {
    flex: 0 0 auto;
}

.mobile-card-header-right {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
    font-size: 0.875rem;
}

.mobile-card-footer {
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--bs-border-color, rgba(0,0,0,.125));
    font-size: 0.875rem;
    color: var(--bs-secondary);
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
    .mobile-history-container .history-bar-container {
        height: 1.5rem;
        border-radius: 0.25rem;
        overflow: hidden;
        display: flex;
        width: 100%;
        gap: 1px;
    }

    .mobile-history-container .history-bar {
        flex: 1;
        min-width: 0;
        border-radius: 1px;
        height: 100%;
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
    }

    .mobile-card-body .btn:active {
        opacity: 0.8;
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

    /* 移动端管理页面按钮优化 */
    .admin-actions-group .btn {
        font-size: 0.875rem;
        padding: 0.5rem 0.75rem;
        border-radius: 0.375rem;
        transition: all 0.2s ease-in-out;
    }

    .admin-actions-group .btn:active {
        transform: scale(0.95);
    }

    .admin-actions-group .dropdown-toggle {
        min-width: auto;
    }



    /* 移动端卡片间距优化 */
    .mobile-server-card, .mobile-site-card {
        margin-bottom: 1rem;
    }

    .mobile-card-body {
        padding: 0.75rem;
    }

    .mobile-card-row {
        padding: 0.375rem 0;
        border-bottom: 1px solid var(--bs-border-color-translucent, rgba(0,0,0,.08));
    }

    .mobile-card-row:last-child {
        border-bottom: none;
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

/* ==================== 自定义背景和透明度控制系统 ==================== */

/* CSS变量定义 */
:root {
    --custom-background-url: '';
    --page-opacity: 0.8;
    --text-contrast-light: rgba(0, 0, 0, 0.87);
    --text-contrast-dark: rgba(255, 255, 255, 0.87);
    --background-overlay-light: rgba(255, 255, 255, 0.9);
    --background-overlay-dark: rgba(18, 18, 18, 0.9);
}

/* 背景图片显示 */
body.custom-background-enabled::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-image: var(--custom-background-url);
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    background-attachment: fixed;
    z-index: -1;
    opacity: 1;
}

/* 启用自定义背景时的页面元素透明度调整 */
body.custom-background-enabled .navbar {
    background-color: rgba(248, 249, 250, var(--page-opacity)) !important;
    /* 移除导航栏的backdrop-filter，避免影响下拉菜单层级 */
    /* backdrop-filter: blur(10px); */
    /* -webkit-backdrop-filter: blur(10px); */
}

body.custom-background-enabled .card {
    background-color: rgba(255, 255, 255, var(--page-opacity)) !important;
    /* 移除大卡片的backdrop-filter，避免创建层叠上下文影响下拉菜单 */
    /* backdrop-filter: blur(5px); */
    /* -webkit-backdrop-filter: blur(5px); */
    border: 1px solid rgba(0, 0, 0, 0.125);
}

body.custom-background-enabled .card-header {
    background-color: rgba(0, 0, 0, calc(0.03 * var(--page-opacity))) !important;
    border-bottom: 1px solid rgba(0, 0, 0, calc(0.125 * var(--page-opacity)));
}

body.custom-background-enabled .modal-content {
    background-color: rgba(255, 255, 255, var(--page-opacity)) !important;
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
}

body.custom-background-enabled .footer {
    background-color: rgba(248, 249, 250, var(--page-opacity)) !important;
    backdrop-filter: blur(5px);
    -webkit-backdrop-filter: blur(5px);
}

/* 表格透明度调整 - 避免与卡片背景叠加 */
body.custom-background-enabled .table {
    background-color: transparent !important;
}

body.custom-background-enabled .table th {
    background-color: transparent !important;
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
}

body.custom-background-enabled .table td {
    background-color: transparent !important;
}

/* 输入框完全透明化 - 方案A */
body.custom-background-enabled .form-control {
    background-color: transparent !important;
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
    border: 1px solid rgba(0, 0, 0, 0.15) !important;
}

body.custom-background-enabled .form-control:focus {
    background-color: transparent !important;
    border: 1px solid rgba(13, 110, 253, 0.6) !important;
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.15) !important;
}

/* 按钮透明度调整 */
body.custom-background-enabled .btn {
    backdrop-filter: blur(3px);
    -webkit-backdrop-filter: blur(3px);
}

/* 滑块完全透明化 - 完整重置 */
body.custom-background-enabled .form-range {
    -webkit-appearance: none !important;
    appearance: none !important;
    background: transparent !important;
    outline: none !important;
}

/* WebKit浏览器 (Chrome, Safari) */
body.custom-background-enabled .form-range::-webkit-slider-track {
    -webkit-appearance: none !important;
    appearance: none !important;
    background: transparent !important;
    border: 1px solid rgba(0, 0, 0, 0.15) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    outline: none !important;
    margin: 0 !important;
    padding: 0 !important;
    box-sizing: border-box !important;
}

body.custom-background-enabled .form-range::-webkit-slider-runnable-track {
    -webkit-appearance: none !important;
    background: transparent !important;
    border: 1px solid rgba(0, 0, 0, 0.15) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
}

/* Firefox */
body.custom-background-enabled .form-range::-moz-range-track {
    background: transparent !important;
    border: 1px solid rgba(0, 0, 0, 0.15) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    outline: none !important;
}

body.custom-background-enabled .form-range::-moz-range-progress {
    background: transparent !important;
    height: 6px !important;
    border-radius: 3px !important;
}

/* 滑块按钮 - 垂直居中对齐 */
body.custom-background-enabled .form-range::-webkit-slider-thumb {
    -webkit-appearance: none !important;
    appearance: none !important;
    background-color: rgba(13, 110, 253, 0.8) !important;
    border: 1px solid rgba(0, 0, 0, 0.1) !important;
    width: 20px !important;
    height: 20px !important;
    border-radius: 50% !important;
    cursor: pointer !important;
    margin-top: -7px !important;
    box-sizing: border-box !important;
}

body.custom-background-enabled .form-range::-moz-range-thumb {
    background-color: rgba(13, 110, 253, 0.8) !important;
    border: 1px solid rgba(0, 0, 0, 0.1) !important;
    width: 20px !important;
    height: 20px !important;
    border-radius: 50% !important;
    cursor: pointer !important;
    box-shadow: none !important;
    margin-top: -8px !important;
    box-sizing: border-box !important;
}

/* 下拉菜单透明度调整 - 确保最高层级显示 */
body.custom-background-enabled .dropdown-menu {
    background-color: rgba(255, 255, 255, var(--page-opacity)) !important;
    /* 移除backdrop-filter避免创建层叠上下文，确保z-index正常工作 */
    /* backdrop-filter: blur(5px); */
    /* -webkit-backdrop-filter: blur(5px); */
}

/* 移动端卡片透明度调整 - 移除backdrop-filter避免创建层叠上下文 */
body.custom-background-enabled .mobile-server-card,
body.custom-background-enabled .mobile-site-card {
    background-color: rgba(255, 255, 255, var(--page-opacity)) !important;
    /* backdrop-filter: blur(5px); 注释掉以避免创建层叠上下文遮挡下拉菜单 */
    /* -webkit-backdrop-filter: blur(5px); */
}

body.custom-background-enabled .mobile-card-header {
    background-color: rgba(0, 0, 0, calc(0.03 * var(--page-opacity))) !important;
}

/* 表格条纹和悬停效果 - 轻微背景色，不叠加透明度 */
body.custom-background-enabled .table-striped > tbody > tr:nth-of-type(odd) > * {
    background-color: rgba(0, 0, 0, 0.02) !important;
}

body.custom-background-enabled .table-hover > tbody > tr:hover > * {
    background-color: rgba(0, 0, 0, 0.04) !important;
}

/* 暗色主题下的自定义背景样式 */
[data-bs-theme="dark"] body.custom-background-enabled .navbar {
    background-color: rgba(30, 30, 30, var(--page-opacity)) !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .card {
    background-color: rgba(30, 30, 30, var(--page-opacity)) !important;
    border-color: rgba(51, 51, 51, var(--page-opacity));
}

[data-bs-theme="dark"] body.custom-background-enabled .card-header {
    background-color: rgba(42, 42, 42, var(--page-opacity)) !important;
    border-bottom-color: rgba(51, 51, 51, var(--page-opacity));
}

[data-bs-theme="dark"] body.custom-background-enabled .modal-content {
    background-color: rgba(30, 30, 30, var(--page-opacity)) !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .footer {
    background-color: rgba(30, 30, 30, var(--page-opacity)) !important;
}

/* 暗色主题下的表格透明度调整 - 避免与卡片背景叠加 */
[data-bs-theme="dark"] body.custom-background-enabled .table {
    background-color: transparent !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .table th {
    background-color: transparent !important;
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
}

[data-bs-theme="dark"] body.custom-background-enabled .table td {
    background-color: transparent !important;
}

/* 暗色主题下的输入框完全透明化 - 方案A */
[data-bs-theme="dark"] body.custom-background-enabled .form-control {
    background-color: transparent !important;
    backdrop-filter: none;
    -webkit-backdrop-filter: none;
    border: 1px solid rgba(255, 255, 255, 0.2) !important;
    color: rgba(255, 255, 255, 0.9) !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .form-control:focus {
    background-color: transparent !important;
    border: 1px solid rgba(13, 110, 253, 0.6) !important;
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.15) !important;
}

/* 暗色主题下的下拉菜单透明度调整 - 移除backdrop-filter */
[data-bs-theme="dark"] body.custom-background-enabled .dropdown-menu {
    background-color: rgba(30, 30, 30, var(--page-opacity)) !important;
    /* 移除backdrop-filter避免创建层叠上下文，确保z-index正常工作 */
    /* backdrop-filter: blur(5px); */
    /* -webkit-backdrop-filter: blur(5px); */
}

/* 暗色主题下的滑块完全透明化 - 完整重置 */
[data-bs-theme="dark"] body.custom-background-enabled .form-range {
    -webkit-appearance: none !important;
    appearance: none !important;
    background: transparent !important;
    outline: none !important;
}

/* WebKit浏览器 (Chrome, Safari) - 暗色主题 */
[data-bs-theme="dark"] body.custom-background-enabled .form-range::-webkit-slider-track {
    -webkit-appearance: none !important;
    appearance: none !important;
    background: transparent !important;
    border: 1px solid rgba(255, 255, 255, 0.2) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    outline: none !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .form-range::-webkit-slider-runnable-track {
    -webkit-appearance: none !important;
    background: transparent !important;
    border: 1px solid rgba(255, 255, 255, 0.2) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
}

/* Firefox - 暗色主题 */
[data-bs-theme="dark"] body.custom-background-enabled .form-range::-moz-range-track {
    background: transparent !important;
    border: 1px solid rgba(255, 255, 255, 0.2) !important;
    height: 6px !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    outline: none !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .form-range::-moz-range-progress {
    background: transparent !important;
    height: 6px !important;
    border-radius: 3px !important;
}

/* 滑块按钮 - 暗色主题 - 垂直居中对齐 */
[data-bs-theme="dark"] body.custom-background-enabled .form-range::-webkit-slider-thumb {
    -webkit-appearance: none !important;
    appearance: none !important;
    background-color: rgba(13, 110, 253, 0.9) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    width: 20px !important;
    height: 20px !important;
    border-radius: 50% !important;
    cursor: pointer !important;
    margin-top: -7px !important;
    box-sizing: border-box !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .form-range::-moz-range-thumb {
    background-color: rgba(13, 110, 253, 0.9) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    width: 20px !important;
    height: 20px !important;
    border-radius: 50% !important;
    cursor: pointer !important;
    box-shadow: none !important;
    margin-top: -8px !important;
    box-sizing: border-box !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .mobile-server-card,
[data-bs-theme="dark"] body.custom-background-enabled .mobile-site-card {
    background-color: rgba(33, 37, 41, var(--page-opacity)) !important;
    border-color: rgba(73, 80, 87, var(--page-opacity));
}

[data-bs-theme="dark"] body.custom-background-enabled .mobile-card-header {
    background-color: rgba(255, 255, 255, calc(0.05 * var(--page-opacity))) !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .table-striped > tbody > tr:nth-of-type(odd) > * {
    background-color: rgba(255, 255, 255, 0.03) !important;
}

[data-bs-theme="dark"] body.custom-background-enabled .table-hover > tbody > tr:hover > * {
    background-color: rgba(255, 255, 255, 0.05) !important;
}





/* 警告框透明度调整 */
body.custom-background-enabled #serverAlert,
body.custom-background-enabled #siteAlert,
body.custom-background-enabled #telegramSettingsAlert,
body.custom-background-enabled #backgroundSettingsAlert {
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.3);
}

/* ==================== 文字描边渲染系统 ==================== */

/* 文字加粗系统 - 精简版 */
p, div, span:not(.badge), td, th, .btn, button, a:not(.navbar-brand),
.form-control, .form-select, .form-check-label, input, textarea,
.card-header, .card-title, .card-body, .modal-content, .modal-title, .dropdown-menu,
.progress span, .alert, .breadcrumb, .list-group-item {
    font-weight: 500;
}

/* 统一Toast弹窗系统 */
.toast-container {
    position: fixed;
    top: 15%;
    left: 50%;
    transform: translateX(-50%);
    z-index: 10000; /* 确保在所有元素之上，包括模态框 */
    pointer-events: none;
    display: flex;
    flex-direction: column;
    align-items: center;
}

.unified-toast {
    pointer-events: auto;
    min-width: 120px;
    max-width: 90vw;
    padding: 16px 50px 16px 24px;
    margin-bottom: 12px;
    border-radius: 12px;
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    font-weight: 500;
    font-size: 15px;
    position: relative;
    display: inline-flex;
    align-items: center;
    animation: toastIn 0.3s ease;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

.unified-toast.hiding {
    animation: toastOut 0.3s ease;
    opacity: 0;
}

.unified-toast.success {
    background: linear-gradient(135deg,
        rgba(34, 197, 94, calc(0.7 * var(--page-opacity, 0.8))),
        rgba(22, 163, 74, calc(0.7 * var(--page-opacity, 0.8))));
    color: white;
    border-color: rgba(34, 197, 94, calc(0.4 * var(--page-opacity, 0.8)));
}

.unified-toast.danger {
    background: linear-gradient(135deg,
        rgba(239, 68, 68, calc(0.7 * var(--page-opacity, 0.8))),
        rgba(220, 38, 38, calc(0.7 * var(--page-opacity, 0.8))));
    color: white;
    border-color: rgba(239, 68, 68, calc(0.4 * var(--page-opacity, 0.8)));
}

.unified-toast.warning {
    background: linear-gradient(135deg,
        rgba(245, 158, 11, calc(0.7 * var(--page-opacity, 0.8))),
        rgba(217, 119, 6, calc(0.7 * var(--page-opacity, 0.8))));
    color: white;
    border-color: rgba(245, 158, 11, calc(0.4 * var(--page-opacity, 0.8)));
}

.unified-toast.info {
    background: linear-gradient(135deg,
        rgba(59, 130, 246, calc(0.7 * var(--page-opacity, 0.8))),
        rgba(37, 99, 235, calc(0.7 * var(--page-opacity, 0.8))));
    color: white;
    border-color: rgba(59, 130, 246, calc(0.4 * var(--page-opacity, 0.8)));
}

.toast-icon {
    margin-right: 8px;
    font-size: 16px;
    flex-shrink: 0;
}

.toast-content {
    flex: 1;
    line-height: 1.4;
}

.toast-close {
    position: absolute;
    top: 50%;
    right: 12px;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: rgba(255, 255, 255, 0.8);
    font-size: 16px;
    cursor: pointer;
    padding: 6px;
    border-radius: 50%;
    width: 28px;
    height: 28px;
}

.toast-close:hover {
    background: rgba(255, 255, 255, 0.2);
}

.toast-progress {
    position: absolute;
    bottom: 0;
    left: 0;
    height: 3px;
    background: rgba(255, 255, 255, 0.3);
    border-radius: 0 0 12px 12px;
    animation: progressBar 5s linear;
}

@keyframes toastIn {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes toastOut {
    from { opacity: 1; }
    to { opacity: 0; }
}

@keyframes progressBar {
    from { width: 100%; }
    to { width: 0%; }
}

[data-bs-theme="dark"] .unified-toast {
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    border-color: rgba(255, 255, 255, 0.1);
}

/* 自定义导航栏高度 */
.navbar {
    --bs-navbar-padding-y: 0.375rem;
    min-height: 50px;
    height: 50px;
}

.navbar-brand {
    padding-top: 0.3125rem;
    padding-bottom: 0.3125rem;
    line-height: 1.25;
}


`;
}

function getMainJs() {
  return `// main.js - 首页面的JavaScript逻辑

// Global variables
let vpsUpdateInterval = null;
let siteUpdateInterval = null;
let serverDataCache = {}; // Cache server data to avoid re-fetching for details
let vpsStatusCache = {}; // 用于跟踪VPS状态变化
const DEFAULT_VPS_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for VPS data if backend setting fails
const DEFAULT_SITE_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for Site data

// ==================== 统一API请求工具 ====================

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    return headers;
}

// ==================== VPS状态变化检测 ====================

// 检测VPS状态变化并发送通知
async function checkVpsStatusChanges(allStatuses) {
    for (const data of allStatuses) {
        const serverId = data.server.id;
        const serverName = data.server.name;
        const currentStatus = determineVpsStatus(data);
        const previousStatus = vpsStatusCache[serverId];

        // 首次加载或状态变化时检测
        if (previousStatus === undefined || previousStatus !== currentStatus) {
                        if (currentStatus === 'offline') {
                await notifyVpsOffline(serverId, serverName);
            } else if (currentStatus === 'online' && previousStatus === 'offline') {
                await notifyVpsRecovery(serverId, serverName);
            }
        }

        vpsStatusCache[serverId] = currentStatus;
    }
}

// 判断VPS状态
function determineVpsStatus(data) {
    if (data.error) return 'error';
    if (!data.metrics) return 'unknown';

    const now = new Date();
    const lastReportTime = new Date(data.metrics.timestamp * 1000);
    const diffMinutes = (now - lastReportTime) / (1000 * 60);

    return diffMinutes <= 5 ? 'online' : 'offline';
}

// 发送VPS离线通知
async function notifyVpsOffline(serverId, serverName) {
    try {
        // 使用完整URL
        const baseUrl = window.location.origin;
        await fetch(baseUrl + '/api/notify/offline', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ serverId, serverName })
        });
            } catch (error) {
            }
}

// 发送VPS恢复通知
async function notifyVpsRecovery(serverId, serverName) {
    try {
        // 使用完整URL
        const baseUrl = window.location.origin;
        await fetch(baseUrl + '/api/notify/recovery', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ serverId, serverName })
        });
            } catch (error) {
            }
}

// 统一API请求函数（用于需要认证的请求）
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: getAuthHeaders(),
        ...options
    };

    try {
        const response = await fetch(url, defaultOptions);

        // 处理认证失败
        if (response.status === 401) {
            localStorage.removeItem('auth_token');
            if (window.location.pathname !== '/login.html') {
                window.location.href = 'login.html';
            }
            throw new Error('认证失败，请重新登录');
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`请求失败 (\${response.status})\`);
        }

        return await response.json();
    } catch (error) {
                throw error;
    }
}

// 公开API请求函数（用于不需要认证的请求）
async function publicApiRequest(url, options = {}) {
    const defaultOptions = {
        headers: getAuthHeaders(), // 仍然发送token（如果有），但不强制要求
        ...options
    };

    try {
        const response = await fetch(url, defaultOptions);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`请求失败 (\${response.status})\`);
        }

        return await response.json();
    } catch (error) {
                throw error;
    }
}

// 显示错误消息
function showError(message, containerId = null) {
    console.error('错误:', message);
    if (containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = \`<div class="alert alert-danger">\${message}</div>\`;
        }
    }
}

// 显示成功消息
function showSuccess(message, containerId = null) {
        if (containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = \`<div class="alert alert-success">\${message}</div>\`;
        }
    }
}

// Function to fetch VPS refresh interval and start periodic VPS data updates
async function initializeVpsDataUpdates() {
        let vpsRefreshIntervalMs = DEFAULT_VPS_REFRESH_INTERVAL_MS;

    try {
                const data = await publicApiRequest('/api/admin/settings/vps-report-interval');
                if (data && typeof data.interval === 'number' && data.interval > 0) {
            vpsRefreshIntervalMs = data.interval * 1000; // Convert seconds to milliseconds
                    } else {
            // 使用默认值
        }
    } catch (error) {
            }

    // Clear existing interval if any
    if (vpsUpdateInterval) {
                clearInterval(vpsUpdateInterval);
    }

    // VPS数据跟随后台设置频率刷新
        vpsUpdateInterval = setInterval(() => {
                loadAllServerStatuses();
    }, vpsRefreshIntervalMs);

    }

// 优化：网站状态每小时刷新一次
function initializeSiteDataUpdates() {
    const hourlyRefreshInterval = 60 * 60 * 1000; // 1小时
        // 清除任何现有的自动刷新间隔
    if (siteUpdateInterval) {
        clearInterval(siteUpdateInterval);
    }

    // 设置每小时刷新一次
    siteUpdateInterval = setInterval(() => {
                loadAllSiteStatuses();
    }, hourlyRefreshInterval);

    }

// 移除手动刷新按钮相关代码，改为自动刷新

// Execute after the page loads (only for main page)
document.addEventListener('DOMContentLoaded', function() {
        // Check if we're on the main page by looking for the server table
    const serverTableBody = document.getElementById('serverTableBody');
    if (!serverTableBody) {
        // Not on the main page, only initialize theme
                initializeTheme();
        return;
    }

        // Initialize theme
    initializeTheme();

    // Load initial data
    loadAllServerStatuses();
    loadAllSiteStatuses();

    // Initialize periodic updates separately
        initializeVpsDataUpdates();
        initializeSiteDataUpdates();

    // Add click event listener to the table body for row expansion
    serverTableBody.addEventListener('click', handleRowClick);

    // Check login status and update admin link
    updateAdminLink();
});

// --- Theme Management ---
const THEME_KEY = 'vps-monitor-theme';
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

        const data = await publicApiRequest('/api/auth/status');
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
    } catch (error) {
                // Network error, assume not logged in
        adminLink.textContent = '管理员登录';
        adminLink.href = '/login.html';
    }
}


// Handle click on a server row
function handleRowClick(event) {
    const clickedRow = event.target.closest('tr.server-row');
    if (!clickedRow) return; // Not a server row

    const  realtime_endpoint= clickedRow.getAttribute('data-realtime-endpoint');
    const  serverId= clickedRow.getAttribute('data-server-id');
    const detailsRow = clickedRow.nextElementSibling; // The details row is the next sibling

    if (detailsRow && detailsRow.classList.contains('server-details-row')) {
        // Toggle visibility
        detailsRow.classList.toggle('d-none');

        // If showing, populate with detailed data
        if (!detailsRow.classList.contains('d-none')) {
            populateDetailsRow(serverId,realtime_endpoint, detailsRow);
        }
    }
}

// 实时监控功能
let realtimeMonitoringInterval = null;
let isRealtimeMonitoringActive = false;
let currentServerId = null;
let cpuUsageHistory = []; // 存储CPU使用率历史数据
const MAX_CPU_HISTORY_POINTS = 60; // 最多显示60秒的数据

function toggleRealtimeMonitoring() {
    const btn = document.getElementById('realtime-monitoring-btn');
    const icon = document.getElementById('monitoring-icon');
    
    if (isRealtimeMonitoringActive) {
        // 停止实时监控
        clearInterval(realtimeMonitoringInterval);
        realtimeMonitoringInterval = null;
        isRealtimeMonitoringActive = false;
        
        btn.innerHTML = '<i class="bi bi-play-fill"></i> 实时监控';
        btn.className = 'btn btn-outline-primary btn-sm';
        
        // 清空CPU历史数据并重置图表
        cpuUsageHistory = [];
        resetCpuChart();
    } else {
        // 开始实时监控
        isRealtimeMonitoringActive = true;
        
        btn.innerHTML = '<i class="bi bi-stop-fill"></i> 停止监控';
        btn.className = 'btn btn-outline-danger btn-sm';
        
        // 启动定时更新
        updateRealtimeData();
        realtimeMonitoringInterval = setInterval(updateRealtimeData, 3000);
    }
}

async function updateRealtimeData() {
    if (!currentServerId) return;
     // 生成随机回调函数名
    const callbackName = \`jsonp_\${Date.now()}\`;
   
        // 使用实时API接口获取单个服务器状态
        const response = await apiRequest(\`\/api\/realtime\/\${currentServerId}\`);
        //const response = await apiRequest(currentRealtimeEndPoint);
		  
    // 创建script标签发起JSONP请求
   // const script = document.createElement('script');
    //script.src =\`\${currentRealtimeEndPoint}?callback=\${callbackName}\`;
	 // 定义全局回调函数
   // window[callbackName] = (data) => {
       // try {
            // 清理script标签
          //  document.body.removeChild(script);
         //   delete window[callbackName];
        if ( response.data) {
            const metrics = response.data;
            
            // 更新CPU负载显示
            const cpuLoadDisplay = document.getElementById('cpu-load-display');
            if (cpuLoadDisplay && metrics.cpu && metrics.cpu.load_avg) {
                cpuLoadDisplay.querySelector('i').nextSibling.textContent = ' ' + metrics.cpu.load_avg.join(', ');
            }
            
            // 更新CPU使用率显示
            const cpuUsageElement = document.getElementById('cpu-usage-value');
            if (cpuUsageElement && metrics.cpu && typeof metrics.cpu.usage_percent === 'number') {
                cpuUsageElement.textContent = metrics.cpu.usage_percent.toFixed(1) + '%';
                
                // 添加CPU使用率到历史记录
                cpuUsageHistory.push({
                    timestamp: Date.now(),
                    usage: metrics.cpu.usage_percent
                });
                
                // 保持最大数据量
                if (cpuUsageHistory.length > MAX_CPU_HISTORY_POINTS) {
                    cpuUsageHistory.shift();
                }
                
                // 绘制CPU曲线图
                renderCpuUsageChart();
            }
            
            // 更新内存使用率和进度条
            const memoryUsageElement = document.getElementById('memory-usage-value');
            const memoryProgressBar = document.getElementById('memory-progress-bar');
            if (memoryUsageElement && metrics.memory && typeof metrics.memory.usage_percent === 'number') {
                const memoryPercent = metrics.memory.usage_percent;
                memoryUsageElement.textContent = memoryPercent.toFixed(1) + '%';
                
                // 更新进度条
                if (memoryProgressBar) {
                    const memoryTotal = formatDataSize(metrics.memory.total * 1024);
                    const memoryUsed = formatDataSize(metrics.memory.used * 1024);
                    let memoryColor = 'bg-success';
                    if (memoryPercent > 80) memoryColor = 'bg-danger';
                    else if (memoryPercent > 60) memoryColor = 'bg-warning';
                    
                    memoryProgressBar.style.width = memoryPercent + '%';
                    memoryProgressBar.className = \`progress-bar \${memoryColor}\`;
                    memoryProgressBar.textContent = \`\${memoryUsed}/\${memoryTotal} (\${memoryPercent.toFixed(1)}%)\`;
                }
            }
            
            // 更新硬盘进度条
            const diskProgressBar = document.getElementById('disk-progress-bar');
            if (diskProgressBar && metrics.disk) {
                const diskPercent = metrics.disk.usage_percent || 0;
                const diskTotal = typeof metrics.disk.total === 'number' ? metrics.disk.total.toFixed(2) : '-';
                const diskUsed = typeof metrics.disk.used === 'number' ? metrics.disk.used.toFixed(2) : '-';
                let diskColor = 'bg-success';
                if (diskPercent > 90) diskColor = 'bg-danger';
                else if (diskPercent > 75) diskColor = 'bg-warning';
                
                diskProgressBar.style.width = diskPercent + '%';
                diskProgressBar.className = \`progress-bar \${diskColor}\`;
                diskProgressBar.textContent = \`\${diskUsed}G/\${diskTotal}G (\${diskPercent.toFixed(1)}%)\`;
            }
        }
   // } catch (error) {
    //    console.error('更新实时数据失败:', error);
    //}
//};
     /* 错误处理
        script.onerror = () => {
            console.error('JSONP请求失败');
            if (window[callbackName]) {
                delete window[callbackName];
            }
        };
        
        // 可选：添加超时处理
        setTimeout(() => {
            if (window[callbackName]) {
                console.error('JSONP请求超时');
                document.body.removeChild(script);
                delete window[callbackName];
            }
        }, 5000); // 添加到DOM发起请求
        document.body.appendChild(script);*/
}
// 绘制CPU使用率曲线图
function renderCpuUsageChart() {
    const chartContainer = document.getElementById('cpu-usage-chart');
    if (!chartContainer || cpuUsageHistory.length === 0) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 创建SVG容器
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    svg.setAttribute('viewBox', '0 0 400 80');
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.style.position = 'absolute';
    svg.style.top = '0';
    svg.style.left = '0';
    svg.style.width = '100%';
    svg.style.height = '100%';
    
    // 计算最大值用于缩放（至少20%以显示低使用率）
    const maxUsage = Math.max(20, Math.max(...cpuUsageHistory.map(point => point.usage)));
    
    // 创建曲线路径
    let pathData = '';
    const pointCount = cpuUsageHistory.length;
    
    cpuUsageHistory.forEach((point, index) => {
        const x = (index / (MAX_CPU_HISTORY_POINTS - 1)) * 400;
        const y = 80 - ((point.usage / maxUsage) * 70); // 70是可用高度，留出10px边距
        
        if (index === 0) {
            pathData += \`M \${x} \${y}\`;
        } else {
            pathData += \` L \${x} \${y}\`;
        }
    });
    
    // 创建路径元素
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', pathData);
    path.setAttribute('stroke', '#007bff');
    path.setAttribute('stroke-width', '2');
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    
    // 创建填充区域
    if (cpuUsageHistory.length > 1) {
        const fillPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const fillData = pathData + \` L 400 80 L 0 80 Z\`;
        fillPath.setAttribute('d', fillData);
        fillPath.setAttribute('fill', 'rgba(0, 123, 255, 0.1)');
        svg.appendChild(fillPath);
    }
    
    svg.appendChild(path);
    
    // 添加网格线
    for (let i = 0; i <= 4; i++) {
        const y = (i / 4) * 70 + 5;
        const gridLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        gridLine.setAttribute('x1', '0');
        gridLine.setAttribute('y1', y.toString());
        gridLine.setAttribute('x2', '400');
        gridLine.setAttribute('y2', y.toString());
        gridLine.setAttribute('stroke', '#e9ecef');
        gridLine.setAttribute('stroke-width', '0.5');
        svg.appendChild(gridLine);
    }
    
    chartContainer.appendChild(svg);
    
    // 添加当前值标签
    const currentValue = cpuUsageHistory[cpuUsageHistory.length - 1].usage;
    const valueLabel = document.createElement('div');
    valueLabel.style.cssText = \`
        position: absolute;
        top: 5px;
        right: 10px;
        background: rgba(0, 123, 255, 0.8);
        color: white;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 600;
    \`;
    valueLabel.textContent = \`\${currentValue.toFixed(1)}%\`;
    chartContainer.appendChild(valueLabel);
}

// 重置CPU曲线图
function resetCpuChart() {
    const chartContainer = document.getElementById('cpu-usage-chart');
    if (chartContainer) {
        chartContainer.innerHTML = \`
            <div class="text-center p-3 text-muted" style="font-size: 0.875rem;">
                点击"实时监控"开始显示CPU使用率曲线
            </div>
        \`;
    }
}

// Populate the detailed row with data
function populateDetailsRow(serverId, vpsRealtimeEndPoint,detailsRow) {
    // 设置当前服务器ID用于实时监控
    currentServerId = serverId;
    currentRealtimeEndPoint=vpsRealtimeEndPoint;
    const serverData = serverDataCache[serverId];
    const detailsContentDiv = detailsRow.querySelector('.server-details-content');

    if (!serverData || !serverData.metrics || !detailsContentDiv) {
        detailsContentDiv.innerHTML = '<p class="text-muted">无详细数据</p>';
        return;
    }

    const metrics = serverData.metrics;

    let detailsHtml = '';

    // Memory and Disk Details with progress bars (combined)
    if (metrics.memory || metrics.disk) {
        detailsHtml += \`<div class="detail-item"><strong>内存 & 硬盘:</strong>\`;
        
        // Memory bar
        if (metrics.memory) {
            const memoryTotal = formatDataSize(metrics.memory.total * 1024);
            const memoryUsed = formatDataSize(metrics.memory.used * 1024);
            const memoryPercent = metrics.memory.usage_percent || 0;
            let memoryColor = 'bg-success';
            if (memoryPercent > 80) memoryColor = 'bg-danger';
            else if (memoryPercent > 60) memoryColor = 'bg-warning';
            
            detailsHtml += \`
                <div class="mt-2">
                    <small class="text-muted">内存</small>
                    <div class="progress" style="height: 25px; background-color: #e9ecef;">
                        <div class="progress-bar \${memoryColor}" role="progressbar" 
                             style="width: \${memoryPercent}%; display: flex; align-items: center; justify-content: center; font-weight: 600; color: white;" 
                             id="memory-progress-bar">
                            \${memoryUsed}/\${memoryTotal} (\${memoryPercent.toFixed(1)}%)
                        </div>
                    </div>
                </div>
            \`;
        }
        
        // Disk bar
        if (metrics.disk) {
            const diskTotal = typeof metrics.disk.total === 'number' ? metrics.disk.total.toFixed(2) : '-';
            const diskUsed = typeof metrics.disk.used === 'number' ? metrics.disk.used.toFixed(2) : '-';
            const diskPercent = metrics.disk.usage_percent || 0;
            let diskColor = 'bg-success';
            if (diskPercent > 90) diskColor = 'bg-danger';
            else if (diskPercent > 75) diskColor = 'bg-warning';
            
            detailsHtml += \`
                <div class="mt-2">
                    <small class="text-muted">硬盘 (/)</small>
                    <div class="progress" style="height: 25px; background-color: #e9ecef;">
                        <div class="progress-bar \${diskColor}" role="progressbar" 
                             style="width: \${diskPercent}%; display: flex; align-items: center; justify-content: center; font-weight: 600; color: white;" 
                             id="disk-progress-bar">
                            \${diskUsed}G/\${diskTotal}G (\${diskPercent.toFixed(1)}%)
                        </div>
                    </div>
                </div>
            \`;
        }
        
        detailsHtml += \`</div>\`;
    }

    // CPU负载 & 总流量 (combined with CPU usage chart)
    detailsHtml += \`
        <div class="detail-item">
            <div class="d-flex justify-content-between align-items-center">
                <strong>CPU负载 & 总流量:</strong>
                
            </div>
            
            <!-- CPU Load and Total Traffic Info -->
            <div class="row mt-2">
                <div class="col-6">
                    <small class="text-muted">CPU负载 (1m, 5m, 15m)</small>
                    <div class="fw-bold text-info" id="cpu-load-display">
                        <i class="bi bi-cpu me-1"></i>
                        \${metrics.cpu && metrics.cpu.load_avg ? metrics.cpu.load_avg.join(', ') : '-'}
                    </div>
                </div>
                <div class="col-6">
                    <small class="text-muted">CPU使用率</small>
                    <div class="fw-bold text-warning" id="cpu-usage-display">
                        <i class="bi bi-speedometer me-1"></i>
                        <span id="cpu-usage-value">\${metrics.cpu && typeof metrics.cpu.usage_percent === 'number' ? metrics.cpu.usage_percent.toFixed(1) + '%' : '-'}</span>
                    </div>
                </div>
            </div>
            
            <!-- Total Traffic -->
            \${metrics.network ? \`
            <div class="row mt-2">
                <div class="col-6">
                    <small class="text-muted">总上传</small>
                    <div class="fw-bold text-success">
                        <i class="bi bi-arrow-up-circle-fill me-1"></i>
                        \${formatDataSize(metrics.network.total_upload)}
                    </div>
                </div>
                <div class="col-6">
                    <small class="text-muted">总下载</small>
                    <div class="fw-bold text-primary">
                        <i class="bi bi-arrow-down-circle-fill me-1"></i>
                        \${formatDataSize(metrics.network.total_download)}
                    </div>
                </div>
            </div>
            \` : ''}
            
        </div>
        <div class="detail-item">
            <!-- CPU Usage Chart -->
            <div class="mt-3">
                <small class="text-muted">CPU使用率曲线图 (最近60秒)</small><button class="btn btn-outline-primary btn-sm" id="realtime-monitoring-btn" onclick="toggleRealtimeMonitoring()">
                    <i class="bi bi-play-fill" id="monitoring-icon"></i> 实时监控
                </button>
                <div id="cpu-usage-chart" style="height: 80px; border: 1px solid #ddd; border-radius: 4px; position: relative; background-color: #f8f9fa; margin-top: 5px;">
                    <div class="text-center p-3 text-muted" style="font-size: 0.875rem;">
                        点击"实时监控"开始显示CPU使用率曲线
                    </div>
                </div>
            </div>
        </div>
    \`;

    detailsContentDiv.innerHTML = detailsHtml || '<p class="text-muted">无详细数据</p>';
}


// Load all server statuses
async function loadAllServerStatuses() {
        try {
        // 使用批量API一次性获取所有VPS状态
        let batchData;
        try {
            batchData = await publicApiRequest('/api/status/batch');
        } catch (error) {
            // 如果批量API失败，可能是数据库未初始化，尝试初始化
                        await publicApiRequest('/api/init-db');
            batchData = await publicApiRequest('/api/status/batch');
        }

        const allStatuses = batchData.servers || [];
                const noServersAlert = document.getElementById('noServers');
        const serverTableBody = document.getElementById('serverTableBody');

        if (allStatuses.length === 0) {
            noServersAlert.classList.remove('d-none');
            serverTableBody.innerHTML = '<tr><td colspan="13" class="text-center">No server data available. Please log in to the admin panel to add servers.</td></tr>';
            // Remove any existing detail rows if the server list becomes empty
            removeAllDetailRows();
            // 同时更新移动端卡片容器
            renderMobileServerCards([]);
            return;
        } else {
            noServersAlert.classList.add('d-none');
        }

        // Update the serverDataCache with the latest data
        allStatuses.forEach(data => {
             serverDataCache[data.server.id] = data;
        });

        // 检测VPS状态变化并发送通知
        await checkVpsStatusChanges(allStatuses);

        // 3. Render the table using DOM manipulation
        renderServerTable(allStatuses);

    } catch (error) {
                const serverTableBody = document.getElementById('serverTableBody');
        serverTableBody.innerHTML = '<tr><td colspan="13" class="text-center text-danger">Failed to load server data. Please refresh the page.</td></tr>';
        removeAllDetailRows();
        // 同时更新移动端卡片容器显示错误状态
        showToast('danger', '加载服务器数据失败，请刷新页面重试');
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
        const realTimeEndPoint = data.server.realtime_endpoint;
        const serverName = data.server.name;
        const metrics = data.metrics;
        const hasError = data.error;

        const card = document.createElement('div');
        card.className = 'mobile-server-card';
        card.setAttribute('data-server-id', serverId);

        card.setAttribute('data-realtime-endpoint', realTimeEndPoint);
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
            <div style="flex: 1;"></div>
            <h6 class="mobile-card-title text-center" style="flex: 1;">\${serverName || '未命名服务器'}</h6>
            <div style="flex: 1; display: flex; justify-content: flex-end;">
                <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
            </div>
        \`;

        // 卡片主体 - 显示所有信息
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // 获取所有数据
        const cpuValue = metrics && metrics.cpu && typeof metrics.cpu.usage_percent === 'number' ? \`\${metrics.cpu.usage_percent.toFixed(1)}%\` : '-';
        const memoryValue = metrics && metrics.memory && typeof metrics.memory.usage_percent === 'number' ? \`\${metrics.memory.usage_percent.toFixed(1)}%\` : '-';
        const diskValue = metrics && metrics.disk && typeof metrics.disk.usage_percent === 'number' ? \`\${metrics.disk.usage_percent.toFixed(1)}%\` : '-';
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

        // 在线率 - 单行（可点击查看历史）
        const uptimeRateRow = document.createElement('div');
        uptimeRateRow.className = 'mobile-card-row';
        uptimeRateRow.style.cursor = 'pointer';
        uptimeRateRow.innerHTML = \`
            <span class="mobile-card-label">在线率</span>
            <span class="mobile-card-value" id="mobile-uptime-\${serverId}" style="color: #007bff; text-decoration: underline;">加载中...</span>
        \`;
        uptimeRateRow.onclick = () => {
            if (typeof showUptimeHistory === 'function') {
                showUptimeHistory(serverId);
            }
        };
        cardBody.appendChild(uptimeRateRow);

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
            <span class="mobile-card-label">最后更新: \${lastUpdate}</span>
        \`;
        cardBody.appendChild(lastUpdateRow);

        // 实时监控按钮行
        const realtimeRow = document.createElement('div');
        realtimeRow.className = 'mobile-card-row';
        realtimeRow.style.marginTop = '10px';
        realtimeRow.innerHTML = \`
            <button class="btn btn-primary btn-sm w-100" onclick="startRealtimeMonitoring('\${serverId}', '\${serverName}')">
                <i class="bi bi-speedometer2"></i> 实时监控
            </button>
        \`;
        cardBody.appendChild(realtimeRow);

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
            <div style="flex: 1;"></div>
            <h6 class="mobile-card-title text-center" style="flex: 1;">\${site.name || '未命名网站'}</h6>
            <div style="flex: 1; display: flex; justify-content: flex-end;">
                <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
            </div>
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
            <span class="mobile-card-label">最后检查: \${lastCheckTime}</span>
        \`;
        cardBody.appendChild(lastCheckRow);

        // 24小时历史记录 - 始终显示，即使没有数据
        const historyContainer = document.createElement('div');
        historyContainer.className = 'mobile-history-container';
        historyContainer.innerHTML = \`
            <div class="mobile-history-label">24小时记录</div>
            <div class="history-bar-container"></div>
        \`;
        cardBody.appendChild(historyContainer);

        // 使用统一的历史记录渲染函数
        const historyBarContainer = historyContainer.querySelector('.history-bar-container');
        renderSiteHistoryBar(historyBarContainer, site.history || []);

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });
}




// 加载服务器在线率数据
async function loadServerUptimeData() {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined') {
        return;
    }
    
    try {
        const data = await apiRequest('/api/admin/servers/uptime?period=24h');
        const uptimeData = data.servers || [];
        
        // 更新每个服务器的在线率显示
        uptimeData.forEach(server => {
            const uptimeCell = document.querySelector(\`.uptime-cell[data-server-id="\${server.id}"]\`);
            const uptimePercentage = server.uptime;
            let uptimeClass = 'text-success';
            if (uptimePercentage < 95) uptimeClass = 'text-warning';
            if (uptimePercentage < 80) uptimeClass = 'text-danger';
            
            // 更新桌面端显示
            if (uptimeCell) {
                uptimeCell.innerHTML = \`<span class="\${uptimeClass}" style="cursor: pointer; text-decoration: underline;" onclick="showUptimeHistory('\${server.id}')">\${uptimePercentage}%</span>\`;
                const totalHours = Math.round(server.totalTime / 60 * 100) / 100;
                uptimeCell.title = \`点击查看详细历史 - 在线率: \${uptimePercentage}% (在线\${server.onlineTime}分钟 / 总计\${server.totalTime}分钟，约\${totalHours}小时)\`;
            } else {
                // 如果找不到特定的单元格，尝试通过索引找到对应行的在线率列
                console.warn(\`无法找到服务器 \${server.id} 的在线率单元格\`);
            }
            
            // 更新移动端显示
            const mobileUptimeCell = document.getElementById(\`mobile-uptime-\${server.id}\`);
            if (mobileUptimeCell) {
                mobileUptimeCell.innerHTML = \`\${uptimePercentage}%\`;
                mobileUptimeCell.className = \`mobile-card-value \${uptimeClass}\`;
                mobileUptimeCell.style.color = '#007bff';
                mobileUptimeCell.style.textDecoration = 'underline';
            }
        });
    } catch (error) {
        console.error('加载在线率数据失败:', error);
        // 如果获取在线率失败，显示错误信息
        const uptimeCells = document.querySelectorAll('.uptime-cell');
        if (uptimeCells.length > 0) {
            uptimeCells.forEach(cell => {
                cell.innerHTML = '<span class="text-muted">-</span>';
                cell.title = '获取在线率数据失败';
            });
        }
    }
}

// 显示在线率历史详情
let currentUptimeServerId = null;

function showUptimeHistory(serverId) {
    if (typeof document === 'undefined') {
        return;
    }
    
    currentUptimeServerId = serverId;
    const modal = new bootstrap.Modal(document.getElementById('uptimeHistoryModal'));
    
    // 重置内容为加载状态
    document.getElementById('uptimeHistoryContent').innerHTML = \`
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
        </div>
    \`;
    
    // 检测设备类型 - 移动设备只显示24小时，桌面设备显示所有选项
    const isMobile = window.innerWidth <= 768;
    const periodButtons = document.getElementById('uptimePeriodButtons');
    
    if (isMobile) {
        // 移动端：只显示24小时选项
        periodButtons.innerHTML = \`
            <input type="radio" class="btn-check" name="uptimePeriod" id="period24h" value="24h" checked>
            <label class="btn btn-outline-primary" for="period24h">24小时</label>
        \`;
        document.getElementById('period24h').checked = true;
        modal.show();
        loadUptimeHistory('24h');
    } else {
        // 桌面端：显示所有时间段选项，但需要检查监控历史
        // 先显示默认的按钮组
        periodButtons.innerHTML = \`
            <input type="radio" class="btn-check" name="uptimePeriod" id="period24h" value="24h" checked>
            <label class="btn btn-outline-primary" for="period24h">24小时</label>
            
            <input type="radio" class="btn-check" name="uptimePeriod" id="period3d" value="3d">
            <label class="btn btn-outline-primary" for="period3d">3天</label>
            
            <input type="radio" class="btn-check" name="uptimePeriod" id="period30d" value="30d">
            <label class="btn btn-outline-primary" for="period30d">1个月</label>
            
            <input type="radio" class="btn-check" name="uptimePeriod" id="period90d" value="90d">
            <label class="btn btn-outline-primary" for="period90d">3个月</label>
            
            <input type="radio" class="btn-check" name="uptimePeriod" id="period180d" value="180d">
            <label class="btn btn-outline-primary" for="period180d">6个月</label>
            
            <input type="radio" class="btn-check" name="uptimePeriod" id="period365d" value="365d">
            <label class="btn btn-outline-primary" for="period365d">1年</label>
        \`;
        
        // 设置默认时间段为3天，如果监控历史不足1个月则只显示3天
        document.getElementById('period3d').checked = true;
        modal.show();
        
        // 先检查服务器的监控历史长度
        checkServerHistoryAndAdjustPeriods(serverId).then(() => {
            loadUptimeHistory('3d');
        });
    }
    
    // 重新绑定时间段切换事件
    const periodInputs = document.querySelectorAll('input[name="uptimePeriod"]');
    periodInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.checked && currentUptimeServerId) {
                loadUptimeHistory(this.value);
            }
        });
    });
}

// 检查服务器监控历史长度并调整可用时间段
async function checkServerHistoryAndAdjustPeriods(serverId) {
    try {
        // 获取服务器信息，检查创建时间
        const serverInfo = await apiRequest(\`/api/servers/\${serverId}\`);
        const now = new Date();
        const createdAt = new Date(serverInfo.created_at || serverInfo.added_at);
        const daysSinceCreation = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24));
        
        const periodButtons = document.getElementById('uptimePeriodButtons');
        
        if (daysSinceCreation < 30) {
            // 监控历史不足1个月，只显示24小时和3天
            periodButtons.innerHTML = \`
                <input type="radio" class="btn-check" name="uptimePeriod" id="period24h" value="24h">
                <label class="btn btn-outline-primary" for="period24h">24小时</label>
                
                <input type="radio" class="btn-check" name="uptimePeriod" id="period3d" value="3d" checked>
                <label class="btn btn-outline-primary" for="period3d">3天</label>
            \`;
            document.getElementById('period3d').checked = true;
        }
        
        // 重新绑定事件监听器
        const periodInputs = document.querySelectorAll('input[name="uptimePeriod"]');
        periodInputs.forEach(input => {
            input.addEventListener('change', function() {
                if (this.checked && currentUptimeServerId) {
                    loadUptimeHistory(this.value);
                }
            });
        });
    } catch (error) {
        console.error('检查服务器历史失败:', error);
        // 如果检查失败，保持默认显示
    }
}

// 加载在线率历史数据
async function loadUptimeHistory(period) {
    if (!currentUptimeServerId) return;
    
    try {
        const response = await apiRequest(\`/api/servers/\${currentUptimeServerId}/uptime/history?period=\${period}\`);
        renderUptimeHistory(response);
    } catch (error) {
        console.error('加载在线率历史失败:', error);
        document.getElementById('uptimeHistoryContent').innerHTML = \`
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                加载失败: \${error.message}
            </div>
        \`;
    }
}

// 渲染断开记录（带分页）
function renderDowntimeRecords(downtimes, currentPage = 1, pageSize = 10) {
    const totalPages = Math.ceil(downtimes.length / pageSize);
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedData = downtimes.slice(startIndex, endIndex);
    
    let html = \`
        <div class="table-responsive">
            <table class="table table-sm table-striped">
                <thead>
                    <tr>
                        <th>断开时间</th>
                        <th>恢复时间</th>
                        <th>持续时间</th>
                    </tr>
                </thead>
                <tbody>
    \`;
    
    let startTimeF = '';
    let endTimeF = '';
    paginatedData.forEach(downtime => {
        startTimeF = new Date(downtime.startTimeFormatted * 1000).toLocaleString();
        endTimeF = new Date(downtime.endTimeFormatted * 1000).toLocaleString();
        const rowClass = downtime.endTime === null ? 'table-danger' : '';
        html += \`
            <tr class="\${rowClass}">
                <td>\${startTimeF}</td>
                <td>\${endTimeF}</td>
                <td>\${downtime.durationFormatted}</td>
            </tr>
        \`;
    });
    
    html += \`
                </tbody>
            </table>
        </div>
    \`;
    
    // 添加分页控件
    if (totalPages > 1) {
        html += \`
            <nav aria-label="断开记录分页">
                <ul class="pagination pagination-sm justify-content-center mb-0">
        \`;
        
        // 上一页
        html += \`
            <li class="page-item \${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="changeDowntimePage(\${currentPage - 1}); return false;">
                    <i class="bi bi-chevron-left"></i>
                </a>
            </li>
        \`;
        
        // 页码
        const maxVisiblePages = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
        let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
        
        if (endPage - startPage + 1 < maxVisiblePages) {
            startPage = Math.max(1, endPage - maxVisiblePages + 1);
        }
        
        for (let i = startPage; i <= endPage; i++) {
            html += \`
                <li class="page-item \${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="changeDowntimePage(\${i}); return false;">\${i}</a>
                </li>
            \`;
        }
        
        // 下一页
        html += \`
            <li class="page-item \${currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="changeDowntimePage(\${currentPage + 1}); return false;">
                    <i class="bi bi-chevron-right"></i>
                </a>
            </li>
        \`;
        
        html += \`
                </ul>
            </nav>
            <div class="text-center mt-2">
                <small class="text-muted">
                    显示第 \${startIndex + 1} - \${Math.min(endIndex, downtimes.length)} 条，共 \${downtimes.length} 条记录
                </small>
            </div>
        \`;
    }
    
    return html;
}

// 分页切换函数
function changeDowntimePage(page) {
    const currentData = window.currentUptimeData;
    if (currentData && currentData.downtimes) {
        const newContent = renderDowntimeRecords(currentData.downtimes, page, 10);
        document.getElementById('downtimeRecords').innerHTML = newContent;
    }
}

// 渲染在线率历史内容
function renderUptimeHistory(data) {
    // 存储当前数据供分页使用
    window.currentUptimeData = data;
    
    const content = document.getElementById('uptimeHistoryContent');
    const starttime = new Date(data.actualStartTime*1000).toLocaleString();
	const uptimeFormat = formatUptime(data.onlineTime*60);
    let html = \`
        <div class="row mb-4">
            <div class="col-md-4">
                <h6><i class="bi bi-server me-2"></i>\${data.serverName}</h6>
                <p class="text-muted mb-1">统计时间段: \${data.period}</p>
                <p class="text-muted">开始时间: \${starttime}</p>
            </div>
            <div class="col-md-7">
                <div class="row text-center">
                    <div class="col-3">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 \${data.uptime >= 95 ? 'text-success' : data.uptime >= 80 ? 'text-warning' : 'text-danger'}">\${data.uptime}%</div>
                            <small class="text-muted">在线率</small>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 text-success">\${uptimeFormat}</div>
                            <small class="text-muted">在线时间</small>
                        </div>
                    </div>
                    <div class="col-3">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 text-info">\${data.downtimeCount}</div>
                            <small class="text-muted">断开次数</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    \`;
    
    // 添加图形化在线率显示
    if (data.chartData && data.chartData.length > 0) {
        html += \`
            <div class="mb-4">
                <h6><i class="bi bi-graph-up me-2"></i>在线率图表</h6>
                <div class="uptime-chart-container" style="height: 60px; border: 1px solid #ddd; border-radius: 4px; overflow: hidden; position: relative;">
        \`;
        let timep='';
        const totalDataPoints = data.chartData.length;
        data.chartData.forEach((point, index) => {
            const width = (100 / totalDataPoints);
            const left = (index * width);
            const color = point.status === 'online' ? '#28a745' : '#dc3545'; // 绿色在线，红色离线
            timep = new Date(point.timeFormatted*1000).toLocaleString();
            html += \`
                <div class="uptime-bar" 
                     style="position: absolute; 
                            left: \${left}%; 
                            width: \${width}%; 
                            height: 100%; 
                            background-color: \${color}; 
                            border-right: 1px solid #fff;"
                     title="\${timep}: \${point.status === 'online' ? '在线' : '离线'}">
                </div>
            \`;
        });
        
        html += \`
                </div>
                <div class="d-flex justify-content-between mt-1 text-muted small">
                    <span>开始时间</span>
                    <span>现在</span>
                </div>
            </div>
        \`;
    }
    
    if (data.downtimes && data.downtimes.length > 0) {
        html += \`
            <h6><i class="bi bi-exclamation-triangle-fill text-warning me-2"></i>断开记录 (共\${data.downtimes.length}条)</h6>
            <div id="downtimeRecords">
                \${renderDowntimeRecords(data.downtimes, 1, 10)}
            </div>
        \`;
    } else {
        html += \`
            <div class="alert alert-success">
                <i class="bi bi-check-circle me-2"></i>
                在此时间段内没有断开记录，服务器一直保持在线状态！
            </div>
        \`;
    }
    
    content.innerHTML = html;
}

// 在模态框初始化时添加时间段切换事件监听
document.addEventListener('DOMContentLoaded', function() {
    if (typeof document === 'undefined') return;
    
    // VPS在线率时间段切换事件
    const periodInputs = document.querySelectorAll('input[name="uptimePeriod"]');
    periodInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.checked && currentUptimeServerId) {
                loadUptimeHistory(this.value);
            }
        });
    });
    
    // 网站在线率时间段切换事件
    const sitePeriodInputs = document.querySelectorAll('input[name="siteUptimePeriod"]');
    sitePeriodInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.checked && currentSiteUptimeId) {
                loadSiteUptimeHistory(this.value);
            }
        });
    });
});


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
		const realtime_endpoint = data.server.realtime_endpoint; 	  
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
        mainRow.setAttribute('data-realtime-endpoint', realtime_endpoint);
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
            <td class="uptime-cell" data-server-id="\${serverId}">-</td>
            <td><span style="color: #000;">\${lastUpdate}</span></td>
            <td><span style="display: none" data-realtime-endpoint="\${realtime_endpoint}">-</span></td>
            <td>
                <button class="btn btn-primary btn-sm" onclick="startRealtimeMonitoring('\${serverId}', '\${serverName}')" title="开启实时监控">
                    <i class="bi bi-speedometer2"></i>
                </button>
            </td>
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
            populateDetailsRow(serverId, realtime_endpoint, detailsRowElement); // Populate content
        }
    });

    // 3. 同时渲染移动端卡片
    renderMobileServerCards(allStatuses);
    
    // 4. 异步加载在线率数据
    const loadUptimeWithRetry = async (retries = 3) => {
        const tableBody = document.getElementById('serverTableBody');
        const uptimeCells = tableBody?.querySelectorAll('td.uptime-cell');
        
        if (uptimeCells && uptimeCells.length > 0) {
            // DOM已准备好，加载在线率数据
            await loadServerUptimeData();
        } else if (retries > 0) {
            // DOM还没准备好，重试
            setTimeout(() => loadUptimeWithRetry(retries - 1), 500);
        } else {
            console.warn('无法找到在线率单元格，可能DOM渲染失败');
        }
    };
    
    // 立即开始检查，不等待固定时间
    setTimeout(() => loadUptimeWithRetry(), 100);
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
        let data;
        try {
            data = await publicApiRequest('/api/sites/status');
        } catch (error) {
            // 如果获取网站状态失败，可能是数据库未初始化，尝试初始化
                        await publicApiRequest('/api/init-db');
            data = await publicApiRequest('/api/sites/status');
        }
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
                const siteStatusTableBody = document.getElementById('siteStatusTableBody');
        siteStatusTableBody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Failed to load website status data. Please refresh the page.</td></tr>'; // Colspan updated
        // 显示错误通知
        showToast('danger', '加载网站数据失败，请刷新页面重试');
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

        // 在线率单元格
        const uptimeCell = document.createElement('td');
        uptimeCell.className = 'uptime-cell';
        uptimeCell.setAttribute('data-site-id', site.id);
        uptimeCell.innerHTML = '-'; // 初始显示，等待异步加载
        
        row.innerHTML = \`
            <td>\${site.name || '-'}</td>
            <td><span class="badge \${statusInfo.class}">\${statusInfo.text}</span></td>
            <td>\${site.last_status_code || '-'}</td>
            <td>\${responseTime}</td>
            <td>\${lastCheckTime}</td>
        \`;
        row.appendChild(uptimeCell);
        tableBody.appendChild(row);
    }

    // 异步加载网站在线率数据
    const loadUptimeWithRetry = async (retries = 3) => {
        const uptimeCells = tableBody?.querySelectorAll('td.uptime-cell');
        
        if (uptimeCells && uptimeCells.length > 0) {
            // DOM已准备好，加载在线率数据
            await loadSiteUptimeData();
        } else if (retries > 0) {
            // DOM还没准备好，重试
            setTimeout(() => loadUptimeWithRetry(retries - 1), 500);
        } else {
            console.warn('无法找到网站在线率单元格，可能DOM渲染失败');
        }
    };
    
    // 立即开始检查，不等待固定时间
    setTimeout(() => loadUptimeWithRetry(), 100);

    // 同时渲染移动端卡片
    renderMobileSiteCards(sites);
}

// 加载网站在线率数据
async function loadSiteUptimeData() {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined') {
        return;
    }
    
    try {
        const data = await apiRequest('/api/admin/sites/uptime?period=24h');
        const uptimeData = data.sites || [];
        
        // 更新每个网站的在线率显示
        uptimeData.forEach(site => {
            const uptimeCell = document.querySelector(\`td.uptime-cell[data-site-id="\${site.id}"]\`);
            if (uptimeCell) {
                const uptimePercentage = site.uptime;
                let uptimeClass = 'text-success';
                if (uptimePercentage < 95) uptimeClass = 'text-warning';
                if (uptimePercentage < 80) uptimeClass = 'text-danger';
                
                uptimeCell.innerHTML = \`<span class="\${uptimeClass}" style="cursor: pointer; text-decoration: underline;" onclick="showSiteUptimeHistory('\${site.id}')">\${uptimePercentage}%</span>\`;
                const totalHours = Math.round(site.totalTime / 60 * 100) / 100;
                uptimeCell.title = \`点击查看详细历史 - 在线率: \${uptimePercentage}% (在线\${site.onlineTime}分钟 / 总计\${site.totalTime}分钟，约\${totalHours}小时)\`;
            } else {
                // 如果找不到特定的单元格
                console.warn(\`无法找到网站 \${site.id} 的在线率单元格\`);
            }
        });
    } catch (error) {
        console.error('加载网站在线率数据失败:', error);
        // 如果获取在线率失败，显示错误信息
        const uptimeCells = document.querySelectorAll('td.uptime-cell');
        if (uptimeCells.length > 0) {
            uptimeCells.forEach(cell => {
                cell.innerHTML = '<span class="text-muted">-</span>';
                cell.title = '获取在线率数据失败';
            });
        }
    }
}

// 显示网站在线率历史详情
let currentSiteUptimeId = null;

function showSiteUptimeHistory(siteId) {
    if (typeof document === 'undefined') {
        return;
    }
    
    currentSiteUptimeId = siteId;
    const modal = new bootstrap.Modal(document.getElementById('siteUptimeHistoryModal'));
    
    // 重置内容为加载状态
    document.getElementById('siteUptimeHistoryContent').innerHTML = \`
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
        </div>
    \`;
    
    // 设置默认时间段为24小时
    document.getElementById('sitePeriod24h').checked = true;
    
    modal.show();
    loadSiteUptimeHistory('24h');
}

// 加载网站在线率历史数据
async function loadSiteUptimeHistory(period) {
    if (!currentSiteUptimeId) return;
    
    try {
        const response = await apiRequest(\`/api/sites/\${currentSiteUptimeId}/uptime/history?period=\${period}\`);
        renderSiteUptimeHistory(response);
    } catch (error) {
        console.error('加载网站在线率历史失败:', error);
        let errorMessage = '系统暂时不可用';
        
        // 根据不同的错误类型提供更详细的信息
        if (error.message.includes('Not Found') || error.message.includes('404')) {
            errorMessage = '网站不存在或未公开访问';
        } else if (error.message.includes('Unauthorized') || error.message.includes('401')) {
            errorMessage = '权限不足，需要管理员权限';
        } else if (error.message.includes('no such table')) {
            errorMessage = '数据库表不存在，请联系管理员初始化系统';
        } else if (error.message.includes('timeout')) {
            errorMessage = '请求超时，请稍后重试';
        } else if (error.message.includes('Failed to fetch')) {
            errorMessage = '网络连接失败，请检查网络连接';
        }
        
        document.getElementById('siteUptimeHistoryContent').innerHTML = \`
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>加载失败</strong><br>
                \${errorMessage}<br>
                <small class="text-muted">错误详情: \${error.message}</small>
            </div>
            <div class="text-center mt-3">
                <button class="btn btn-outline-primary btn-sm" onclick="loadSiteUptimeHistory('24h')">
                    <i class="bi bi-arrow-clockwise me-1"></i>重试
                </button>
            </div>
        \`;
    }
}

// 渲染网站在线率历史内容
function renderSiteUptimeHistory(data) {
    const content = document.getElementById('siteUptimeHistoryContent');
    
    let html = \`
        <div class="row mb-4">
            <div class="col-md-6">
                <h6><i class="bi bi-globe me-2"></i>\${data.siteName}</h6>
                <p class="text-muted mb-1">URL: \${data.siteUrl}</p>
                <p class="text-muted mb-1">统计时间段: \${data.period}</p>
                <p class="text-muted">开始时间: \${data.startTimeFormatted}</p>
            </div>
            <div class="col-md-6">
                <div class="row text-center">
                    <div class="col-4">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 \${data.uptime >= 95 ? 'text-success' : data.uptime >= 80 ? 'text-warning' : 'text-danger'}">\${data.uptime}%</div>
                            <small class="text-muted">在线率</small>
                        </div>
                    </div>
                    <div class="col-4">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 text-success">\${data.onlineTime}分</div>
                            <small class="text-muted">在线时间</small>
                        </div>
                    </div>
                    <div class="col-4">
                        <div class="border rounded p-2">
                            <div class="h5 mb-1 text-info">\${data.downtimeCount}</div>
                            <small class="text-muted">断开次数</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    \`;
    
    if (data.downtimes && data.downtimes.length > 0) {
        html += \`
            <h6><i class="bi bi-exclamation-triangle-fill text-warning me-2"></i>断开记录</h6>
            <div class="table-responsive">
                <table class="table table-sm table-striped">
                    <thead>
                        <tr>
                            <th>断开时间</th>
                            <th>恢复时间</th>
                            <th>持续时间</th>
                            <th>状态码</th>
                            <th>响应时间</th>
                            <th>备注</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
        \`;
        
        data.downtimes.forEach(downtime => {
            const rowClass = downtime.endTime === null ? 'table-danger' : '';
            html += \`
                <tr class="\${rowClass}">
                    <td>\${downtime.startTimeFormatted}</td>
                    <td>\${downtime.endTimeFormatted}</td>
                    <td>\${downtime.durationFormatted}</td>
                    <td>\${downtime.statusCode}</td>
                    <td>\${downtime.responseTimeMs === '-' ? '-' : downtime.responseTimeMs + 'ms'}</td>
                    <td>
                        <span class="note-display" id="note-\${downtime.id}">\${downtime.note || '无备注'}</span>
                        <input type="text" class="form-control form-control-sm note-input d-none" id="input-\${downtime.id}" value="\${downtime.note || ''}" maxlength="100">
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary btn-sm edit-note-btn" onclick="editNote('\${downtime.id}')" title="编辑备注">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <button class="btn btn-outline-success btn-sm save-note-btn d-none" onclick="saveNote('\${downtime.id}')" title="保存">
                                <i class="bi bi-check"></i>
                            </button>
                            <button class="btn btn-outline-secondary btn-sm cancel-note-btn d-none" onclick="cancelEditNote('\${downtime.id}')" title="取消">
                                <i class="bi bi-x"></i>
                            </button>
                            \${downtime.endTime !== null ? \`<button class="btn btn-outline-danger btn-sm" onclick="deleteDowntime('\${downtime.id}')" title="删除记录"><i class="bi bi-trash"></i></button>\` : ''}
                        </div>
                    </td>
                </tr>
            \`;
        });
        
        html += \`
                    </tbody>
                </table>
            </div>
        \`;
    } else {
        html += \`
            <div class="alert alert-success">
                <i class="bi bi-check-circle me-2"></i>
                在此时间段内没有断开记录，网站一直保持在线状态！
            </div>
        \`;
    }
    
    content.innerHTML = html;
}

// 编辑备注
function editNote(downtimeId) {
    const display = document.getElementById(\`note-\${downtimeId}\`);
    const input = document.getElementById(\`input-\${downtimeId}\`);
    const editBtn = display.parentElement.parentElement.querySelector('.edit-note-btn');
    const saveBtn = display.parentElement.parentElement.querySelector('.save-note-btn');
    const cancelBtn = display.parentElement.parentElement.querySelector('.cancel-note-btn');
    
    display.classList.add('d-none');
    input.classList.remove('d-none');
    editBtn.classList.add('d-none');
    saveBtn.classList.remove('d-none');
    cancelBtn.classList.remove('d-none');
    
    input.focus();
}

// 取消编辑备注
function cancelEditNote(downtimeId) {
    const display = document.getElementById(\`note-\${downtimeId}\`);
    const input = document.getElementById(\`input-\${downtimeId}\`);
    const editBtn = display.parentElement.parentElement.querySelector('.edit-note-btn');
    const saveBtn = display.parentElement.parentElement.querySelector('.save-note-btn');
    const cancelBtn = display.parentElement.parentElement.querySelector('.cancel-note-btn');
    
    display.classList.remove('d-none');
    input.classList.add('d-none');
    editBtn.classList.remove('d-none');
    saveBtn.classList.add('d-none');
    cancelBtn.classList.add('d-none');
}

// 保存备注
async function saveNote(downtimeId) {
    const display = document.getElementById(\`note-\${downtimeId}\`);
    const input = document.getElementById(\`input-\${downtimeId}\`);
    const newNote = input.value.trim();
    
    try {
        // 这里需要实现保存备注的API调用
        await apiRequest(\`/api/sites/downtime/\${downtimeId}/note\`, {
            method: 'PUT',
            body: JSON.stringify({ note: newNote })
        });
        
        display.textContent = newNote || '无备注';
        cancelEditNote(downtimeId);
        showToast('success', '备注已保存');
    } catch (error) {
        console.error('保存备注失败:', error);
        showToast('danger', '保存备注失败: ' + error.message);
    }
}

// 删除断开记录
async function deleteDowntime(downtimeId) {
    if (!confirm('确定要删除这条断开记录吗？此操作不可撤销。')) {
        return;
    }
    
    try {
        await apiRequest(\`/api/sites/downtime/\${downtimeId}\`, {
            method: 'DELETE'
        });
        
        showToast('success', '断开记录已删除');
        // 重新加载当前时间段的数据
        const period = document.querySelector('input[name="siteUptimePeriod"]:checked').value;
        loadSiteUptimeHistory(period);
    } catch (error) {
        console.error('删除记录失败:', error);
        showToast('danger', '删除记录失败: ' + error.message);
    }
}

// Render 24h history bar for a site (unified function for PC and mobile)
function renderSiteHistoryBar(containerElement, history) {
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

        const recordForHour = history?.find(
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

    containerElement.innerHTML = historyHtml;
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

// ==================== 全局背景设置功能 ====================

// 全局背景设置加载函数
async function loadGlobalBackgroundSettings() {
    try {
        // 检查localStorage缓存（无痕模式兼容）
        const cacheKey = 'background-settings-cache';
        let cached = null;
        let settings = null;

        try {
            cached = localStorage.getItem(cacheKey);
        } catch (storageError) {
                    }

        if (cached) {
            try {
                const cachedData = JSON.parse(cached);
                const now = Date.now();
                const cacheAge = now - cachedData.timestamp;
                const CACHE_DURATION = 5 * 60 * 1000; // 5分钟缓存

                if (cacheAge < CACHE_DURATION) {
                    settings = cachedData;
                                    }
            } catch (parseError) {
                            }
        }

        // 缓存过期或不存在，从API获取
        if (!settings) {
            try {
                const response = await fetch('/api/background-settings');
                if (response.ok) {
                    const apiSettings = await response.json();
                    settings = {
                        enabled: apiSettings.enabled,
                        url: apiSettings.url,
                        opacity: apiSettings.opacity,
                        timestamp: Date.now()
                    };

                    // 尝试更新缓存（无痕模式可能失败，但不影响功能）
                    try {
                        localStorage.setItem(cacheKey, JSON.stringify(settings));
                                            } catch (storageError) {
                                            }
                } else {
                                        settings = { enabled: false, url: '', opacity: 80 };
                }
            } catch (error) {
                                settings = { enabled: false, url: '', opacity: 80 };
            }
        }

        // 应用背景设置
        applyGlobalBackgroundSettings(settings.enabled, settings.url, settings.opacity);

    } catch (error) {
            }
}

// 应用全局背景设置
function applyGlobalBackgroundSettings(enabled, url, opacity) {
    const body = document.body;

    if (enabled && url) {
        // 验证URL格式
        if (!url.startsWith('https://')) {
                        return;
        }

        // 预加载图片，确保加载成功
        const img = new Image();
        img.onload = function() {
            // 图片加载成功，应用背景
            body.style.setProperty('--custom-background-url', \`url(\${url})\`);
            body.style.setProperty('--page-opacity', opacity / 100);
            body.classList.add('custom-background-enabled');



                    };
        img.onerror = function() {
            // 图片加载失败，不应用背景
            body.classList.remove('custom-background-enabled');
            body.classList.remove('low-contrast', 'medium-contrast', 'high-contrast');
        };
        img.src = url;
    } else {
        // 移除背景设置
        body.style.removeProperty('--custom-background-url');
        body.style.removeProperty('--page-opacity');
        body.classList.remove('custom-background-enabled');
            }
}



// 页面加载时初始化背景设置
document.addEventListener('DOMContentLoaded', function() {
    loadGlobalBackgroundSettings();
});

// 监听storage事件，实现跨页面设置同步
window.addEventListener('storage', function(e) {
    if (e.key === 'background-settings-cache' && e.newValue) {
        try {
            const newSettings = JSON.parse(e.newValue);
            applyGlobalBackgroundSettings(newSettings.enabled, newSettings.url, newSettings.opacity);
                    } catch (error) {
                    }
    }
});
`;
}

function getLoginJs() {
  return `// login.js - 登录页面的JavaScript逻辑

// ==================== 统一API请求工具 ====================
// 注意：此处的apiRequest函数已移至主要位置，避免重复定义

// --- Theme Management (copied from main.js) ---
const THEME_KEY = 'vps-monitor-theme';
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
            showToast('warning', '请输入用户名和密码');
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

// ==================== 统一API请求工具 ====================

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    return headers;
}

// 统一API请求函数
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: getAuthHeaders(),
        ...options
    };

    try {
        const response = await fetch(url, defaultOptions);

        // 处理认证失败
        if (response.status === 401) {
            localStorage.removeItem('auth_token');
            if (window.location.pathname !== '/login.html') {
                window.location.href = 'login.html';
            }
            throw new Error('认证失败，请重新登录');
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`请求失败 (\${response.status})\`);
        }

        return await response.json();
    } catch (error) {
                throw error;
    }
}

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

        const data = await apiRequest('/api/auth/status');

        if (data.authenticated) {
            // 已登录，重定向到管理后台
            window.location.href = 'admin.html';
        }
    } catch (error) {
            }
}

// 登录函数
async function login(username, password) {
    try {
        // 显示加载状态
        const loginForm = document.getElementById('loginForm');
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 登录中...';

        // 发送登录请求（不需要认证头）
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`登录失败 (\${response.status})\`);
        }

        const data = await response.json();

        // 恢复按钮状态
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;

        // 保存token到localStorage
        localStorage.setItem('auth_token', data.token);

        // 直接跳转到管理后台
        window.location.href = 'admin.html';

    } catch (error) {
                // 恢复按钮状态
        const loginForm = document.getElementById('loginForm');
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '登录';

        showToast('danger', error.message || '登录请求失败，请稍后重试');
    }
}



// ==================== 全局背景设置功能 ====================

// 全局背景设置加载函数（登录页面版本）
async function loadGlobalBackgroundSettings() {
    try {
        // 检查localStorage缓存（无痕模式兼容）
        const cacheKey = 'background-settings-cache';
        let cached = null;
        let settings = null;

        try {
            cached = localStorage.getItem(cacheKey);
        } catch (storageError) {
                    }

        if (cached) {
            try {
                const cachedData = JSON.parse(cached);
                const now = Date.now();
                const cacheAge = now - cachedData.timestamp;
                const CACHE_DURATION = 5 * 60 * 1000; // 5分钟缓存

                if (cacheAge < CACHE_DURATION) {
                    settings = cachedData;
                                    }
            } catch (parseError) {
                            }
        }

        // 缓存过期或不存在，从API获取
        if (!settings) {
            try {
                const response = await fetch('/api/background-settings');
                if (response.ok) {
                    const apiSettings = await response.json();
                    settings = {
                        enabled: apiSettings.enabled,
                        url: apiSettings.url,
                        opacity: apiSettings.opacity,
                        timestamp: Date.now()
                    };

                    // 尝试更新缓存（无痕模式可能失败，但不影响功能）
                    try {
                        localStorage.setItem(cacheKey, JSON.stringify(settings));
                                            } catch (storageError) {
                                            }
                } else {
                                        settings = { enabled: false, url: '', opacity: 80 };
                }
            } catch (error) {
                                settings = { enabled: false, url: '', opacity: 80 };
            }
        }

        // 应用背景设置
        applyGlobalBackgroundSettings(settings.enabled, settings.url, settings.opacity);

    } catch (error) {
            }
}

// 应用全局背景设置
function applyGlobalBackgroundSettings(enabled, url, opacity) {
    const body = document.body;

    if (enabled && url) {
        // 验证URL格式
        if (!url.startsWith('https://')) {
                        return;
        }

        // 预加载图片，确保加载成功
        const img = new Image();
        img.onload = function() {
            // 图片加载成功，应用背景
            body.style.setProperty('--custom-background-url', \`url(\${url})\`);
            body.style.setProperty('--page-opacity', opacity / 100);
            body.classList.add('custom-background-enabled');



                    };
        img.onerror = function() {
            // 图片加载失败，不应用背景
            body.classList.remove('custom-background-enabled');
        };
        img.src = url;
    } else {
        // 移除背景设置
        body.style.removeProperty('--custom-background-url');
        body.style.removeProperty('--page-opacity');
        body.classList.remove('custom-background-enabled');
            }
}



// 页面加载时初始化背景设置
document.addEventListener('DOMContentLoaded', function() {
    loadGlobalBackgroundSettings();
});

// 监听storage事件，实现跨页面设置同步
window.addEventListener('storage', function(e) {
    if (e.key === 'background-settings-cache' && e.newValue) {
        try {
            const newSettings = JSON.parse(e.newValue);
            applyGlobalBackgroundSettings(newSettings.enabled, newSettings.url, newSettings.opacity);
                    } catch (error) {
                    }
    }
});
`;
}
// Helper functions for updating server/site settings are no longer needed for frequent notifications
// as that feature is removed.

function getAdminJs() {
  return `// admin.js - 管理后台的JavaScript逻辑

// ==================== 统一API请求工具 ====================

// 获取认证头
function getAuthHeaders() {
    const token = localStorage.getItem('auth_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    return headers;
}

// 统一API请求函数
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: getAuthHeaders(),
        ...options
    };

    try {
        const response = await fetch(url, defaultOptions);

        // 处理认证失败
        if (response.status === 401) {
            localStorage.removeItem('auth_token');
            window.location.href = 'login.html';
            throw new Error('认证失败，请重新登录');
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || \`请求失败 (\${response.status})\`);
        }

        return await response.json();
    } catch (error) {
                throw error;
    }
}

// Global variables for VPS data updates
let vpsUpdateInterval = null;
const DEFAULT_VPS_REFRESH_INTERVAL_MS = 60000; // Default to 60 seconds for VPS data if backend setting fails

// Function to fetch VPS refresh interval and start periodic VPS data updates
async function initializeVpsDataUpdates() {
        let vpsRefreshIntervalMs = DEFAULT_VPS_REFRESH_INTERVAL_MS;

    try {
                const data = await apiRequest('/api/admin/settings/vps-report-interval');
                if (data && typeof data.interval === 'number' && data.interval > 0) {
            vpsRefreshIntervalMs = data.interval * 1000; // Convert seconds to milliseconds
                    } else {
            // 使用默认值
        }
    } catch (error) {
            }

    // Clear existing interval if any
    if (vpsUpdateInterval) {
                clearInterval(vpsUpdateInterval);
    }

    // Set up new periodic updates for VPS data ONLY
        vpsUpdateInterval = setInterval(() => {
                // Reload server list to get updated data
        if (typeof loadServerList === 'function') {
            loadServerList();
        }
    }, vpsRefreshIntervalMs);

    }

// --- Theme Management (copied from main.js) ---
const THEME_KEY = 'vps-monitor-theme';
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

// 工具提示现在使用浏览器原生title属性，无需JavaScript初始化

// 优化的清理函数 - 清理可能卡住的开关
function cleanupStuckToggles() {
    const stuckToggles = document.querySelectorAll('[data-updating="true"]');
    if (stuckToggles.length > 0) {
                stuckToggles.forEach(toggle => {
            toggle.disabled = false;
            delete toggle.dataset.updating;
            toggle.style.opacity = '1';
        });
    }
}

// 移除了复杂的waitForToggleReady函数，现在直接在API响应后更新UI状态

// 全局变量
let currentServerId = null;
let currentRealtimeEndPoint = null;
let currentSiteId = null; // For site deletion
let serverList = [];
let siteList = []; // For monitored sites
let hasAddedNewServer = false; // 标记是否添加了新服务器

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', async function() {
    // Initialize theme
    initializeTheme();

    // 检查登录状态 - 必须先完成认证检查
    await checkLoginStatus();

    // 初始化事件监听
    initEventListeners();

    // 初始化Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // 加载服务器列表
    loadServerList();
    // 加载监控网站列表
    loadSiteList();
    // 加载Telegram设置
    loadTelegramSettings();
    // 加载背景设置
    loadBackgroundSettings();
    // 加载全局设置 (VPS Report Interval) - will use serverAlert for notifications
    loadGlobalSettings();

    // 初始化管理后台的定时刷新机制
    initializeVpsDataUpdates();

    // 检查是否使用默认密码
    checkDefaultPasswordUsage();

    // 优化：停止自动清理以节省配额
    // setInterval(cleanupStuckToggles, 30000);
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

        const data = await apiRequest('/api/auth/status');
        if (!data.authenticated) {
            // 未登录，重定向到登录页面
            window.location.href = 'login.html';
        }
    } catch (error) {
                window.location.href = 'login.html';
    }
}

// 检查是否使用默认密码
async function checkDefaultPasswordUsage() {
    try {
        // 从localStorage获取是否显示过默认密码提醒
        const hasShownDefaultPasswordWarning = localStorage.getItem('hasShownDefaultPasswordWarning');

        if (hasShownDefaultPasswordWarning === 'true') {
            return; // 已经显示过提醒，不再显示
        }

        // 检查当前用户登录状态和默认密码使用情况
        const token = localStorage.getItem('auth_token');
                if (token) {
            try {
                const statusData = await apiRequest('/api/auth/status');
                if (statusData.authenticated && statusData.user && statusData.user.usingDefaultPassword) {
                    // 显示默认密码提醒
                    showToast('warning',
                        '安全提醒：您正在使用默认密码登录。为了您的账户安全，建议尽快修改密码。点击右上角的"修改密码"按钮来更改密码。',
                        { duration: 10000 }); // 10秒显示

                    // 标记已显示过提醒
                    localStorage.setItem('hasShownDefaultPasswordWarning', 'true');
                }
            } catch (error) {
                            }
        }
    } catch (error) {
            }
}

// 初始化在线率
async function initializeUptime() {
    if (typeof document === 'undefined') {
        console.error('初始化功能需要在浏览器环境中运行');
        return;
    }
    
    if (!confirm('确定要初始化所有服务器的在线率吗？这将清除所有历史在线率数据并重新开始计算。')) {
        return;
    }
    
    try {
        const response = await apiRequest('/api/admin/servers/init-uptime', {
            method: 'POST'
        });
        
        showToast('success', \`已初始化 \${response.count || 0} 个服务器的在线率\`);
        
        // 刷新在线率显示
        setTimeout(() => {
            if (typeof loadServerUptimeData === 'function') {
                loadServerUptimeData();
            }
        }, 1000);
        
    } catch (error) {
        showToast('danger', '初始化在线率失败: ' + error.message);
    }
}

// 初始化事件监听
function initEventListeners() {
    // 添加服务器按钮
    document.getElementById('addServerBtn').addEventListener('click', function() {
        showServerModal();
    });

    // 导出服务器按钮
    document.getElementById('exportServersBtn').addEventListener('click', function() {
        exportServers();
    });

    // 导入服务器按钮
    document.getElementById('importServersBtn').addEventListener('click', function() {
        document.getElementById('serverImportFile').click();
    });

    // 初始化在线率按钮
    document.getElementById('initUptimeBtn').addEventListener('click', function() {
        initializeUptime();
    });

    // 服务器导入文件选择
    document.getElementById('serverImportFile').addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            importServers(e.target.files[0]);
        }
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
            // 静默处理复制失败
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

    // 修改密码按钮（移动端）
    document.getElementById('changePasswordBtn').addEventListener('click', function() {
        showPasswordModal();
    });

    // 修改密码按钮（PC端）
    document.getElementById('changePasswordBtnDesktop').addEventListener('click', function() {
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

    // 导出网站按钮
    document.getElementById('exportSitesBtn').addEventListener('click', function() {
        exportSites();
    });

    // 导入网站按钮
    document.getElementById('importSitesBtn').addEventListener('click', function() {
        document.getElementById('siteImportFile').click();
    });

    // 网站导入文件选择
    document.getElementById('siteImportFile').addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            importSites(e.target.files[0]);
        }
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

    // Background Settings Event Listeners
    document.getElementById('saveBackgroundSettingsBtn').addEventListener('click', function() {
        saveBackgroundSettings();
    });

    // 透明度滑块实时预览
    document.getElementById('pageOpacity').addEventListener('input', function() {
        updateOpacityPreview();
    });

    // 背景开关变化时的预览
    document.getElementById('enableCustomBackground').addEventListener('change', function() {
        const enabled = this.checked;
        const url = document.getElementById('backgroundImageUrl').value.trim();
        const opacity = parseInt(document.getElementById('pageOpacity').value, 10);
        applyBackgroundSettings(enabled, url, opacity, false);
    });

    // URL输入框变化时的预览
    document.getElementById('backgroundImageUrl').addEventListener('input', function() {
        const enabled = document.getElementById('enableCustomBackground').checked;
        const url = this.value.trim();
        const opacity = parseInt(document.getElementById('pageOpacity').value, 10);
        if (enabled) {
            applyBackgroundSettings(enabled, url, opacity, false);
        }
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

// --- Server Management Functions ---

// 加载服务器列表
async function loadServerList() {
    try {
        const data = await apiRequest('/api/admin/servers');
        serverList = data.servers || [];

        // 简化逻辑：直接渲染，智能状态显示会处理更新中的按钮
        renderServerTable(serverList);
    } catch (error) {
                showToast('danger', '加载服务器列表失败，请刷新页面重试');
    }
}


// 渲染服务器表格
function renderServerTable(servers) {
    const tableBody = document.getElementById('serverTableBody');

    // 简化状态管理：不再需要复杂的状态保存机制

    tableBody.innerHTML = '';

    if (servers.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="12" class="text-center">暂无服务器数据</td>'; // Updated colspan
        tableBody.appendChild(row);
        // 同时更新移动端卡片
        renderMobileAdminServerCards([]);
        return;
    }

    servers.forEach((server, index) => {
        const row = document.createElement('tr');
        row.setAttribute('data-server-id', server.id);
        row.setAttribute('data-realtime-endpoint', server.realtime_endpoint);
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

        // 智能状态显示：完整保存更新中按钮的所有状态
        const existingToggle = document.querySelector('.server-visibility-toggle[data-server-id="' + server.id + '"]');
        const isCurrentlyUpdating = existingToggle && existingToggle.dataset.updating === 'true';
        const displayState = isCurrentlyUpdating ? existingToggle.checked : server.is_public;
        const needsUpdatingState = isCurrentlyUpdating;

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
            '<td>' +
                '<div class="form-check form-switch">' +
                    '<input class="form-check-input server-visibility-toggle" type="checkbox" data-server-id="' + server.id + '" ' + (displayState ? 'checked' : '') + (needsUpdatingState ? ' data-updating="true"' : '') + '>' +
                '</div>' +
            '</td>' +
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

    // 优化的显示开关事件监听 - 直接处理状态切换
    document.querySelectorAll('.server-visibility-toggle').forEach(toggle => {
        toggle.addEventListener('click', function(event) {
            // 如果开关正在更新中，忽略点击
            if (this.disabled || this.dataset.updating === 'true') {
                event.preventDefault();
                return;
            }

            const serverId = this.getAttribute('data-server-id');
            const targetState = this.checked; // 点击后的状态就是目标状态
            const originalState = !this.checked; // 原始状态是目标状态的相反

                        // 立即设置为加载状态
            this.disabled = true;
            this.style.opacity = '0.6';
            this.dataset.updating = 'true';

            updateServerVisibility(serverId, targetState, originalState, this);
        });
    });

    // 重新应用正在更新按钮的视觉状态（因为重新渲染会创建新元素）
    document.querySelectorAll('.server-visibility-toggle[data-updating="true"]').forEach(toggle => {
        toggle.disabled = true;
        toggle.style.opacity = '0.6';
    });

    // 同时渲染移动端卡片
    renderMobileAdminServerCards(servers);
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
        await apiRequest('/api/admin/servers/batch-reorder', {
            method: 'POST',
            body: JSON.stringify({ serverIds: newOrder })
        });

        // 重新加载服务器列表
        await loadServerList();
        showToast('success', '服务器排序已更新');

    } catch (error) {
                showToast('danger', '拖拽排序失败: ' + error.message);
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
        // 获取包含完整API密钥的服务器信息
        const response = await apiRequest('/api/admin/servers?full_key=true');
        const server = response.servers.find(s => s.id === serverId);

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

        showToast('success', '服务器 "' + serverName + '" 的安装脚本已复制到剪贴板');

    } catch (error) {
                showToast('danger', '复制脚本失败: ' + error.message);
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

// 更新服务器显示状态
async function updateServerVisibility(serverId, isPublic, originalState, toggleElement) {
    const startTime = Date.now();
        try {
        const data = await apiRequest('/api/admin/servers/' + serverId + '/visibility', {
            method: 'POST',
            body: JSON.stringify({ is_public: isPublic })
        });

        const requestTime = Date.now() - startTime;
                // 更新本地数据
        const serverIndex = serverList.findIndex(s => s.id === serverId);
        if (serverIndex !== -1) {
            serverList[serverIndex].is_public = isPublic;
        }

        // 成功后设置最终正常状态 - 使用可靠的恢复机制
        function restoreButtonState(retryCount = 0) {
            const currentToggle = document.querySelector('.server-visibility-toggle[data-server-id="' + serverId + '"]');
            if (currentToggle) {
                                currentToggle.checked = isPublic;
                currentToggle.style.opacity = '1';
                currentToggle.disabled = false;
                delete currentToggle.dataset.updating;

                // 直接显示成功提醒
                showToast('success', '服务器显示状态已' + (isPublic ? '开启' : '关闭'));
            } else if (retryCount < 3) {
                                setTimeout(() => restoreButtonState(retryCount + 1), 100);
            } else {
                // 静默处理按钮元素未找到
            }
        }

        // 立即尝试恢复，如果失败则重试
        restoreButtonState();

    } catch (error) {
                // 失败时恢复原始状态
        const currentToggle = document.querySelector('.server-visibility-toggle[data-server-id="' + serverId + '"]');
        if (currentToggle) {
            currentToggle.checked = originalState;
            currentToggle.style.opacity = '1';
            currentToggle.disabled = false;
            delete currentToggle.dataset.updating;

            // 直接显示错误提醒，不需要等待状态变化
            showToast('danger', '更新显示状态失败: ' + error.message);
        } else {
            // 如果找不到开关元素，立即显示错误
            showToast('danger', '更新显示状态失败: ' + error.message);
        }
    }
}

// 移动服务器顺序
async function moveServer(serverId, direction) {
    try {
        await apiRequest('/api/admin/servers/' + serverId + '/reorder', {
            method: 'POST',
            body: JSON.stringify({ direction })
        });

        // 重新加载列表以反映新顺序
        await loadServerList();
        showToast('success', '服务器已成功' + (direction === 'up' ? '上移' : '下移'));

    } catch (error) {
                showToast('danger', '移动服务器失败: ' + error.message);
    }
}

// 显示服务器模态框（添加模式）
function showServerModal() {
    // 重置表单和标记
    document.getElementById('serverForm').reset();
    document.getElementById('serverId').value = '';
    document.getElementById('vpsRealApi').value = '';
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
    document.getElementById('vpsRealApi').value = server.realtime_endpoint || '';
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
    const vpsRealApi = document.getElementById('vpsRealApi').value.trim(); // Removed

    if (!serverName) {
        showToast('warning', '服务器名称不能为空');
        return;
    }

    try {
        let data;

        if (serverId) {
            // 更新服务器
            data = await apiRequest('/api/admin/servers/' + serverId, {
                method: 'PUT',
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription,
		    realtime_endpoint: vpsRealApi
                })
            });
        } else {
            // 添加服务器
            data = await apiRequest('/api/admin/servers', {
                method: 'POST',
                body: JSON.stringify({
                    name: serverName,
                    description: serverDescription,
		    realtime_endpoint: vpsRealApi
                })
            });
        }

        // 如果是新添加的服务器，流畅地切换到密钥显示（不隐藏模态框）
        if (!serverId && data.server && data.server.api_key) {
            hasAddedNewServer = true; // 标记已添加新服务器

            // 直接在当前模态框中显示密钥信息，提供流畅的用户体验
            // 不隐藏模态框，而是切换内容，让用户感觉是自然的过渡
            showApiKeyInCurrentModal(data.server);
            showToast('success', '服务器添加成功');

            // 在后台异步刷新服务器列表
            loadServerList().catch(error => {
                            });
        } else {
            // 编辑服务器的情况，正常隐藏模态框并刷新列表
            const serverModal = bootstrap.Modal.getInstance(document.getElementById('serverModal'));
            serverModal.hide();

            await loadServerList();
            showToast('success', serverId ? '服务器更新成功' : '服务器添加成功');
        }
    } catch (error) {
                showToast('danger', '保存服务器失败，请稍后重试');
    }
}

// 查看API密钥（获取完整密钥版本）
async function viewApiKey(serverId) {
    try {
        // 请求包含完整API密钥的服务器信息
        const response = await apiRequest('/api/admin/servers?full_key=true');
        const server = response.servers.find(s => s.id === serverId);

        if (server && server.api_key) {
            showApiKey(server);
        } else {
            showToast('danger', '未找到服务器信息或API密钥，请稍后重试');
        }
    } catch (error) {
                showToast('danger', '查看API密钥失败，请稍后重试');
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
        await apiRequest('/api/admin/servers/' + serverId + '?confirm=true', {
            method: 'DELETE'
        });

        // 隐藏模态框
        const deleteModal = bootstrap.Modal.getInstance(document.getElementById('deleteModal'));
        deleteModal.hide();

        // 重新加载服务器列表
        loadServerList();
        showToast('success', '服务器删除成功');
    } catch (error) {
                showToast('danger', '删除服务器失败，请稍后重试');
    }
}


// --- Site Monitoring Functions (Continued) ---

// 更新网站显示状态
async function updateSiteVisibility(siteId, isPublic, originalState, toggleElement) {
    const startTime = Date.now();
        try {
        await apiRequest('/api/admin/sites/' + siteId + '/visibility', {
            method: 'POST',
            body: JSON.stringify({ is_public: isPublic })
        });

        const requestTime = Date.now() - startTime;
                        // 更新本地数据
        const siteIndex = siteList.findIndex(s => s.id === siteId);
        if (siteIndex !== -1) {
            siteList[siteIndex].is_public = isPublic;
        }

        // 成功后设置最终正常状态 - 使用可靠的恢复机制
        function restoreButtonState(retryCount = 0) {
            const currentToggle = document.querySelector('.site-visibility-toggle[data-site-id="' + siteId + '"]');
            if (currentToggle) {
                                currentToggle.checked = isPublic;
                currentToggle.style.opacity = '1';
                currentToggle.disabled = false;
                delete currentToggle.dataset.updating;

                // 直接显示成功提醒
                showToast('success', '网站显示状态已' + (isPublic ? '开启' : '关闭'));
            } else if (retryCount < 3) {
                                setTimeout(() => restoreButtonState(retryCount + 1), 100);
            } else {
                // 静默处理网站按钮元素未找到
            }
        }

        // 立即尝试恢复，如果失败则重试
        restoreButtonState();

    } catch (error) {
                // 失败时恢复原始状态
        const currentToggle = document.querySelector('.site-visibility-toggle[data-site-id="' + siteId + '"]');
        if (currentToggle) {
            currentToggle.checked = originalState;
            currentToggle.style.opacity = '1';
            currentToggle.disabled = false;
            delete currentToggle.dataset.updating;

            // 直接显示错误提醒，不需要等待状态变化
            showToast('danger', '更新显示状态失败: ' + error.message);
        } else {
            // 如果找不到开关元素，立即显示错误
            showToast('danger', '更新显示状态失败: ' + error.message);
        }
    }
}

// 移动网站顺序
async function moveSite(siteId, direction) {
    try {
        await apiRequest('/api/admin/sites/' + siteId + '/reorder', {
            method: 'POST',
            body: JSON.stringify({ direction })
        });

        // 重新加载列表以反映新顺序
        await loadSiteList();
        showToast('success', '网站已成功' + (direction === 'up' ? '上移' : '下移'));

    } catch (error) {
                showToast('danger', '移动网站失败: ' + error.message);
    }
}


// --- Password Management Functions ---

// 显示密码修改模态框
function showPasswordModal() {
    // 重置表单
    document.getElementById('passwordForm').reset();

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
        showToast('warning', '所有密码字段都必须填写');
        return;
    }

    if (newPassword !== confirmPassword) {
        showToast('warning', '新密码和确认密码不匹配');
        return;
    }

    try {
        await apiRequest('/api/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        // 隐藏模态框
        const passwordModal = bootstrap.Modal.getInstance(document.getElementById('passwordModal'));
        passwordModal.hide();

        // 清除默认密码提醒标记，这样如果用户再次使用默认密码登录会重新提醒
        localStorage.removeItem('hasShownDefaultPasswordWarning');

        showToast('success', '密码修改成功');
    } catch (error) {
                showToast('danger', '密码修改请求失败，请稍后重试');
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
        const data = await apiRequest('/api/admin/sites');
        siteList = data.sites || [];

        // 简化逻辑：直接渲染，智能状态显示会处理更新中的按钮
        renderSiteTable(siteList);
    } catch (error) {
                showToast('danger', '加载监控网站列表失败: ' + error.message);
    }
}

// 渲染监控网站表格
function renderSiteTable(sites) {
    const tableBody = document.getElementById('siteTableBody');

    // 简化状态管理：不再需要复杂的状态保存机制

    tableBody.innerHTML = '';

    if (sites.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="9" class="text-center">暂无监控网站</td></tr>'; // Colspan updated
        // 同时更新移动端卡片
        renderMobileAdminSiteCards([]);
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

        // 智能状态显示：完整保存更新中按钮的所有状态
        const existingToggle = document.querySelector('.site-visibility-toggle[data-site-id="' + site.id + '"]');
        const isCurrentlyUpdating = existingToggle && existingToggle.dataset.updating === 'true';
        const displayState = isCurrentlyUpdating ? existingToggle.checked : site.is_public;
        const needsUpdatingState = isCurrentlyUpdating;

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
            <td>
                <div class="form-check form-switch">
                    <input class="form-check-input site-visibility-toggle" type="checkbox" data-site-id="\${site.id}" \${displayState ? 'checked' : ''}\${needsUpdatingState ? ' data-updating="true"' : ''}>
                </div>
            </td>
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

    // 优化的网站显示开关事件监听 - 直接处理状态切换
    document.querySelectorAll('.site-visibility-toggle').forEach(toggle => {
        toggle.addEventListener('click', function(event) {
            // 如果开关正在更新中，忽略点击
            if (this.disabled || this.dataset.updating === 'true') {
                event.preventDefault();
                return;
            }

            const siteId = this.getAttribute('data-site-id');
            const targetState = this.checked; // 点击后的状态就是目标状态
            const originalState = !this.checked; // 原始状态是目标状态的相反

                        // 立即设置为加载状态
            this.disabled = true;
            this.style.opacity = '0.6';
            this.dataset.updating = 'true';

            updateSiteVisibility(siteId, targetState, originalState, this);
        });
    });

    // 重新应用正在更新按钮的视觉状态（因为重新渲染会创建新元素）
    document.querySelectorAll('.site-visibility-toggle[data-updating="true"]').forEach(toggle => {
        toggle.disabled = true;
        toggle.style.opacity = '0.6';
    });

    // 同时渲染移动端卡片
    renderMobileAdminSiteCards(sites);
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
        await apiRequest('/api/admin/sites/batch-reorder', {
            method: 'POST',
            body: JSON.stringify({ siteIds: newOrder })
        });

        // 重新加载网站列表
        await loadSiteList();
        showToast('success', '网站排序已更新');

    } catch (error) {
                showToast('danger', '拖拽排序失败: ' + error.message);
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
            showToast('danger', '未找到要编辑的网站信息');
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
        showToast('warning', '请输入网站URL');
        return;
    }
    if (!siteUrl.startsWith('http://') && !siteUrl.startsWith('https://')) {
         showToast('warning', 'URL必须以 http:// 或 https:// 开头');
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
        const responseData = await apiRequest(apiUrl, {
            method: method,
            body: JSON.stringify(requestBody)
        });

        const siteModalInstance = bootstrap.Modal.getInstance(document.getElementById('siteModal'));
        if (siteModalInstance) {
            siteModalInstance.hide();
        }

        await loadSiteList(); // Reload the list
        showToast('success', '监控网站' + (siteId ? '更新' : '添加') + '成功');

    } catch (error) {
                showToast('danger', '保存网站失败: ' + error.message);
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
        await apiRequest(\`/api/admin/sites/\${siteId}?confirm=true\`, {
            method: 'DELETE'
        });

        // Hide modal and reload list
        const deleteModal = bootstrap.Modal.getInstance(document.getElementById('deleteSiteModal'));
        deleteModal.hide();
        await loadSiteList(); // Reload list
        showToast('success', '网站监控已删除');
        currentSiteId = null; // Reset current ID

    } catch (error) {
                showToast('danger', '删除网站失败: ' + error.message);
    }
}


// --- Utility Functions ---

// 统一Toast弹窗函数 (增强版)
function showToast(type, message, options = {}) {
    const defaults = {
        success: 3000,
        info: 5000,
        warning: 8000,
        danger: 10000
    };

    const duration = options.duration || defaults[type] || 5000;
    const persistent = options.persistent || false;

    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'unified-toast ' + type;

    const icons = {
        success: 'bi-check-circle-fill',
        danger: 'bi-x-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill'
    };

    toast.innerHTML =
        '<i class="toast-icon bi ' + icons[type] + '"></i>' +
        '<div class="toast-content">' + message + '</div>' +
        '<button class="toast-close" onclick="hideToast(this.parentElement)">×</button>' +
        (persistent ? '' : '<div class="toast-progress" style="animation-duration: ' + duration + 'ms"></div>');

    container.appendChild(toast);

    if (!persistent) {
        setTimeout(() => hideToast(toast), duration);
    }

    return toast;
}

function hideToast(toast) {
    if (!toast || toast.classList.contains('hiding')) return;
    toast.classList.add('hiding');
    setTimeout(function() {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 300);
}





// --- Telegram Settings Functions ---

// 加载Telegram通知设置
async function loadTelegramSettings() {
    try {
        const settings = await apiRequest('/api/admin/telegram-settings');
        if (settings) {
            document.getElementById('telegramBotToken').value = settings.bot_token || '';
            document.getElementById('telegramChatId').value = settings.chat_id || '';
            document.getElementById('enableTelegramNotifications').checked = !!settings.enable_notifications;
        }
    } catch (error) {
                showToast('danger', '加载Telegram设置失败: ' + error.message);
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
             showToast('warning', 'Bot Token 和 Chat ID 均不能为空才能启用通知。通知已自动禁用');
        }
    } else if (enableNotifications && (!botToken || !chatId)) { // This case should ideally not be hit due to above logic, but kept for safety
        showToast('warning', '启用通知时，Bot Token 和 Chat ID 不能为空');
        return;
    }


    try {
        await apiRequest('/api/admin/telegram-settings', {
            method: 'POST',
            body: JSON.stringify({
                bot_token: botToken,
                chat_id: chatId,
                enable_notifications: enableNotifications // Use the potentially modified value
            })
        });

        showToast('success', 'Telegram设置已成功保存');

    } catch (error) {
            showToast('danger', '保存Telegram设置失败: ' + error.message);
    }
}

// --- Background Settings Functions ---

// 加载背景设置
async function loadBackgroundSettings() {
    try {
        const settings = await apiRequest('/api/background-settings');
        if (settings) {
            document.getElementById('enableCustomBackground').checked = !!settings.enabled;
            document.getElementById('backgroundImageUrl').value = settings.url || '';
            document.getElementById('pageOpacity').value = settings.opacity || 80;
            document.getElementById('opacityValue').textContent = settings.opacity || 80;

            // 应用当前设置（不保存到数据库）
            applyBackgroundSettings(settings.enabled, settings.url, settings.opacity, false);
        }
    } catch (error) {
                showToast('danger', '加载背景设置失败: ' + error.message);
    }
}

// 保存背景设置
async function saveBackgroundSettings() {
    const enabled = document.getElementById('enableCustomBackground').checked;
    const url = document.getElementById('backgroundImageUrl').value.trim();
    const opacity = parseInt(document.getElementById('pageOpacity').value, 10);

    // 验证输入
    if (enabled && url) {
        if (!url.startsWith('https://')) {
            showToast('warning', '背景图片URL必须以https://开头');
            return;
        }
    }

    if (isNaN(opacity) || opacity < 0 || opacity > 100) {
        showToast('warning', '透明度必须是0-100之间的数字');
        return;
    }

    try {
        await apiRequest('/api/admin/background-settings', {
            method: 'POST',
            body: JSON.stringify({
                enabled: enabled,
                url: url,
                opacity: opacity
            })
        });

        // 应用设置并保存到localStorage
        applyBackgroundSettings(enabled, url, opacity, true);

        showToast('success', '背景设置已成功保存');

    } catch (error) {
                showToast('danger', '保存背景设置失败: ' + error.message);
    }
}

// 应用背景设置
function applyBackgroundSettings(enabled, url, opacity, saveToCache = false) {
    const body = document.body;

    if (enabled && url) {
        // 设置背景图片
        body.style.setProperty('--custom-background-url', \`url(\${url})\`);
        body.style.setProperty('--page-opacity', opacity / 100);
        body.classList.add('custom-background-enabled');


    } else {
        // 移除背景图片
        body.style.removeProperty('--custom-background-url');
        body.style.removeProperty('--page-opacity');
        body.classList.remove('custom-background-enabled');


    }

    // 缓存设置到localStorage（可选）
    if (saveToCache) {
        const settings = { enabled, url, opacity, timestamp: Date.now() };
        localStorage.setItem('background-settings-cache', JSON.stringify(settings));
    }
}

// 实时预览透明度变化
function updateOpacityPreview() {
    const opacity = parseInt(document.getElementById('pageOpacity').value, 10);
    const enabled = document.getElementById('enableCustomBackground').checked;
    const url = document.getElementById('backgroundImageUrl').value.trim();

    // 更新显示的数值
    document.getElementById('opacityValue').textContent = opacity;

    // 实时预览（不保存）
    if (enabled && url) {
        document.body.style.setProperty('--page-opacity', opacity / 100);

    }
}



// --- Global Settings Functions (VPS Report Interval) ---
async function loadGlobalSettings() {
    try {
        const settings = await apiRequest('/api/admin/settings/vps-report-interval');
        if (settings && typeof settings.interval === 'number') {
            document.getElementById('vpsReportInterval').value = settings.interval;
        } else {
            document.getElementById('vpsReportInterval').value = 60; // Default if not set
        }
    } catch (error) {
                showToast('danger', '加载VPS报告间隔失败: ' + error.message);
        document.getElementById('vpsReportInterval').value = 60; // Default on error
    }
}

async function saveVpsReportInterval() {
    const intervalInput = document.getElementById('vpsReportInterval');
    const interval = parseInt(intervalInput.value, 10);

    if (isNaN(interval) || interval < 1) { // Changed to interval < 1
        showToast('warning', 'VPS报告间隔必须是一个大于或等于1的数字');
        return;
    }
    // Removed warning for interval < 10

    try {
        await apiRequest('/api/admin/settings/vps-report-interval', {
            method: 'POST',
            body: JSON.stringify({ interval: interval })
        });

        showToast('success', 'VPS数据更新频率已成功保存。前端刷新间隔已立即更新');

        // Immediately update the frontend refresh interval
        // Check if we're on a page that has VPS data updates running
        if (typeof initializeVpsDataUpdates === 'function') {
            try {
                await initializeVpsDataUpdates();
                            } catch (error) {
                            }
        }
    } catch (error) {
                showToast('danger', '保存VPS报告间隔失败: ' + error.message);
    }
}

// --- 自动排序功能 ---

// 服务器自动排序
async function autoSortServers(sortBy) {
    try {
        await apiRequest('/api/admin/servers/auto-sort', {
            method: 'POST',
            body: JSON.stringify({ sortBy: sortBy, order: 'asc' })
        });

        // 更新下拉菜单选中状态
        updateServerSortDropdownSelection(sortBy);

        // 重新加载服务器列表
        await loadServerList();
        showToast('success', '服务器已按' + getSortDisplayName(sortBy) + '排序');

    } catch (error) {
                showToast('danger', '服务器自动排序失败: ' + error.message);
    }
}

// 网站自动排序
async function autoSortSites(sortBy) {
    try {
        await apiRequest('/api/admin/sites/auto-sort', {
            method: 'POST',
            body: JSON.stringify({ sortBy: sortBy, order: 'asc' })
        });

        // 更新下拉菜单选中状态
        updateSiteSortDropdownSelection(sortBy);

        // 重新加载网站列表
        await loadSiteList();
        showToast('success', '网站已按' + getSortDisplayName(sortBy) + '排序');

    } catch (error) {
                showToast('danger', '网站自动排序失败: ' + error.message);
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
        card.setAttribute('data-realtime-endpoint', server.realtime_endpoint);

        // 状态显示逻辑（与PC端一致）
        let statusBadge = '<span class="badge bg-secondary">未知</span>';
        let lastUpdateText = '从未';

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

        // 卡片头部
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <div class="mobile-card-header-left">
                \${statusBadge}
            </div>
            <h6 class="mobile-card-title text-center">\${server.name || '未命名服务器'}</h6>
            <div class="mobile-card-header-right">
                <span class="me-2">显示</span>
                <div class="form-check form-switch d-inline-block">
                    <input class="form-check-input server-visibility-toggle" type="checkbox"
                           data-server-id="\${server.id}" \${server.is_public ? 'checked' : ''}>
                </div>
            </div>
        \`;

        // 卡片主体
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

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



        // 四个按钮 - 两行两列布局
        const buttonsContainer = document.createElement('div');
        buttonsContainer.className = 'mobile-card-buttons-grid';
        buttonsContainer.innerHTML = \`
            <div class="d-flex gap-2 mb-2">
                <button class="btn btn-outline-secondary btn-sm flex-fill" onclick="showServerApiKey('\${server.id}')">
                    <i class="bi bi-key"></i> 查看密钥
                </button>
                <button class="btn btn-outline-info btn-sm flex-fill" onclick="copyVpsInstallScript('\${server.id}', '\${server.name}', this)">
                    <i class="bi bi-clipboard"></i> 复制脚本
                </button>
            </div>
            <div class="d-flex gap-2">
                <button class="btn btn-outline-primary btn-sm flex-fill" onclick="editServer('\${server.id}')">
                    <i class="bi bi-pencil"></i> 编辑
                </button>
                <button class="btn btn-outline-danger btn-sm flex-fill" onclick="deleteServer('\${server.id}')">
                    <i class="bi bi-trash"></i> 删除
                </button>
            </div>
        \`;
        cardBody.appendChild(buttonsContainer);

        // 最后更新时间 - 底部单行（与PC端功能一致）
        const lastUpdateRow = document.createElement('div');
        lastUpdateRow.className = 'mobile-card-row mobile-card-footer';
        lastUpdateRow.innerHTML = \`
            <span class="mobile-card-label">最后更新: \${lastUpdateText}</span>
        \`;
        cardBody.appendChild(lastUpdateRow);

        // 组装卡片
        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        mobileContainer.appendChild(card);
    });

    // 为移动端显示开关添加事件监听器
    document.querySelectorAll('.server-visibility-toggle').forEach(toggle => {
        toggle.addEventListener('change', function() {
            const serverId = this.dataset.serverId;
            const isPublic = this.checked;
            toggleServerVisibility(serverId, isPublic);
        });
    });
}

// 切换服务器显示状态
async function toggleServerVisibility(serverId, isPublic) {
    try {
        const toggle = document.querySelector(\`.server-visibility-toggle[data-server-id="\${serverId}"]\`);
        if (toggle) {
            toggle.disabled = true;
            toggle.style.opacity = '0.6';
        }

        await apiRequest(\`/api/admin/servers/\${serverId}/visibility\`, {
            method: 'POST',
            body: JSON.stringify({ is_public: isPublic })
        });

        // 更新本地数据
        const serverIndex = serverList.findIndex(s => s.id === serverId);
        if (serverIndex !== -1) {
            serverList[serverIndex].is_public = isPublic;
        }

        if (toggle) {
            toggle.disabled = false;
            toggle.style.opacity = '1';
        }

        showToast('success', '服务器显示状态已' + (isPublic ? '开启' : '关闭'));

    } catch (error) {
                // 恢复开关状态
        const toggle = document.querySelector(\`.server-visibility-toggle[data-server-id="\${serverId}"]\`);
        if (toggle) {
            toggle.checked = !isPublic;
            toggle.disabled = false;
            toggle.style.opacity = '1';
        }

        showToast('danger', '切换显示状态失败: ' + error.message);
    }
}

// 管理页面移动端网站卡片渲染函数
function renderMobileAdminSiteCards(sites) {
    const mobileContainer = document.getElementById('mobileAdminSiteContainer');
    if (!mobileContainer) return;

    mobileContainer.innerHTML = '';

    // 添加居中的排序和添加网站按钮
    const mobileActionsContainer = document.createElement('div');
    mobileActionsContainer.className = 'text-center mb-3';
    mobileActionsContainer.innerHTML = \`
        <div class="d-flex gap-2 justify-content-center">
            <div class="dropdown">
                <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-sort-alpha-down"></i> 自动排序
                </button>
                <ul class="dropdown-menu">
                    <li><a class="dropdown-item active" href="#" onclick="autoSortSites('custom')">自定义排序</a></li>
                    <li><a class="dropdown-item" href="#" onclick="autoSortSites('name')">按名称排序</a></li>
                    <li><a class="dropdown-item" href="#" onclick="autoSortSites('url')">按URL排序</a></li>
                    <li><a class="dropdown-item" href="#" onclick="autoSortSites('status')">按状态排序</a></li>
                </ul>
            </div>
            <button id="addSiteBtnMobile" class="btn btn-success" onclick="showSiteModal()">
                <i class="bi bi-plus-circle"></i> 添加监控网站
            </button>
        </div>
    \`;
    mobileContainer.appendChild(mobileActionsContainer);

    if (!sites || sites.length === 0) {
        const noDataDiv = document.createElement('div');
        noDataDiv.className = 'text-center p-3 text-muted';
        noDataDiv.textContent = '暂无监控网站数据';
        mobileContainer.appendChild(noDataDiv);
        return;
    }

    sites.forEach(site => {
        const card = document.createElement('div');
        card.className = 'mobile-site-card';

        const statusInfo = getSiteStatusBadge(site.last_status);
        const lastCheckTime = site.last_checked ? new Date(site.last_checked * 1000).toLocaleString() : '从未';
        const responseTime = site.last_response_time_ms !== null ? \`\${site.last_response_time_ms} ms\` : '-';

        // 卡片头部 - 完全参考服务器卡片布局：状态在左上角，网站名在中间，显示开关在右上角
        const cardHeader = document.createElement('div');
        cardHeader.className = 'mobile-card-header';
        cardHeader.innerHTML = \`
            <div class="mobile-card-header-left">
                <span class="badge \${statusInfo.class}">\${statusInfo.text}</span>
            </div>
            <h6 class="mobile-card-title text-center">\${site.name || '未命名网站'}</h6>
            <div class="mobile-card-header-right">
                <span class="me-2">显示</span>
                <div class="form-check form-switch d-inline-block">
                    <input class="form-check-input site-visibility-toggle" type="checkbox"
                           data-site-id="\${site.id}" \${site.is_public ? 'checked' : ''}>
                </div>
            </div>
        \`;

        // 卡片主体
        const cardBody = document.createElement('div');
        cardBody.className = 'mobile-card-body';

        // URL 和网站链接 - 单行
        const urlRow = document.createElement('div');
        urlRow.className = 'mobile-card-row';
        urlRow.innerHTML = \`
            <span class="mobile-card-label" style="word-break: break-all;">
                URL: \${site.url}<a href="\${site.url}" target="_blank" rel="noopener noreferrer" class="text-decoration-none" style="margin-left: 4px;"><i class="bi bi-box-arrow-up-right"></i></a>
            </span>
        \`;
        cardBody.appendChild(urlRow);



        // 最后检查 - 单行
        const lastCheckRow = document.createElement('div');
        lastCheckRow.className = 'mobile-card-row';
        lastCheckRow.innerHTML = \`
            <span class="mobile-card-label">最后检查: \${lastCheckTime}</span>
        \`;
        cardBody.appendChild(lastCheckRow);

        // 操作按钮 - 编辑和删除
        const actionsRow = document.createElement('div');
        actionsRow.className = 'mobile-card-row';
        actionsRow.innerHTML = \`
            <div class="d-flex gap-2 w-100">
                <button class="btn btn-outline-primary btn-sm flex-fill" onclick="editSite('\${site.id}')">
                    <i class="bi bi-pencil"></i> 编辑
                </button>
                <button class="btn btn-outline-danger btn-sm flex-fill" onclick="deleteSite('\${site.id}')">
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

    // 为移动端网站显示开关添加事件监听器
    document.querySelectorAll('.site-visibility-toggle').forEach(toggle => {
        toggle.addEventListener('change', function() {
            const siteId = this.dataset.siteId;
            const isPublic = this.checked;
            toggleSiteVisibility(siteId, isPublic);
        });
    });
}

// 切换网站显示状态
async function toggleSiteVisibility(siteId, isPublic) {
    try {
        const toggle = document.querySelector(\`.site-visibility-toggle[data-site-id="\${siteId}"]\`);
        if (toggle) {
            toggle.disabled = true;
            toggle.style.opacity = '0.6';
        }

        await apiRequest(\`/api/admin/sites/\${siteId}/visibility\`, {
            method: 'POST',
            body: JSON.stringify({ is_public: isPublic })
        });

        // 更新本地数据
        const siteIndex = siteList.findIndex(s => s.id === siteId);
        if (siteIndex !== -1) {
            siteList[siteIndex].is_public = isPublic;
        }

        if (toggle) {
            toggle.disabled = false;
            toggle.style.opacity = '1';
        }

        showToast('success', '网站显示状态已' + (isPublic ? '开启' : '关闭'));

    } catch (error) {
                // 恢复开关状态
        const toggle = document.querySelector(\`.site-visibility-toggle[data-site-id="\${siteId}"]\`);
        if (toggle) {
            toggle.checked = !isPublic;
            toggle.disabled = false;
            toggle.style.opacity = '1';
        }

        showToast('danger', '切换显示状态失败: ' + error.message);
    }
}

// 移动端查看服务器API密钥
function showServerApiKey(serverId) {
    viewApiKey(serverId);
}

// ==================== 全局背景设置同步功能 ====================

// 监听storage事件，实现跨页面设置同步
window.addEventListener('storage', function(e) {
    if (e.key === 'background-settings-cache' && e.newValue) {
        try {
            const newSettings = JSON.parse(e.newValue);
            // 使用管理页面的背景设置应用函数
            applyBackgroundSettings(newSettings.enabled, newSettings.url, newSettings.opacity, false);
                    } catch (error) {
                    }
    }
});

// 页面加载时也检查并应用缓存的背景设置
document.addEventListener('DOMContentLoaded', function() {
    // 延迟执行，确保loadBackgroundSettings()先执行
    setTimeout(function() {
        const cached = localStorage.getItem('background-settings-cache');
        if (cached) {
            try {
                const cachedData = JSON.parse(cached);
                const now = Date.now();
                const cacheAge = now - cachedData.timestamp;
                const CACHE_DURATION = 5 * 60 * 1000; // 5分钟缓存

                if (cacheAge < CACHE_DURATION) {
                    // 缓存有效，确保设置已应用
                    applyBackgroundSettings(cachedData.enabled, cachedData.url, cachedData.opacity, false);
                                    }
            } catch (error) {
                            }
        }
    }, 100);
});

// ==================== 导出导入功能 ====================

// 导出服务器列表
async function exportServers() {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined' || typeof Blob === 'undefined') {
        console.error('导出功能需要在浏览器环境中运行');
        return;
    }
    
    try {
        const response = await apiRequest('/api/admin/servers/export');
        const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = \`servers_export_\${new Date().toISOString().slice(0, 10)}.json\`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showToast('success', \`已导出 \${response.data.length} 个服务器配置\`);
    } catch (error) {
        showToast('danger', '导出服务器列表失败: ' + error.message);
    }
}

// 导入服务器列表
async function importServers(file) {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined') {
        console.error('导入功能需要在浏览器环境中运行');
        return;
    }
    
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        
        // 验证文件格式
        if (!data || data.type !== 'servers' || !Array.isArray(data.data)) {
            showToast('danger', '导入文件格式无效，请选择正确的服务器配置文件');
            return;
        }
        
        const response = await apiRequest('/api/admin/servers/import', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        if (response.success) {
            showToast('success', response.message);
            if (response.errors && response.errors.length > 0) {
                console.warn('导入过程中的错误:', response.errors);
            }
            // 刷新服务器列表
            await loadServerList();
        } else {
            showToast('danger', response.message || '导入失败');
        }
        
        // 清空文件输入
        const fileInput = document.getElementById('serverImportFile');
        if (fileInput) fileInput.value = '';
        
    } catch (error) {
        showToast('danger', '导入服务器列表失败: ' + error.message);
        const fileInput = document.getElementById('serverImportFile');
        if (fileInput) fileInput.value = '';
    }
}

// 导出网站列表
async function exportSites() {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined' || typeof Blob === 'undefined') {
        console.error('导出功能需要在浏览器环境中运行');
        return;
    }
    
    try {
        const response = await apiRequest('/api/admin/sites/export');
        const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = \`sites_export_\${new Date().toISOString().slice(0, 10)}.json\`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showToast('success', \`已导出 \${response.data.length} 个网站配置\`);
    } catch (error) {
        showToast('danger', '导出网站列表失败: ' + error.message);
    }
}

// 导入网站列表
async function importSites(file) {
    // 确保在浏览器环境中运行
    if (typeof document === 'undefined') {
        console.error('导入功能需要在浏览器环境中运行');
        return;
    }
    
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        
        // 验证文件格式
        if (!data || data.type !== 'sites' || !Array.isArray(data.data)) {
            showToast('danger', '导入文件格式无效，请选择正确的网站配置文件');
            return;
        }
        
        const response = await apiRequest('/api/admin/sites/import', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        
        if (response.success) {
            showToast('success', response.message);
            if (response.errors && response.errors.length > 0) {
                console.warn('导入过程中的错误:', response.errors);
            }
            // 刷新网站列表
            await loadSiteList();
        } else {
            showToast('danger', response.message || '导入失败');
        }
        
        // 清空文件输入
        const fileInput = document.getElementById('siteImportFile');
        if (fileInput) fileInput.value = '';
        
    } catch (error) {
        showToast('danger', '导入网站列表失败: ' + error.message);
        const fileInput = document.getElementById('siteImportFile');
        if (fileInput) fileInput.value = '';
    }
}
`;
}
