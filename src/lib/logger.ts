import { appendFileSync, mkdirSync } from "fs";
import { resolve } from "path";

const LOG_DIR = resolve(process.cwd(), "scan-logs");

try {
  mkdirSync(LOG_DIR, { recursive: true });
} catch {
  // Directory might already exist
}

function getTimestamp(): string {
  return new Date().toISOString();
}

function formatLog(level: string, message: string, data?: any): string {
  const timestamp = getTimestamp();
  const dataStr = data ? ` | ${JSON.stringify(data)}` : "";
  return `[${timestamp}] [${level}] ${message}${dataStr}\n`;
}

function getLogFilePath(): string {
  const now = new Date();
  const date = now.toISOString().split("T")[0];
  const filename = `scan-${date}.log`;
  return resolve(LOG_DIR, filename);
}

export const logger = {
  info(message: string, data?: any) {
    const log = formatLog("INFO", message, data);
    appendFileSync(getLogFilePath(), log);
    console.log(log.trim());
  },

  warn(message: string, data?: any) {
    const log = formatLog("WARN", message, data);
    appendFileSync(getLogFilePath(), log);
    console.warn(log.trim());
  },

  error(message: string, data?: any) {
    const log = formatLog("ERROR", message, data);
    appendFileSync(getLogFilePath(), log);
    console.error(log.trim());
  },

  debug(message: string, data?: any) {
    if (process.env.DEBUG) {
      const log = formatLog("DEBUG", message, data);
      appendFileSync(getLogFilePath(), log);
      console.debug(log.trim());
    }
  },

  rateLimit(message: string, remaining: number, resetTime: number) {
    const resetDate = new Date(resetTime * 1000).toISOString();
    const log = formatLog("RATE_LIMIT", message, {
      remaining,
      resetTime: resetDate,
    });
    appendFileSync(getLogFilePath(), log);
    console.warn(log.trim());
  },
};
