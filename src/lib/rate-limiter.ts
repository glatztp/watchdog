import { Octokit } from "@octokit/rest";
import { logger } from "./logger";

interface RateLimitInfo {
  remaining: number;
  limit: number;
  resetTime: number;
  percentage: number;
}

class RateLimiterManager {
  private octokit: Octokit;
  private retryAttempts: Map<string, number> = new Map();
  private readonly MAX_RETRIES = 3;
  private readonly BASE_RETRY_DELAY_MS = 60000;

  constructor() {
    if (!process.env.GITHUB_TOKEN) {
      logger.warn(
        "GITHUB_TOKEN not set. Using unauthenticated requests (limited to 60 req/hr)",
      );
    }

    this.octokit = new Octokit({
      auth: process.env.GITHUB_TOKEN,
      throttle: {
        onRateLimit: (retryAfter, options) => {
          const message = `Rate limit exceeded. Will retry after ${retryAfter} seconds`;
          logger.warn(message);
          return true;
        },
        onAbuseLimit: (retryAfter, options) => {
          const message = `Abuse limit hit. Will retry after ${retryAfter} seconds`;
          logger.warn(message);
          return true;
        },
      },
    });
  }

  async getRateLimitInfo(): Promise<RateLimitInfo> {
    try {
      const { data } = await this.octokit.rateLimit.get();
      const core = data.resources.core;
      const percentage = (core.remaining / core.limit) * 100;

      return {
        remaining: core.remaining,
        limit: core.limit,
        resetTime: core.reset,
        percentage,
      };
    } catch (err) {
      logger.error("Failed to get rate limit info", {
        error: err instanceof Error ? err.message : String(err),
      });
      return {
        remaining: 0,
        limit: 60,
        resetTime: 0,
        percentage: 0,
      };
    }
  }

  async checkRateLimit(): Promise<boolean> {
    const info = await this.getRateLimitInfo();
    logger.info("Rate limit status", {
      remaining: info.remaining,
      limit: info.limit,
      percentage: info.percentage.toFixed(1),
    });

    if (info.remaining < 10) {
      logger.rateLimit(
        `⚠️  Low rate limit! Only ${info.remaining} requests remaining`,
        info.remaining,
        info.resetTime,
      );
      return false;
    }

    if (info.remaining === 0) {
      logger.rateLimit(
        `❌ Rate limit EXCEEDED!`,
        info.remaining,
        info.resetTime,
      );
      throw new Error(
        `GitHub rate limit exceeded. Reset at ${new Date(info.resetTime * 1000).toISOString()}`,
      );
    }

    return true;
  }

  async executeWithRetry<T>(
    operation: () => Promise<T>,
    operationName: string,
  ): Promise<T> {
    let lastError: Error | null = null;
    const key = operationName;
    const attempts = this.retryAttempts.get(key) ?? 0;

    if (attempts >= this.MAX_RETRIES) {
      throw new Error(
        `Operation "${operationName}" failed after ${this.MAX_RETRIES} retries`,
      );
    }

    try {
      await this.checkRateLimit();
      const result = await operation();
      this.retryAttempts.delete(key);
      return result;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));

      if (lastError.message.includes("rate limit")) {
        const nextAttempts = attempts + 1;
        this.retryAttempts.set(key, nextAttempts);
        const waitTime = this.BASE_RETRY_DELAY_MS * Math.pow(2, attempts);
        const waitTimeMinutes = (waitTime / 1000 / 60).toFixed(1);

        logger.warn(
          `Rate limit hit. Retry ${nextAttempts}/${this.MAX_RETRIES} in ${waitTimeMinutes} minutes`,
          {
            operation: operationName,
          },
        );

        await new Promise((resolve) => setTimeout(resolve, waitTime));
        return this.executeWithRetry(operation, operationName);
      }

      throw lastError;
    }
  }

  getOctokit(): Octokit {
    return this.octokit;
  }
}

export const rateLimiter = new RateLimiterManager();
