import { randomBytes } from 'node:crypto';

/**
 * 環境変数から読み込んだ設定。起動時に一度だけ検証し、以降は型の付いたこの値だけを使う。
 * process.env を各所で直接読むと、検証漏れや「本番だけ値が無い」事故が起きやすいため。
 */
export interface Config {
  nodeEnv: 'development' | 'test' | 'production';
  host: string;
  port: number;
  /** WebAuthn の RP ID。パスキーはこのドメインに紐づく（S5: ドメイン固定） */
  rpId: string;
  /** 認証器のダイアログに表示されるサービス名 */
  rpName: string;
  /** 画面を配信するオリジン。WebAuthn の検証と CSRF 対策（S13）の Origin 照合に使う */
  origin: string;
  sessionSecret: string;
  /** SESSION_SECRET が未設定で、開発用に使い捨ての値を作ったか */
  sessionSecretIsEphemeral: boolean;
  databasePath: string;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  /** S7: 本番では Cookie に Secure を付ける。http://localhost で開発できるよう本番以外は外す */
  cookieSecure: boolean;
}

/** 設定の誤り。どの変数がなぜ駄目かを全部まとめて伝える（1 個ずつ直して再起動、を繰り返させない） */
export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`環境変数の設定に誤りがあります:\n- ${problems.join('\n- ')}`);
    this.name = 'ConfigError';
  }
}

const NODE_ENVS = ['development', 'test', 'production'] as const;
const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;

// 32 文字未満の秘密は総当たりの余地が残る。base64url で 32 バイト（43 文字）を推奨値とする。
const MIN_SECRET_LENGTH = 32;

function oneOf<T extends string>(value: string, allowed: readonly T[]): value is T {
  return (allowed as readonly string[]).includes(value);
}

/**
 * 環境変数を検証して Config を返す。誤りがあれば ConfigError を投げる。
 * 引数で env を受け取るのは、テストで process.env を書き換えずに済ませるため。
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];

  const nodeEnvRaw = env.NODE_ENV ?? 'development';
  if (!oneOf(nodeEnvRaw, NODE_ENVS)) {
    problems.push(`NODE_ENV は ${NODE_ENVS.join(' / ')} のいずれかにしてください`);
  }
  const nodeEnv = oneOf(nodeEnvRaw, NODE_ENVS) ? nodeEnvRaw : 'development';
  const isProduction = nodeEnv === 'production';

  const host = env.HOST ?? '127.0.0.1';

  const portRaw = env.PORT ?? '3000';
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    problems.push('PORT は 1〜65535 の整数にしてください');
  }

  const rpId = env.RP_ID ?? 'localhost';
  const rpName = env.RP_NAME ?? 'passkey-auth-starter';
  const origin = env.ORIGIN ?? `http://localhost:${portRaw}`;

  let originUrl: URL | undefined;
  try {
    originUrl = new URL(origin);
  } catch {
    problems.push('ORIGIN は http(s)://ホスト名[:ポート] の形にしてください');
  }
  if (originUrl) {
    if (originUrl.origin !== origin) {
      problems.push('ORIGIN にはパスや末尾の / を付けないでください（例: https://example.com）');
    }
    // WebAuthn の仕様上、RP ID はオリジンのホスト名そのものか、その親ドメインでなければならない。
    // ここで弾いておかないと、起動はできるのにパスキー登録だけが謎の失敗をする。
    const hostname = originUrl.hostname;
    if (hostname !== rpId && !hostname.endsWith(`.${rpId}`)) {
      problems.push(`RP_ID（${rpId}）は ORIGIN のホスト名（${hostname}）と同じか、その親ドメインにしてください`);
    }
    // パスキーは安全なコンテキスト（https、または localhost）でしか動かない。
    if (isProduction && originUrl.protocol !== 'https:') {
      problems.push('本番（NODE_ENV=production）では ORIGIN を https:// にしてください');
    }
  }

  // 秘密の値そのものはエラー文に含めない。ログに残って漏れるのを防ぐため（S12 と同じ考え方）。
  let sessionSecret = env.SESSION_SECRET ?? '';
  let sessionSecretIsEphemeral = false;
  if (sessionSecret === '') {
    if (isProduction) {
      problems.push('本番では SESSION_SECRET が必須です');
    } else {
      // 開発中は README の手順（.env をコピーして起動）だけで動くよう、起動ごとに使い捨ての値を作る。
      // 再起動するとログイン状態は消えるが、固定の秘密をリポジトリに置くよりは安全。
      sessionSecret = randomBytes(32).toString('base64url');
      sessionSecretIsEphemeral = true;
    }
  } else if (sessionSecret.length < MIN_SECRET_LENGTH) {
    problems.push(`SESSION_SECRET は ${MIN_SECRET_LENGTH} 文字以上にしてください`);
  }

  const databasePath = env.DATABASE_PATH ?? './data/app.sqlite';

  const logLevelRaw = env.LOG_LEVEL ?? (nodeEnv === 'test' ? 'silent' : 'info');
  if (!oneOf(logLevelRaw, LOG_LEVELS)) {
    problems.push(`LOG_LEVEL は ${LOG_LEVELS.join(' / ')} のいずれかにしてください`);
  }
  const logLevel = oneOf(logLevelRaw, LOG_LEVELS) ? logLevelRaw : 'info';

  if (problems.length > 0) {
    throw new ConfigError(problems);
  }

  return {
    nodeEnv,
    host,
    port,
    rpId,
    rpName,
    origin,
    sessionSecret,
    sessionSecretIsEphemeral,
    databasePath,
    logLevel,
    cookieSecure: isProduction,
  };
}
