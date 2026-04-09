import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client, type ConnectConfig, type SFTPWrapper } from "ssh2";

export interface SSHConfig {
  host: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  password?: string;
  agent?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

function resolveConfig(config: SSHConfig): ConnectConfig {
  const connectConfig: ConnectConfig = {
    host: config.host,
    port: config.port || 22,
    username: config.username || process.env.USER || process.env.USERNAME || "root",
  };

  // Auth priority: explicit key > explicit password > agent > default key paths
  if (config.privateKeyPath) {
    connectConfig.privateKey = readFileSync(config.privateKeyPath);
  } else if (config.password) {
    connectConfig.password = config.password;
  } else if (config.agent || process.env.SSH_AUTH_SOCK) {
    connectConfig.agent = config.agent || process.env.SSH_AUTH_SOCK;
  } else {
    const home = homedir();
    const defaultKeys = ["id_ed25519", "id_rsa", "id_ecdsa"];
    for (const keyName of defaultKeys) {
      const keyPath = join(home, ".ssh", keyName);
      try {
        connectConfig.privateKey = readFileSync(keyPath);
        break;
      } catch {
        // Key doesn't exist, try next
      }
    }
  }

  return connectConfig;
}

export function connect(config: SSHConfig): Promise<Client> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    const connectConfig = resolveConfig(config);

    client
      .on("ready", () => resolve(client))
      .on("error", (err) => reject(err))
      .connect(connectConfig);
  });
}

export function exec(client: Client, command: string, timeoutMs = 30000): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    let settled = false;

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const timer = setTimeout(() => {
      settle(() => reject(new Error(`Command timed out after ${timeoutMs}ms`)));
    }, timeoutMs);

    client.exec(command, (err, stream) => {
      if (err) {
        settle(() => reject(err));
        return;
      }

      let stdout = "";
      let stderr = "";

      stream
        .on("close", (code: number) => {
          settle(() => resolve({ stdout, stderr, code: code ?? 0 }));
        })
        .on("data", (data: Buffer) => {
          stdout += data.toString();
        })
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });

      stream.stderr
        .on("data", (data: Buffer) => {
          stderr += data.toString();
        })
        .on("error", (err: Error) => {
          settle(() => reject(err));
        });
    });
  });
}

function getSftp(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      resolve(sftp);
    });
  });
}

export async function readFile(client: Client, remotePath: string): Promise<string> {
  const sftp = await getSftp(client);
  try {
    return await new Promise((resolve, reject) => {
      sftp.readFile(remotePath, (err, data) => {
        if (err) return reject(err);
        resolve(data.toString("utf8"));
      });
    });
  } finally {
    sftp.end();
  }
}

export async function writeFile(client: Client, remotePath: string, content: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.writeFile(remotePath, content, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function uploadFile(client: Client, localPath: string, remotePath: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastPut(localPath, remotePath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function downloadFile(client: Client, remotePath: string, localPath: string): Promise<void> {
  const sftp = await getSftp(client);
  try {
    await new Promise<void>((resolve, reject) => {
      sftp.fastGet(remotePath, localPath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  } finally {
    sftp.end();
  }
}

export async function listDir(client: Client, remotePath: string): Promise<string[]> {
  const sftp = await getSftp(client);
  try {
    return await new Promise((resolve, reject) => {
      sftp.readdir(remotePath, (err, list) => {
        if (err) return reject(err);
        resolve(list.map((item) => item.filename));
      });
    });
  } finally {
    sftp.end();
  }
}
