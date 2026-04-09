import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client, type ConnectConfig } from "ssh2";

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
    // Try default key paths
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
    const timer = setTimeout(() => {
      reject(new Error(`Command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    client.exec(command, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        return reject(err);
      }

      let stdout = "";
      let stderr = "";

      stream
        .on("close", (code: number) => {
          clearTimeout(timer);
          resolve({ stdout, stderr, code: code ?? 0 });
        })
        .on("data", (data: Buffer) => {
          stdout += data.toString();
        })
        .stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });
    });
  });
}

export function readFile(client: Client, remotePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.readFile(remotePath, (err, data) => {
        if (err) return reject(err);
        resolve(data.toString("utf8"));
      });
    });
  });
}

export function writeFile(client: Client, remotePath: string, content: string): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.writeFile(remotePath, content, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  });
}

export function uploadFile(client: Client, localPath: string, remotePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(localPath, remotePath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  });
}

export function downloadFile(client: Client, remotePath: string, localPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastGet(remotePath, localPath, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  });
}

export function listDir(client: Client, remotePath: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.readdir(remotePath, (err, list) => {
        if (err) return reject(err);
        resolve(list.map((item) => item.filename));
      });
    });
  });
}
