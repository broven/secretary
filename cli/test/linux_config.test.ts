import { chmod, lstat, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, test } from "bun:test";
import {
  CLIENT_SERVICE,
  TOKEN_SERVICE,
  URL_SERVICE,
  createLinuxConfigStore,
  linuxConfigPaths,
  main,
  type ClientDeps,
} from "../src/secretary.ts";

async function withConfig<T>(fn: (env: Record<string, string | undefined>) => Promise<T>): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), "secretary-issue-11-"));
  const env = { HOME: root, XDG_CONFIG_HOME: join(root, "xdg") };
  try {
    return await fn(env);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("Linux user config store", () => {
  test("the installed wrapper preserves XDG_CONFIG_HOME through its env scrub", async () => {
    const wrapper = await Bun.file(new URL("../scripts/secretary", import.meta.url)).text();
    expect(wrapper).toContain("NODE_EXTRA_CA_CERTS XDG_CONFIG_HOME SECRETARY_CLIENT_ID");
    expect(wrapper).toContain('XDG_CONFIG_HOME="${XDG_CONFIG_HOME-}"');
  });

  test("persists individual fields with strict ownership and modes", async () => {
    await withConfig(async (env) => {
      const store = createLinuxConfigStore(env, async () => "token-from-terminal");
      await store.write(URL_SERVICE, "secretary", "https://broker.example/");
      await store.write(TOKEN_SERVICE, "secretary", "token-from-terminal");
      await store.write(CLIENT_SERVICE, "secretary", "client-1");

      const paths = linuxConfigPaths(env);
      expect((await stat(paths.directory)).mode & 0o7777).toBe(0o700);
      expect((await stat(paths.file)).mode & 0o7777).toBe(0o600);
      expect(JSON.parse(await readFile(paths.file, "utf8"))).toEqual({
        url: "https://broker.example",
        token: "token-from-terminal",
        clientId: "client-1",
      });
      expect(await store.read(URL_SERVICE, "secretary")).toBe("https://broker.example");
      expect(await store.read(TOKEN_SERVICE, "secretary")).toBe("token-from-terminal");
    });
  });

  test("keeps other fields when one field is updated and imports through auth", async () => {
    await withConfig(async (env) => {
      const store = createLinuxConfigStore(env, async () => "hidden-token");
      const output: string[] = [];
      const errors: string[] = [];
      const deps: ClientDeps = {
        env,
        fetch,
        keychain: store,
        platform: "linux",
        realpath: (async (path) => String(path)) as ClientDeps["realpath"],
        stat,
        now: Date.now,
        randomUUID: () => crypto.randomUUID(),
        hostname: () => "test-host",
        username: () => "test-user",
        gitRemote: () => undefined,
        spawn: async () => 0,
        stdout: (message) => output.push(message),
        stderr: (message) => errors.push(message),
        readStdin: async () => "",
        promptSecret: async () => "hidden-token",
      };

      expect(await main(["--cwd", "/repo", "auth", "set-url", "https://broker.example/"], deps)).toBe(0);
      expect(await main(["--cwd", "/repo", "auth", "import"], deps)).toBe(0);
      expect(await main(["--cwd", "/repo", "auth", "set-client-id", "client-1"], deps)).toBe(0);
      expect(JSON.parse(await Bun.file(linuxConfigPaths(env).file).text())).toEqual({
        url: "https://broker.example",
        token: "hidden-token",
        clientId: "client-1",
      });
      expect(output.join("")).toContain("Linux XDG 配置文件");
      expect(output.join("")).not.toContain("hidden-token");
      expect(errors).toEqual([]);
    });
  });

  test("rejects malformed JSON and unknown or invalid field values", async () => {
    await withConfig(async (env) => {
      const store = createLinuxConfigStore(env, async () => "token");
      await store.write(TOKEN_SERVICE, "secretary", "token");
      const paths = linuxConfigPaths(env);
      await writeFile(paths.file, JSON.stringify({ token: "token", unexpected: true }));
      await expect(store.read(TOKEN_SERVICE, "secretary")).rejects.toThrow("未知字段");
      await writeFile(paths.file, JSON.stringify({ token: 42 }));
      await expect(store.read(TOKEN_SERVICE, "secretary")).rejects.toThrow("token 无效");
      await writeFile(paths.file, "not json");
      await expect(store.read(TOKEN_SERVICE, "secretary")).rejects.toThrow("JSON 无效");
    });
  });
  test("fails closed on unsafe permissions but still lets the owner clean up", async () => {
    await withConfig(async (env) => {
      const store = createLinuxConfigStore(env, async () => "token");
      await store.write(TOKEN_SERVICE, "secretary", "token");
      const paths = linuxConfigPaths(env);
      await chmod(paths.file, 0o644);
      await expect(store.read(TOKEN_SERVICE, "secretary")).rejects.toThrow("权限不安全");
      await store.delete(URL_SERVICE, "secretary");
      await expect(lstat(paths.file)).rejects.toMatchObject({ code: "ENOENT" });
    });
  });

  test("refuses symlinks on read and removes only the link on delete", async () => {
    await withConfig(async (env) => {
      const store = createLinuxConfigStore(env, async () => "token");
      await store.write(TOKEN_SERVICE, "secretary", "token");
      const paths = linuxConfigPaths(env);
      const target = join(paths.directory, "outside.json");
      await writeFile(target, JSON.stringify({ token: "must-not-read" }), { mode: 0o600 });
      await unlink(paths.file);
      await symlink(target, paths.file);

      await expect(store.read(TOKEN_SERVICE, "secretary")).rejects.toThrow("符号链接");
      await store.delete(URL_SERVICE, "secretary");
      expect(await Bun.file(target).text()).toContain("must-not-read");
      await expect(lstat(paths.file)).rejects.toMatchObject({ code: "ENOENT" });
    });
  });

  test("environment variables override file values without changing the file", async () => {
    await withConfig(async (baseEnv) => {
      const store = createLinuxConfigStore(baseEnv, async () => "file-token");
      await store.write(URL_SERVICE, "secretary", "https://file.example");
      await store.write(TOKEN_SERVICE, "secretary", "file-token");
      const env = { ...baseEnv, SECRETARY_URL: "https://env.example", SECRETARY_TOKEN: "env-token" };
      const output: string[] = [];
      const deps: ClientDeps = {
        env,
        fetch: (async () => Response.json({ items: [] })) as unknown as typeof fetch,
        keychain: createLinuxConfigStore(env, async () => "file-token"),
        platform: "linux",
        realpath: (async (path) => String(path)) as ClientDeps["realpath"],
        stat,
        now: Date.now,
        randomUUID: () => crypto.randomUUID(),
        hostname: () => "test-host",
        username: () => "test-user",
        gitRemote: () => undefined,
        spawn: async () => 0,
        stdout: (message) => output.push(message),
        stderr: () => {},
        readStdin: async () => "",
      };
      expect(await main(["--cwd", "/repo", "auth", "status"], deps)).toBe(0);
      const status = output.join("");
      expect(status).toContain("broker URL：已配置（来源：环境变量 SECRETARY_URL）");
      expect(status).toContain("token：已配置（来源：环境变量 SECRETARY_TOKEN）");
      const beforeDelete = await Bun.file(linuxConfigPaths(env).file).text();
      expect(await main(["--cwd", "/repo", "auth", "delete"], deps)).toBe(0);
      expect(env.SECRETARY_TOKEN).toBe("env-token");
      await expect(lstat(linuxConfigPaths(env).file)).rejects.toMatchObject({ code: "ENOENT" });
      expect(beforeDelete).toContain("file-token");
    });
  });
});
