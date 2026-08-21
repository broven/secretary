import { describe, expect, test } from "bun:test";
import { formatCommandDisplay, isInlineShellCommand } from "../src/requests.ts";
import { commandFingerprint } from "../src/grants.ts";

describe("inline shell detection (ported table)", () => {
  test("shell -c forms are inline", () => {
    expect(isInlineShellCommand(["sh", "-c", "echo hi"])).toBe(true);
    expect(isInlineShellCommand(["bash", "-lc", "echo hi"])).toBe(true);
    expect(isInlineShellCommand(["/bin/zsh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["fish", "-c", "x"])).toBe(true);
  });

  test("interpreter eval flags are inline", () => {
    expect(isInlineShellCommand(["python3", "-c", "print(1)"])).toBe(true);
    expect(isInlineShellCommand(["node", "-e", "1"])).toBe(true);
    expect(isInlineShellCommand(["node", "--eval", "1"])).toBe(true);
    expect(isInlineShellCommand(["ruby", "-e", "1"])).toBe(true);
    expect(isInlineShellCommand(["bun", "-e", "1"])).toBe(true);
  });

  test("env wrappers are stripped before detection", () => {
    expect(isInlineShellCommand(["env", "A=1", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["/usr/bin/env", "A=1", "B=2", "python", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "A=1"])).toBe(false);
  });

  test("plain commands are not inline", () => {
    expect(isInlineShellCommand(["curl", "-c", "cookies.txt", "https://x"])).toBe(false);
    expect(isInlineShellCommand(["python3", "script.py"])).toBe(false);
    expect(isInlineShellCommand(["sh", "script.sh"])).toBe(false);
    expect(isInlineShellCommand(["git", "push"])).toBe(false);
    expect(isInlineShellCommand([])).toBe(false);
  });
});

describe("command display", () => {
  test("safe tokens joined, unsafe quoted", () => {
    expect(formatCommandDisplay(["git", "push", "origin", "main"])).toBe("git push origin main");
    expect(formatCommandDisplay(["echo", "a b"])).toBe('echo "a b"');
  });

  test("over-long commands truncate with the argv fingerprint appended", () => {
    const argv = ["tool", "x".repeat(2000)];
    const display = formatCommandDisplay(argv);
    expect(display.length).toBeLessThan(1100);
    expect(display).toContain(commandFingerprint(argv));
  });
});
