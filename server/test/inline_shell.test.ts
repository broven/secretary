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

  test("env option evasion forms stay inline (P1-1)", () => {
    expect(isInlineShellCommand(["env", "--", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "-i", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "--ignore-environment", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "-u", "FOO", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "--unset=FOO", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "-C", "/tmp", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "--chdir=/tmp", "sh", "-c", "x"])).toBe(true);
    expect(isInlineShellCommand(["env", "-i", "A=1", "--", "bash", "-lc", "x"])).toBe(true);
    // Unrecognized env options are unauditable → conservatively inline.
    expect(isInlineShellCommand(["env", "-S", "sh -c x"])).toBe(true);
    expect(isInlineShellCommand(["env", "--split-string=sh -c x"])).toBe(true);
    // Recognized options wrapping a plain command stay non-inline.
    expect(isInlineShellCommand(["env", "-i", "tool", "--flag"])).toBe(false);
    expect(isInlineShellCommand(["env", "-u", "FOO", "git", "push"])).toBe(false);
    // env with options but no command is not a command at all.
    expect(isInlineShellCommand(["env", "-i"])).toBe(false);
    expect(isInlineShellCommand(["env", "-u"])).toBe(false);
  });

  test("combined and equivalent eval flags are inline (P1-a)", () => {
    const inline: string[][] = [
      ["sh", "-cx", "echo hi"],
      ["bash", "-xc", "echo hi"],
      ["zsh", "-ilc", "echo hi"],
      ["python3", "-uc", "print(1)"],
      ["node", "-p", "1+1"],
      ["node", "--print", "1+1"],
      ["node", "--print=1+1"],
      ["node", "--eval=1"],
      ["bun", "-p", "1"],
      ["deno", "-p", "1"],
      ["perl", "-we", "print 1"],
      ["perl", "-E", "say 1"],
      ["ruby", "-e", "puts 1"],
      ["ruby", "-ne", "print"],
      ["php", "-r", "echo 1;"],
    ];
    for (const argv of inline) {
      expect({ argv, inline: isInlineShellCommand(argv) }).toEqual({ argv, inline: true });
    }
    const notInline: string[][] = [
      ["sh", "-x", "script.sh"],
      ["bash", "-l", "script.sh"],
      ["python3", "-u", "script.py"],
      ["node", "--version"],
      ["node", "script.js", "--print-config"],
      ["php", "-f", "script.php"],
    ];
    for (const argv of notInline) {
      expect({ argv, inline: isInlineShellCommand(argv) }).toEqual({ argv, inline: false });
    }
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
