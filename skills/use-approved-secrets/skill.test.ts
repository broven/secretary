import { describe, expect, test } from "bun:test";

const skill = await Bun.file(new URL("./SKILL.md", import.meta.url)).text();
const bashExamples = [...skill.matchAll(/```bash\n([\s\S]*?)```/g)]
  .map((match) => match[1])
  .join("\n");
const jqPath = Bun.which("jq");

if (!jqPath) {
  console.warn("Skipping jq encoder integration check: jq is not installed");
}

describe("write examples", () => {
  test("never interpolate secret values through echo or jq argv", () => {
    expect(bashExamples).not.toMatch(/\becho\b/);
    expect(bashExamples).not.toMatch(/\bjq\s+--arg\b/);
    expect(bashExamples).not.toMatch(/'[^'\n]*'"\$[A-Za-z_][A-Za-z0-9_]*"/);
  });

  test("the mixed owner-entry example supplies the inline username as JSON", () => {
    expect(skill).toContain(
      "USERNAME_VALUE=\"ops@acme.com\" jq -n '{username: env.USERNAME_VALUE}' | \\\n" +
      "  approved-secret create --item \"Acme Prod\"",
    );
    expect(skill).toContain("--field username=@stdin --field password=@owner");
  });

  test.skipIf(!jqPath)("the documented jq encoder preserves JSON-sensitive characters", () => {
    const value = 'quote " and slash \\ and line\nfeed';
    const encoded = Bun.spawnSync([jqPath!, "-n", "{password: env.FIELD_VALUE}"], {
      env: { ...process.env, FIELD_VALUE: value },
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(encoded.exitCode).toBe(0);
    expect(JSON.parse(encoded.stdout.toString())).toEqual({ password: value });
    expect(encoded.stderr.toString()).toBe("");
  });
});
