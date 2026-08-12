const { mockClient } = require("aws-sdk-client-mock");
const { DynamoDBDocumentClient, PutCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");
const { SNSClient } = require("@aws-sdk/client-sns");
const { SESClient } = require("@aws-sdk/client-ses");

process.env.SUBMISSIONS_TABLE = "test-table";
process.env.ALLOWED_ORIGIN = "https://example.com";

const ddbMock = mockClient(DynamoDBDocumentClient);
const snsMock = mockClient(SNSClient);
const sesMock = mockClient(SESClient);

const { handler, _internal } = require("./index");
const { validateSubmission, maskEmail, ValidationError } = _internal;

beforeEach(() => {
  ddbMock.reset();
  snsMock.reset();
  sesMock.reset();
});

describe("validateSubmission", () => {
  test("accepts a valid name + email", () => {
    expect(validateSubmission({ name: "Ada Lovelace", email: "ada@example.com" }))
      .toEqual({ name: "Ada Lovelace", email: "ada@example.com" });
  });

  test("trims whitespace", () => {
    expect(validateSubmission({ name: "  Ada  ", email: "  ada@example.com  " }))
      .toEqual({ name: "Ada", email: "ada@example.com" });
  });

  test("rejects an empty name", () => {
    expect(() => validateSubmission({ name: "", email: "ada@example.com" }))
      .toThrow(ValidationError);
  });

  test("rejects a missing name", () => {
    expect(() => validateSubmission({ email: "ada@example.com" }))
      .toThrow(ValidationError);
  });

  test.each([
    "not-an-email",
    "missing-at-sign.com",
    "@no-local-part.com",
    "no-domain@",
    "spaces in@email.com",
  ])("rejects invalid email %s", (email) => {
    expect(() => validateSubmission({ name: "Ada", email })).toThrow(ValidationError);
  });

  test("rejects an overly long name", () => {
    const longName = "a".repeat(201);
    expect(() => validateSubmission({ name: longName, email: "ada@example.com" }))
      .toThrow(ValidationError);
  });
});

describe("maskEmail", () => {
  test("masks the local part, keeps the domain visible", () => {
    expect(maskEmail("arnav@example.com")).toBe("ar***@example.com");
  });

  test("pads short local parts to at least 3 stars", () => {
    expect(maskEmail("ab@example.com")).toBe("ab***@example.com");
  });
});

describe("handler: POST /contact", () => {
  const baseEvent = { httpMethod: "POST", resource: "/contact" };

  test("returns 400 for invalid JSON body", async () => {
    const res = await handler({ ...baseEvent, body: "{not json" });
    expect(res.statusCode).toBe(400);
  });

  test("returns 400 for missing name", async () => {
    const res = await handler({ ...baseEvent, body: JSON.stringify({ email: "a@b.com" }) });
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/name/i);
  });

  test("persists to DynamoDB and returns 200 on valid input", async () => {
    ddbMock.on(PutCommand).resolves({});
    const res = await handler({
      ...baseEvent,
      body: JSON.stringify({ name: "Ada", email: "ada@example.com" }),
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).message).toMatch(/Ada/);
    expect(ddbMock.commandCalls(PutCommand)).toHaveLength(1);
  });

  test("still returns 200 even if SNS publish fails (best-effort)", async () => {
    ddbMock.on(PutCommand).resolves({});
    snsMock.rejects(new Error("boom"));
    const res = await handler({
      ...baseEvent,
      body: JSON.stringify({ name: "Ada", email: "ada@example.com" }),
    });
    expect(res.statusCode).toBe(200);
  });

  test("includes the configured CORS origin on every response", async () => {
    const res = await handler({ ...baseEvent, body: JSON.stringify({ name: "", email: "" }) });
    expect(res.headers["Access-Control-Allow-Origin"]).toBe("https://example.com");
  });
});

describe("handler: GET /submissions", () => {
  test("returns masked emails, newest first", async () => {
    ddbMock.on(QueryCommand).resolves({
      Items: [
        { name: "Ada", email: "ada@example.com", createdAt: "2026-08-11T00:00:00.000Z" },
      ],
    });
    const res = await handler({ httpMethod: "GET", resource: "/submissions" });
    expect(res.statusCode).toBe(200);
    const { submissions } = JSON.parse(res.body);
    expect(submissions).toHaveLength(1);
    expect(submissions[0].email).toBe("ad***@example.com");
  });
});

describe("handler: unknown route", () => {
  test("returns 404", async () => {
    const res = await handler({ httpMethod: "DELETE", resource: "/nope" });
    expect(res.statusCode).toBe(404);
  });
});
