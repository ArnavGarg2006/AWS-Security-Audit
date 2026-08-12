/**
 * Contact form handler.
 *
 * Routes (single Lambda, API Gateway REST proxy integration):
 *   POST /contact      validate {name, email} -> persist to DynamoDB -> notify via SNS
 *                       -> best-effort SES confirmation email -> JSON success message
 *   GET  /submissions   recent submissions (name + masked email + timestamp), newest first
 *
 * Deliberately defensive: a DynamoDB/SNS/SES failure never blocks the *other* steps or
 * the caller-facing response more than necessary — see handleContact() for the ordering.
 */
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, PutCommand, QueryCommand } = require("@aws-sdk/lib-dynamodb");
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");
const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses");
const crypto = require("crypto");

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const TABLE_NAME = process.env.SUBMISSIONS_TABLE;
const TOPIC_ARN = process.env.NOTIFICATIONS_TOPIC_ARN;
const SES_SENDER = process.env.SES_SENDER_EMAIL;
const SES_ENABLED = process.env.SES_ENABLED === "true";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
};

function wrapClient(client) {
  // Only patch with the X-Ray SDK inside a real Lambda invocation, never under Jest.
  if (!process.env.AWS_LAMBDA_FUNCTION_NAME) return client;
  try {
    const AWSXRay = require("aws-xray-sdk-core");
    return AWSXRay.captureAWSv3Client(client);
  } catch {
    return client;
  }
}

const ddb = DynamoDBDocumentClient.from(wrapClient(new DynamoDBClient({})));
const sns = wrapClient(new SNSClient({}));
const ses = wrapClient(new SESClient({}));

function log(level, message, meta = {}) {
  console.log(JSON.stringify({ level, message, timestamp: new Date().toISOString(), ...meta }));
}

/** Pure validation — no I/O, easy to unit test. Throws ValidationError on bad input. */
class ValidationError extends Error {}

function validateSubmission(body) {
  const name = (body.name || "").trim();
  const email = (body.email || "").trim();

  if (!name) throw new ValidationError("Name is required.");
  if (name.length > 200) throw new ValidationError("Name is too long.");
  if (!EMAIL_RE.test(email)) throw new ValidationError("A valid email address is required.");

  return { name, email };
}

/** "arnav@example.com" -> "ar***@example.com" — used on the public recent-submissions list. */
function maskEmail(email) {
  const [local, domain] = email.split("@");
  const visible = local.slice(0, 2);
  return `${visible}${"*".repeat(Math.max(local.length - 2, 3))}@${domain}`;
}

function respond(statusCode, bodyObj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    body: JSON.stringify(bodyObj),
  };
}

async function persistSubmission({ name, email }) {
  const now = new Date();
  const id = crypto.randomUUID();
  const sk = `${now.toISOString()}#${id.slice(0, 8)}`;

  await ddb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: { pk: "SUBMISSION", sk, id, name, email, createdAt: now.toISOString() },
  }));

  return { id, createdAt: now.toISOString() };
}

async function notifySns({ name, email, id }) {
  if (!TOPIC_ARN) return;
  try {
    await sns.send(new PublishCommand({
      TopicArn: TOPIC_ARN,
      Subject: "New contact form submission",
      Message: `New submission (${id}):\nName: ${name}\nEmail: ${email}`,
    }));
  } catch (err) {
    log("error", "SNS publish failed", { error: err.message, id });
  }
}

async function sendConfirmationEmail({ name, email }) {
  if (!SES_ENABLED || !SES_SENDER) return;
  try {
    await ses.send(new SendEmailCommand({
      Source: SES_SENDER,
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: "We've received your message" },
        Body: { Text: { Data: `Hi ${name},\n\nThanks for reaching out — we've got your message and will be in touch soon.` } },
      },
    }));
  } catch (err) {
    // Expected in SES sandbox mode unless the recipient is also a verified identity.
    log("warn", "SES send failed (sandbox mode only allows verified recipients)", { error: err.message, email });
  }
}

async function handleContact(event) {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return respond(400, { error: "Request body must be valid JSON." });
  }

  let submission;
  try {
    submission = validateSubmission(body);
  } catch (err) {
    if (err instanceof ValidationError) return respond(400, { error: err.message });
    throw err;
  }

  const { id, createdAt } = await persistSubmission(submission);
  log("info", "New contact submission", { id, createdAt });

  // Notification + confirmation email are best-effort side effects; they never fail the request.
  await Promise.all([
    notifySns({ ...submission, id }),
    sendConfirmationEmail(submission),
  ]);

  return respond(200, {
    message: `Thanks, ${submission.name} — we've got your email (${submission.email}) and will be in touch soon!`,
  });
}

async function handleSubmissions() {
  if (!TABLE_NAME) return respond(200, { submissions: [] });

  const result = await ddb.send(new QueryCommand({
    TableName: TABLE_NAME,
    KeyConditionExpression: "pk = :pk",
    ExpressionAttributeValues: { ":pk": "SUBMISSION" },
    ScanIndexForward: false,
    Limit: 20,
  }));

  const submissions = (result.Items || []).map((item) => ({
    name: item.name,
    email: maskEmail(item.email),
    createdAt: item.createdAt,
  }));

  return respond(200, { submissions });
}

exports.handler = async (event) => {
  const method = event.httpMethod;
  const path = event.resource || event.path || "";

  try {
    if (method === "POST" && path.includes("/contact")) return await handleContact(event);
    if (method === "GET" && path.includes("/submissions")) return await handleSubmissions();
    return respond(404, { error: "Not found." });
  } catch (err) {
    log("error", "Unhandled error", { error: err.message, stack: err.stack });
    return respond(500, { error: "Internal server error." });
  }
};

exports._internal = { validateSubmission, maskEmail, ValidationError };
