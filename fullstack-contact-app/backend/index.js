/**
 * Contact form handler — validates {name, email}, returns a JSON success message.
 * Deployed behind API Gateway (REST API, Lambda proxy integration).
 */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "OPTIONS,POST",
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

exports.handler = async (event) => {
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return respond(400, { error: "Request body must be valid JSON." });
  }

  const name = (body.name || "").trim();
  const email = (body.email || "").trim();

  if (!name) {
    return respond(400, { error: "Name is required." });
  }
  if (!EMAIL_RE.test(email)) {
    return respond(400, { error: "A valid email address is required." });
  }

  console.log(`New contact submission: ${name} <${email}>`);

  return respond(200, {
    message: `Thanks, ${name} — we've got your email (${email}) and will be in touch soon!`,
  });
};

function respond(statusCode, bodyObj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    body: JSON.stringify(bodyObj),
  };
}
