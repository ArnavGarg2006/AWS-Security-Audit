# Full-Stack Contact Form (Lambda + API Gateway + S3/CloudFront)

A minimal full-stack app: a static HTML/JS frontend collects a name and email, calls
an API Gateway REST endpoint, which invokes a Lambda function that validates the input
and returns a JSON success message. No data is persisted — this is a processing/response
demo, not a database-backed form.

## Live deployment

| Component | Value |
|---|---|
| Frontend | http://contact-form-frontend-653011867129-ap-south-1.s3-website.ap-south-1.amazonaws.com |
| API | `POST https://bv2wjj78b0.execute-api.ap-south-1.amazonaws.com/prod/contact` |
| Lambda | `contact-form-handler` (Node.js 20.x), `ap-south-1` |

**Note on hosting:** the original design calls for S3 + CloudFront. This AWS account
currently returns `AccessDenied: Your account must be verified before you can add new
CloudFront resources` on `CreateDistribution` — an account-level gate that needs an AWS
Support ticket to clear, not something fixable via configuration. The frontend is live via
**S3 static website hosting** instead (see below) so the app works end-to-end today; the
"Upgrade to CloudFront" section covers migrating once the account is verified.

## Architecture

```
Browser --(HTTPS)--> S3 static website (index.html)
   |
   `--(fetch POST, CORS)--> API Gateway REST API (/contact)
                                  |
                                  `--(AWS_PROXY)--> Lambda (contact-form-handler)
```

## Backend code

[backend/index.js](backend/index.js) — validates `name` (non-empty) and `email` (regex
format check), logs the submission to CloudWatch, and returns a JSON message. CORS headers
are included directly in the Lambda response (required for `AWS_PROXY` integrations, since
API Gateway passes the Lambda's response through unmodified).

## Frontend code

[frontend/index.html](frontend/index.html) — single-page form with a dark gradient UI,
client-side validation (shake animation on invalid input), a loading spinner while the
request is in flight, and success/error states. The API endpoint is read from a placeholder
(`__API_URL__`) that gets substituted with the real URL at deploy time — see below.

## Deploy from scratch via the AWS Management Console

### 1. Lambda function

1. Open **Lambda** → **Create function**.
2. Choose **Author from scratch**. Name: `contact-form-handler`. Runtime: **Node.js 20.x**.
3. Under **Permissions**, create a new role with basic Lambda permissions (this attaches
   `AWSLambdaBasicExecutionRole` — CloudWatch Logs only, nothing else).
4. Click **Create function**.
5. In the **Code** tab, replace the default `index.js` contents with
   [backend/index.js](backend/index.js), then click **Deploy**.
6. In **Configuration → General configuration**, set **Timeout** to 10 seconds.

### 2. API Gateway (REST API)

1. Open **API Gateway** → **Create API** → **REST API** (not HTTP API) → **Build**.
2. API name: `contact-form-api`. Endpoint type: **Regional**.
3. **Actions → Create Resource**. Resource name: `contact` (path `/contact`).
4. With `/contact` selected, **Actions → Create Method → POST**.
   - Integration type: **Lambda Function**.
   - Use **Lambda Proxy integration**: checked.
   - Lambda Function: `contact-form-handler`.
   - Save, and accept the prompt to grant API Gateway permission to invoke the function.
5. With `/contact` selected, **Actions → Enable CORS**.
   - Accept the defaults (this creates the `OPTIONS` method with the CORS headers).
   - Click **Enable CORS and replace existing CORS headers**.
6. **Actions → Deploy API**. Deployment stage: **New Stage**, name it `prod`.
7. Note the **Invoke URL** shown at the top of the stage editor — your endpoint is
   `{Invoke URL}/contact`.

### 3. S3 + CloudFront (as originally specified)

1. **S3 → Create bucket**. Name must be globally unique (e.g. `your-contact-form-<account-id>`).
   Keep **Block all public access** turned ON (CloudFront will read via Origin Access
   Control, the bucket itself stays private).
2. Before uploading, open `frontend/index.html` and replace `__API_URL__` with your real
   `{Invoke URL}/contact` from step 2.7.
3. Upload the edited `index.html` to the bucket.
4. **CloudFront → Create distribution**.
   - Origin domain: select your S3 bucket (pick the one *without* `-website` in the
     suggested list — this uses the REST endpoint, not the website endpoint).
   - Origin access: **Origin access control settings (recommended)** → create a new OAC.
   - Viewer protocol policy: **Redirect HTTP to HTTPS**.
   - Default root object: `index.html`.
   - Click **Create distribution**.
5. CloudFront will show a banner to **copy the bucket policy** it generated (restricting
   reads to only this distribution via the OAC) — click **Copy policy**, then go to your
   S3 bucket → **Permissions → Bucket policy** → paste it in → **Save**.
6. Wait for the distribution status to become **Enabled** (typically 5-15 minutes). Your
   site is then live at the `*.cloudfront.net` domain shown on the distribution's detail page.

### 3-alt. S3 static website hosting (what's actually live right now)

Used here because this account isn't yet CloudFront-verified. Simpler, but plain HTTP only
(no HTTPS, no CDN caching/edge network) — treat it as a stand-in, not the end state.

1. **S3 → Create bucket**. This time, uncheck **Block all public access** (needed — a
   website-hosting bucket must allow public reads) and acknowledge the warning.
2. **Properties → Static website hosting → Enable**. Index document: `index.html`.
3. **Permissions → Bucket policy** — add:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Sid": "PublicReadForWebsite",
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*"
     }]
   }
   ```
4. Upload `index.html` (with `__API_URL__` already replaced).
5. The site URL is shown under **Properties → Static website hosting** —
   `http://YOUR-BUCKET-NAME.s3-website.YOUR-REGION.amazonaws.com`.

### Upgrade to CloudFront later

Once AWS Support clears the account verification: follow section 3 above, pointing the
CloudFront origin at the *same* bucket (switch it to OAC-based private access instead of
the public website-hosting policy), then remove the public bucket policy and disable
static website hosting once CloudFront is confirmed working.

## Local testing

```bash
curl -X POST https://YOUR-API-URL/prod/contact \
  -H "Content-Type: application/json" \
  -d '{"name":"Ada Lovelace","email":"ada@example.com"}'
```

## Notes / things a real production version would add

- **CORS is wide open** (`Access-Control-Allow-Origin: *`) — fine for a public form with no
  auth or cookies; scope it to the exact frontend origin if that ever changes.
- **No persistence** — submissions are only logged to CloudWatch. Add DynamoDB or SES if you
  actually need to store or forward them.
- **No rate limiting** — consider an API Gateway usage plan / throttling if this goes
  properly public.
