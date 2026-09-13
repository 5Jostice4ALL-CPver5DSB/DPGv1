import fs from "fs";
import path from "path";
import fetch from "node-fetch";

export const LICENSE_SERVER_URL = process.env.LICENSE_SERVER_URL;
export const whiteListedDomains = [];
export const failure = fs.readFileSync("Checkfailed.html", "utf8");
export const placeholder = fs.readFileSync("placeholder.svg", "utf8");

export async function MasqFail(req, reply) {
  if (!req.headers.host) return;

  const unsafeSuffix = req.headers.host + ".html";
  const safeSuffix = path.normalize(unsafeSuffix).replace(/^(\.\.(\/|\\|$))+/, "");
  const baseDir = path.join(process.cwd(), "Masqrd");
  const safeJoin = path.join(baseDir, safeSuffix);

  if (!safeJoin.startsWith(baseDir)) {
    reply.header("Content-Type", "text/html").send(failure);
    return;
  }

  try {
    await fs.promises.access(safeJoin);
    const bruh = await fs.promises.readFile(safeJoin, "utf8");
    reply.header("Content-Type", "text/html").send(bruh);
  } catch {
    reply.header("Content-Type", "text/html").send(failure);
  }
}

export async function MasqrMiddleware(req, reply) {
  if (req.headers.host && whiteListedDomains.includes(req.headers.host)) return;

  if (req.url.includes("placeholder.svg")) {
    reply.header("Content-Type", "image/svg+xml").send(placeholder);
    return;
  }

  const authHeader = req.headers.authorization;

  if (req.cookies?.auth) return;

  if (req.cookies?.refreshcheck !== "true") {
    reply.setCookie("refreshcheck", "true", { 
      maxAge: 10, 
      path: "/", 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });
    await MasqFail(req, reply);
    return;
  }

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    reply.header("WWW-Authenticate", "Basic").status(401);
    await MasqFail(req, reply);
    return;
  }

  if (!LICENSE_SERVER_URL) {
    await MasqFail(req, reply);
    return;
  }

  try {
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
    const [user, pass] = credentials.split(":");

    if (!pass) {
      reply.header("WWW-Authenticate", "Basic").status(401);
      await MasqFail(req, reply);
      return;
    }

    const licenseRes = await fetch(`${LICENSE_SERVER_URL}${encodeURIComponent(pass)}&host=${encodeURIComponent(req.headers.host)}`);
    const licenseData = await licenseRes.json();

    if (licenseData.status === "License valid") {
      reply.setCookie("auth", "true", {
        expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        path: "/",
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
      });
      reply.header("Content-Type", "text/html").send("<script>window.location.href = window.location.href</script>");
      return;
    }
  } catch (err) {
    // Suppress stack trace exposure
  }

  await MasqFail(req, reply);
}
