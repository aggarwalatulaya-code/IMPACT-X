// Runs on Netlify before publishing: injects private settings from environment variables into index.html.
import { readFileSync, writeFileSync } from "node:fs";
let s = readFileSync("index.html", "utf8");
const put = (name, val) => { const re = new RegExp("const " + name + "='[^']*';"); if (!re.test(s)) throw new Error(name + " placeholder missing"); s = s.replace(re, () => "const " + name + "='" + String(val || "").replace(/[^A-Za-z0-9:._@-]/g, "") + "';"); };
put("ADMIN_HASH", process.env.ADMIN_HASH);
put("GOOGLE_CLIENT_ID", process.env.GOOGLE_CLIENT_ID);
writeFileSync("index.html", s);
console.log("Settings injected. Admin " + (process.env.ADMIN_HASH ? "ON" : "locked") + ", Google sign-in " + (process.env.GOOGLE_CLIENT_ID ? "ON" : "off"));
