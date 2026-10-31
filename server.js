
require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  throw new Error("JWT_SECRET is missing");
}

const db = new Database("ads-growth.db");

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 role TEXT DEFAULT 'user',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 slug TEXT UNIQUE NOT NULL,
 product_name TEXT NOT NULL,
 description TEXT DEFAULT '',
 price TEXT DEFAULT '',
 image TEXT DEFAULT '',
 button_text TEXT DEFAULT 'Buy Now',
 pixel_id TEXT DEFAULT '',
 published INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS leads (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 page_id INTEGER NOT NULL,
 customer_name TEXT,
 phone TEXT,
 email TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api", rateLimit({
 windowMs: 15 * 60 * 1000,
 max: 150
}));

app.use(express.static(path.join(__dirname, "public")));

function createToken(user) {
 return jwt.sign(
  { id: user.id, role: user.role },
  SECRET,
  { expiresIn: "7d" }
 );
}

function auth(req, res, next) {
 const header = req.headers.authorization || "";
 const token = header.startsWith("Bearer ")
  ? header.slice(7)
  : "";

 try {
  req.user = jwt.verify(token, SECRET);
  next();
 } catch {
  res.status(401).json({ error: "Please login again" });
 }
}

function adminOnly(req, res, next) {
 if (req.user.role !== "admin") {
  return res.status(403).json({ error: "Admin only" });
 }
 next();
}

function clean(value, max = 2000) {
 return String(value || "").trim().slice(0, max);
}

async function setupAdmin() {
 const email = process.env.ADMIN_EMAIL;
 const password = process.env.ADMIN_PASSWORD;

 if (!email || !password) return;

 const exists = db.prepare(
  "SELECT id FROM users WHERE email=?"
 ).get(email.toLowerCase());

 if (!exists) {
  const hash = await bcrypt.hash(password, 12);

  db.prepare(`
   INSERT INTO users(name,email,password,role)
   VALUES(?,?,?,'admin')
  `).run("Administrator", email.toLowerCase(), hash);
 }
}

/* SIGNUP */

app.post("/api/signup", async (req, res) => {
 try {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 150).toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !email.includes("@") || password.length < 8) {
   return res.status(400).json({
    error: "Valid name, email and 8 character password required"
   });
  }

  const hash = await bcrypt.hash(password, 12);

  const result = db.prepare(`
   INSERT INTO users(name,email,password)
   VALUES(?,?,?)
  `).run(name, email, hash);

  const user = {
   id: result.lastInsertRowid,
   name,
   email,
   role: "user"
  };

  res.json({
   token: createToken(user),
   user
  });
 } catch {
  res.status(400).json({
   error: "Email already registered"
  });
 }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
 const email = clean(req.body.email, 150).toLowerCase();
 const password = String(req.body.password || "");

 const user = db.prepare(
  "SELECT * FROM users WHERE email=?"
 ).get(email);

 if (!user || !(await bcrypt.compare(password, user.password))) {
  return res.status(401).json({
   error: "Incorrect email or password"
  });
 }

 res.json({
  token: createToken(user),
  user: {
   id: user.id,
   name: user.name,
   email: user.email,
   role: user.role
  }
 });
});

/* CURRENT USER */

app.get("/api/me", auth, (req, res) => {
 const user = db.prepare(`
  SELECT id,name,email,role,created_at
  FROM users WHERE id=?
 `).get(req.user.id);

 res.json(user);
});

/* CREATE PAGE */

app.post("/api/pages", auth, (req, res) => {
 const title = clean(req.body.title, 100);
 const product = clean(req.body.product_name, 150);

 if (!title || !product) {
  return res.status(400).json({
   error: "Title and product name required"
  });
 }

 const slug = crypto.randomBytes(8).toString("hex");

 const result = db.prepare(`
  INSERT INTO pages(
   user_id,title,slug,product_name,
   description,price,image,button_text,pixel_id
  )
  VALUES(?,?,?,?,?,?,?,?,?)
 `).run(
  req.user.id,
  title,
  slug,
  product,
  clean(req.body.description),
  clean(req.body.price, 30),
  clean(req.body.image, 2000),
  clean(req.body.button_text, 40) || "Buy Now",
  clean(req.body.pixel_id, 30).replace(/\D/g, "")
 );

 res.json({
  success: true,
  id: result.lastInsertRowid,
  slug,
  url: (process.env.BASE_URL || "") + "/p/" + slug
 });
});

/* LIST PAGES */

app.get("/api/pages", auth, (req, res) => {
 const pages = db.prepare(`
  SELECT * FROM pages
  WHERE user_id=?
  ORDER BY id DESC
 `).all(req.user.id);

 res.json(pages);
});

/* EDIT PAGE */

app.put("/api/pages/:id", auth, (req, res) => {
 const page = db.prepare(`
  SELECT * FROM pages
  WHERE id=? AND user_id=?
 `).get(req.params.id, req.user.id);

 if (!page) {
  return res.status(404).json({ error: "Page not found" });
 }

 db.prepare(`
  UPDATE pages SET
   title=?,
   product_name=?,
   description=?,
   price=?,
   image=?,
   button_text=?,
   pixel_id=?
  WHERE id=? AND user_id=?
 `).run(
  clean(req.body.title || page.title, 100),
  clean(req.body.product_name || page.product_name, 150),
  clean(req.body.description ?? page.description),
  clean(req.body.price ?? page.price, 30),
  clean(req.body.image ?? page.image, 2000),
  clean(req.body.button_text || page.button_text, 40),
  clean(req.body.pixel_id ?? page.pixel_id, 30).replace(/\D/g, ""),
  page.id,
  req.user.id
 );

 res.json({ success: true });
});

/* PUBLISH PAGE */

app.patch("/api/pages/:id/publish", auth, (req, res) => {
 const result = db.prepare(`
  UPDATE pages SET published=?
  WHERE id=? AND user_id=?
 `).run(
  req.body.published ? 1 : 0,
  req.params.id,
  req.user.id
 );

 if (!result.changes) {
  return res.status(404).json({ error: "Page not found" });
 }

 res.json({ success: true });
});

/* DELETE PAGE */

app.delete("/api/pages/:id", auth, (req, res) => {
 const page = db.prepare(`
  SELECT id FROM pages
  WHERE id=? AND user_id=?
 `).get(req.params.id, req.user.id);

 if (!page) {
  return res.status(404).json({ error: "Page not found" });
 }

 db.prepare("DELETE FROM leads WHERE page_id=?").run(page.id);
 db.prepare("DELETE FROM pages WHERE id=?").run(page.id);

 res.json({ success: true });
});

/* USER LEADS */

app.get("/api/leads", auth, (req, res) => {
 const leads = db.prepare(`
  SELECT leads.*, pages.title AS page_title
  FROM leads
  JOIN pages ON pages.id=leads.page_id
  WHERE pages.user_id=?
  ORDER BY leads.id DESC
 `).all(req.user.id);

 res.json(leads);
});

/* ADMIN STATS */

app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
 const users = db.prepare(
  "SELECT COUNT(*) AS total FROM users"
 ).get().total;

 const pages = db.prepare(
  "SELECT COUNT(*) AS total FROM pages"
 ).get().total;

 const leads = db.prepare(
  "SELECT COUNT(*) AS total FROM leads"
 ).get().total;

 res.json({ users, pages, leads });
});

/* HTML ESCAPE */

function esc(value) {
 return String(value || "").replace(/[&<>"']/g, c => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
 })[c]);
}

/* PUBLIC LANDING PAGE */

app.get("/p/:slug", (req, res) => {
 const page = db.prepare(`
  SELECT * FROM pages
  WHERE slug=? AND published=1
 `).get(req.params.slug);

 if (!page) {
  return res.status(404).send("Landing page not found");
 }

 const pixelCode = page.pixel_id ? `
 <script>
 !function(f,b,e,v,n,t,s)
 {if(f.fbq)return;n=f.fbq=function(){
 n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
 if(!f._fbq)f._fbq=n;
 n.push=n;n.loaded=!0;n.version='2.0';
 n.queue=[];t=b.createElement(e);t.async=!0;
 t.src=v;s=b.getElementsByTagName(e)[0];
 s.parentNode.insertBefore(t,s)
 }(window,document,'script',
 'https://connect.facebook.net/en_US/fbevents.js');
 fbq('init','${page.pixel_id}');
 fbq('track','PageView');
 </script>
 ` : "";

 res.send(`
 <!DOCTYPE html>
 <html lang="en">
 <head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width,initial-scale=1">
 <title>${esc(page.title)}</title>
 ${pixelCode}
 <style>
 body{margin:0;padding:20px;background:#081225;color:white;
 font-family:Arial,sans-serif}
 .card{max-width:430px;margin:25px auto;padding:22px;
 background:#172640;border-radius:16px;text-align:center}
 img{width:100%;max-height:280px;object-fit:contain}
 input{width:100%;padding:13px;margin:8px 0;
 box-sizing:border-box;border:0;border-radius:7px}
 button{width:100%;padding:14px;background:#16a34a;
 color:white;border:0;border-radius:8px;font-weight:bold}
 .price{font-size:26px;font-weight:bold}
 </style>
 </head>
 <body>
 <div class="card">
 ${page.image ? `<img src="${esc(page.image)}" alt="Product">` : ""}
 <h1>${esc(page.product_name)}</h1>
 <p>${esc(page.description)}</p>
 <div class="price">${esc(page.price)}</div>
 <form id="leadForm">
 <input name="customer_name" placeholder="Your Name" required>
 <input name="phone" placeholder="Phone Number" required>
 <input name="email" type="email" placeholder="Email (optional)">
 <button type="submit">${esc(page.button_text)}</button>
 </form>
 <p id="message"></p>
 </div>
 <script>
 const form=document.getElementById("leadForm");
 form.addEventListener("submit",async e=>{
 e.preventDefault();
 const data=Object.fromEntries(new FormData(form).entries());
 const button=form.querySelector("button");
 button.disabled=true;
 try{
 const response=await fetch("/api/public/leads/${page.id}",{
 method:"POST",
 headers:{"Content-Type":"application/json"},
 body:JSON.stringify(data)
 });
 const result=await response.json();
 if(!response.ok) throw new Error(result.error || "Try again");
 document.getElementById("message").textContent=
 "Thank you! Your details have been received.";
 if(typeof fbq==="function") fbq("track","Lead");
 form.reset();
 }catch(error){
 document.getElementById("message").textContent=error.message;
 }finally{
 button.disabled=false;
 }
 });
 </script>
 </body>
 </html>
 `);
});

/* PUBLIC LEAD SUBMISSION */

app.post("/api/public/leads/:id", (req, res) => {
 const page = db.prepare(`
  SELECT id FROM pages
  WHERE id=? AND published=1
 `).get(req.params.id);

 if (!page) {
  return res.status(404).json({ error: "Page not found" });
 }

 const name = clean(req.body.customer_name, 100);
 const phone = clean(req.body.phone, 30);
 const email = clean(req.body.email, 150);

 if (!name || !phone) {
  return res.status(400).json({
   error: "Name and phone are required"
  });
 }

 db.prepare(`
  INSERT INTO leads(page_id,customer_name,phone,email)
  VALUES(?,?,?,?)
 `).run(page.id, name, phone, email);

 res.json({ success: true });
});

/* HOME */

app.get("/", (req, res) => {
 res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* START */

setupAdmin().then(() => {
 app.listen(PORT, () => {
  console.log("ADS GROWTH AGENCY running on port " + PORT);
 });
}).catch(error => {
 console.error("Startup failed:", error);
 process.exit(1);
});
        
