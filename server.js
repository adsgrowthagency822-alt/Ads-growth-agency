require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SECRET) throw new Error("JWT_SECRET is missing");
if (!DATABASE_URL) throw new Error("DATABASE_URL is missing");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 10000
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150
}));
app.use(express.static(path.join(__dirname, "public")));

function clean(value, max = 2000) {
  return String(value || "").trim().slice(0, max);
}

function esc(value) {
  return String(value || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

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

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      product_name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price TEXT DEFAULT '',
      image TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Buy Now',
      pixel_id TEXT DEFAULT '',
      published INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS leads (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
      customer_name TEXT,
      phone TEXT,
      email TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const email = clean(process.env.ADMIN_EMAIL, 150).toLowerCase();
  const password = process.env.ADMIN_PASSWORD;

  if (email && password) {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (!existing.rowCount) {
      const hash = await bcrypt.hash(password, 12);

      await pool.query(
        `INSERT INTO users(name,email,password,role)
         VALUES($1,$2,$3,'admin')`,
        ["Administrator", email, hash]
      );
    }
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

    const result = await pool.query(
      `INSERT INTO users(name,email,password)
       VALUES($1,$2,$3) RETURNING id`,
      [name, email, hash]
    );

    const user = {
      id: result.rows[0].id,
      name,
      email,
      role: "user"
    };

    res.json({
      token: createToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({
        error: "Email already registered"
      });
    }

    console.error(error);
    res.status(500).json({ error: "Could not create account" });
  }
});

/* LOGIN */
app.post("/api/login", async (req, res) => {
  try {
    const email = clean(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

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
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
  }
});

/* CURRENT USER */
app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,name,email,role,created_at
       FROM users WHERE id=$1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load user" });
  }
});

/* CREATE PAGE */
app.post("/api/pages", auth, async (req, res) => {
  try {
    const title = clean(req.body.title, 100);
    const product = clean(req.body.product_name, 150);

    if (!title || !product) {
      return res.status(400).json({
        error: "Title and product name required"
      });
    }

    const slug = crypto.randomBytes(8).toString("hex");

    const result = await pool.query(`
      INSERT INTO pages(
        user_id,title,slug,product_name,
        description,price,image,button_text,pixel_id
      )
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id
    `, [
      req.user.id,
      title,
      slug,
      product,
      clean(req.body.description),
      clean(req.body.price, 30),
      clean(req.body.image, 2000),
      clean(req.body.button_text, 40) || "Buy Now",
      clean(req.body.pixel_id, 30).replace(/\D/g, "")
    ]);

    res.json({
      success: true,
      id: result.rows[0].id,
      slug,
      url: `${req.protocol}://${req.get("host")}/p/${slug}`
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not create page" });
  }
});

/* LIST PAGES */
app.get("/api/pages", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM pages WHERE user_id=$1 ORDER BY id DESC",
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load pages" });
  }
});

/* EDIT PAGE */
app.put("/api/pages/:id", auth, async (req, res) => {
  try {
    const found = await pool.query(
      "SELECT * FROM pages WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.id]
    );

    const page = found.rows[0];

    if (!page) {
      return res.status(404).json({ error: "Page not found" });
    }

    await pool.query(`
      UPDATE pages SET
        title=$1,
        product_name=$2,
        description=$3,
        price=$4,
        image=$5,
        button_text=$6,
        pixel_id=$7
      WHERE id=$8 AND user_id=$9
    `, [
      clean(req.body.title || page.title, 100),
      clean(req.body.product_name || page.product_name, 150),
      clean(req.body.description ?? page.description),
      clean(req.body.price ?? page.price, 30),
      clean(req.body.image ?? page.image, 2000),
      clean(req.body.button_text || page.button_text, 40),
      clean(req.body.pixel_id ?? page.pixel_id, 30).replace(/\D/g, ""),
      page.id,
      req.user.id
    ]);

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not update page" });
  }
});

/* PUBLISH PAGE */
app.patch("/api/pages/:id/publish", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE pages SET published=$1
       WHERE id=$2 AND user_id=$3 RETURNING id`,
      [req.body.published ? 1 : 0, req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not publish page" });
  }
});

/* DELETE PAGE */
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM pages WHERE id=$1 AND user_id=$2 RETURNING id",
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Page not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not delete page" });
  }
});

/* USER LEADS */
app.get("/api/leads", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT leads.*, pages.title AS page_title
      FROM leads
      JOIN pages ON pages.id=leads.page_id
      WHERE pages.user_id=$1
      ORDER BY leads.id DESC
    `, [req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load leads" });
  }
});

/* ADMIN STATS */
app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  try {
    const [users, pages, leads] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total FROM users"),
      pool.query("SELECT COUNT(*)::int AS total FROM pages"),
      pool.query("SELECT COUNT(*)::int AS total FROM leads")
    ]);

    res.json({
      users: users.rows[0].total,
      pages: pages.rows[0].total,
      leads: leads.rows[0].total
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load admin stats" });
  }
});

/* PUBLIC LANDING PAGE */
app.get("/p/:slug", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM pages WHERE slug=$1 AND published=1",
      [req.params.slug]
    );

    const page = result.rows[0];

    if (!page) {
      return res.status(404).send("Landing page not found");
    }

    const pixelId = String(page.pixel_id || "").replace(/\D/g, "");

    const pixelCode = pixelId ? `
      <script>
      !function(f,b,e,v,n,t,s){
        if(f.fbq)return;
        n=f.fbq=function(){
          n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)
        };
        if(!f._fbq)f._fbq=n;
        n.push=n;n.loaded=!0;n.version='2.0';
        n.queue=[];
        t=b.createElement(e);t.async=!0;
        t.src=v;
        s=b.getElementsByTagName(e)[0];
        s.parentNode.insertBefore(t,s)
      }(window,document,'script',
      'https://connect.facebook.net/en_US/fbevents.js');
      fbq('init','${pixelId}');
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
          body{margin:0;padding:20px;background:#081225;color:white;font-family:Arial,sans-serif}
          .card{max-width:430px;margin:25px auto;padding:22px;background:#172640;border-radius:16px;text-align:center}
          img{width:100%;max-height:280px;object-fit:contain}
          input{width:100%;padding:13px;margin:8px 0;box-sizing:border-box;border:0;border-radius:7px}
          button{width:100%;padding:14px;background:#16a34a;color:white;border:0;border-radius:8px;font-weight:bold}
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
          const form = document.getElementById("leadForm");

          form.addEventListener("submit", async e => {
            e.preventDefault();

            const data = Object.fromEntries(
              new FormData(form).entries()
            );

            const button = form.querySelector("button");
            button.disabled = true;

            try {
              const response = await fetch(
                "/api/public/leads/${page.id}",
                {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify(data)
                }
              );

              const result = await response.json();

              if (!response.ok) {
                throw new Error(result.error || "Try again");
              }

              document.getElementById("message").textContent =
                "Thank you! Your details have been received.";

              if (typeof fbq === "function") {
                fbq("track", "Lead");
              }

              form.reset();
            } catch (error) {
              document.getElementById("message").textContent =
                error.message;
            } finally {
              button.disabled = false;
            }
          });
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).send("Could not load landing page");
  }
});

/* PUBLIC LEAD SUBMISSION */
app.post("/api/public/leads/:id", async (req, res) => {
  try {
    const found = await pool.query(
      "SELECT id FROM pages WHERE id=$1 AND published=1",
      [req.params.id]
    );

    const page = found.rows[0];

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

    await pool.query(
      `INSERT INTO leads(page_id,customer_name,phone,email)
       VALUES($1,$2,$3,$4)`,
      [page.id, name, phone, email]
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not save lead" });
  }
});

/* HOME */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* START SERVER */
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log("ADS GROWTH AGENCY running on port " + PORT);
    });
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
  
