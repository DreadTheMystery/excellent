const path = require("path");
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

const DB_PATH = path.join(__dirname, "data", "school.db");
const db = new sqlite3.Database(DB_PATH);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 }
  })
);
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });

const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const CLASS_OPTIONS = [
  "Primary 1A",
  "Primary 1B",
  "Primary 2A",
  "Primary 2B",
  "Primary 3A",
  "Primary 3B",
  "Primary 4A",
  "Primary 4B",
  "Primary 5A",
  "Primary 5B",
  "Primary 6A",
  "Primary 6B",
  "JSS 1A",
  "JSS 1B",
  "JSS 2A",
  "JSS 2B",
  "JSS 3A",
  "JSS 3B",
  "SS 1A",
  "SS 1B",
  "SS 2A",
  "SS 2B",
  "SS 3A",
  "SS 3B"
];

const initDb = () => {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS inquiries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        section TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        gender TEXT NOT NULL,
        dob TEXT NOT NULL,
        class_name TEXT NOT NULL,
        guardian_name TEXT NOT NULL,
        guardian_phone TEXT NOT NULL,
        address TEXT,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        subject TEXT NOT NULL,
        class_name TEXT,
        qualification TEXT,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS finance_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        type TEXT NOT NULL,
        occurred_on TEXT NOT NULL,
        notes TEXT,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        term TEXT NOT NULL,
        session TEXT NOT NULL,
        class_name TEXT NOT NULL,
        exam_date TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        exam_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        score REAL NOT NULL,
        grade TEXT NOT NULL,
        remark TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(student_id) REFERENCES students(id),
        FOREIGN KEY(exam_id) REFERENCES exams(id)
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS student_fees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        class_name TEXT NOT NULL,
        term TEXT NOT NULL,
        session TEXT NOT NULL,
        total_fee REAL NOT NULL,
        amount_paid REAL NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(student_id) REFERENCES students(id)
      )`
    );
    db.run("ALTER TABLE teachers ADD COLUMN class_name TEXT", () => {});
    db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
      if (err) return;
      if (row.count === 0) {
        const adminEmail = process.env.ADMIN_EMAIL || "owner@excellenceacademy.ng";
        const adminPass = process.env.ADMIN_PASSWORD || "ChangeMe123!";
        const hash = bcrypt.hashSync(adminPass, 10);
        db.run(
          "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
          ["School Owner", adminEmail, hash, "owner", new Date().toISOString()],
          (seedErr) => {
            if (!seedErr) {
              console.log("Default owner created:", adminEmail, adminPass);
            }
          }
        );
      }
    });
  });
};

initDb();

const formatDate = (isoString) => {
  const date = new Date(isoString);
  return date.toLocaleString("en-NG", {
    timeZone: "Africa/Lagos",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
};

const requireAuth = (req, res, next) => {
  if (req.session.user) return next();
  return res.redirect("/login");
};

app.get("/", (req, res) => {
  const success = req.query.success === "1";
  res.render("index", { success });
});

app.get("/login", (req, res) => {
  const error = req.query.error === "1" ? "Invalid credentials." : null;
  res.render("login", { error });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.redirect("/login?error=1");
  }
  try {
    const user = await dbGet("SELECT * FROM users WHERE email = ?", [email.trim()]);
    if (!user) return res.redirect("/login?error=1");
    const isValid = bcrypt.compareSync(password, user.password_hash);
    if (!isValid) return res.redirect("/login?error=1");
    req.session.user = { id: user.id, name: user.name, role: user.role };
    return res.redirect("/dashboard");
  } catch (err) {
    return res.redirect("/login?error=1");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.post("/contact", (req, res) => {
  const { name, email, phone, section, message } = req.body;
  const allowedSections = new Set(["Nursery", "Primary", "Secondary"]);
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^(\+234|0)[0-9]{10}$/;

  if (!name || !email || !phone || !section || !message) {
    return res.status(400).render("index", { success: false, error: "All fields are required." });
  }

  if (!emailRegex.test(String(email).trim())) {
    return res.status(400).render("index", { success: false, error: "Please enter a valid email address." });
  }

  if (!phoneRegex.test(String(phone).trim())) {
    return res.status(400).render("index", { success: false, error: "Please enter a valid Nigerian phone number." });
  }

  if (!allowedSections.has(String(section).trim())) {
    return res.status(400).render("index", { success: false, error: "Please select a valid section." });
  }

  const createdAt = new Date().toISOString();
  db.run(
    `INSERT INTO inquiries (name, email, phone, section, message, created_at)
     VALUES (?, ?, ?, ?, ?, ?)` ,
    [name.trim(), email.trim(), phone.trim(), section.trim(), message.trim(), createdAt],
    (err) => {
      if (err) {
        return res.status(500).render("index", { success: false, error: "Could not send your message. Please try again." });
      }
      return res.redirect("/?success=1#contact");
    }
  );
});

app.get("/admin", requireAuth, (req, res) => {
  db.all("SELECT * FROM inquiries ORDER BY id DESC LIMIT 100", (err, rows) => {
    if (err) {
      return res.status(500).send("Failed to load inquiries");
    }
    const inquiries = rows.map((row) => ({
      ...row,
      created_at: formatDate(row.created_at)
    }));
    return res.render("admin", { inquiries });
  });
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const [students, teachers, inquiries, exams, results] = await Promise.all([
      dbGet("SELECT COUNT(*) as count FROM students"),
      dbGet("SELECT COUNT(*) as count FROM teachers"),
      dbGet("SELECT COUNT(*) as count FROM inquiries"),
      dbGet("SELECT COUNT(*) as count FROM exams"),
      dbGet("SELECT COUNT(*) as count FROM results")
    ]);
    const income = await dbGet(
      "SELECT COALESCE(SUM(amount), 0) as total FROM finance_records WHERE type = 'income'"
    );
    const expense = await dbGet(
      "SELECT COALESCE(SUM(amount), 0) as total FROM finance_records WHERE type = 'expense'"
    );
    const outstanding = await dbGet(
      "SELECT COALESCE(SUM(total_fee - amount_paid), 0) as total FROM student_fees WHERE status = 'partial'"
    );
    res.render("dashboard", {
      stats: {
        students: students.count,
        teachers: teachers.count,
        inquiries: inquiries.count,
        exams: exams.count,
        results: results.count,
        income: income.total,
        expense: expense.total,
        outstanding: outstanding.total
      }
    });
  } catch (err) {
    res.status(500).send("Failed to load dashboard");
  }
});

app.get("/dashboard/students", requireAuth, async (req, res) => {
  try {
    const students = await dbAll("SELECT * FROM students ORDER BY id DESC");
    res.render("students", { students, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load students");
  }
});

app.post("/dashboard/students", requireAuth, async (req, res) => {
  const { first_name, last_name, gender, dob, class_name, guardian_name, guardian_phone, address } = req.body;
  if (!first_name || !last_name || !gender || !dob || !class_name || !guardian_name || !guardian_phone) {
    return res.status(400).send("Missing student fields");
  }
  await dbRun(
    `INSERT INTO students (first_name, last_name, gender, dob, class_name, guardian_name, guardian_phone, address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      first_name.trim(),
      last_name.trim(),
      gender.trim(),
      dob,
      class_name.trim(),
      guardian_name.trim(),
      guardian_phone.trim(),
      address ? address.trim() : "",
      new Date().toISOString()
    ]
  );
  res.redirect("/dashboard/students");
});

app.post("/dashboard/students/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM students WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/students");
});

app.get("/dashboard/teachers", requireAuth, async (req, res) => {
  try {
    const teachers = await dbAll("SELECT * FROM teachers ORDER BY id DESC");
    res.render("teachers", { teachers, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load teachers");
  }
});

app.post("/dashboard/teachers", requireAuth, async (req, res) => {
  const { name, email, phone, subject, class_name, qualification } = req.body;
  if (!name || !email || !phone || !subject) {
    return res.status(400).send("Missing teacher fields");
  }
  await dbRun(
    `INSERT INTO teachers (name, email, phone, subject, class_name, qualification, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      name.trim(),
      email.trim(),
      phone.trim(),
      subject.trim(),
      class_name ? class_name.trim() : "",
      qualification ? qualification.trim() : "",
      new Date().toISOString()
    ]
  );
  res.redirect("/dashboard/teachers");
});

app.post("/dashboard/teachers/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM teachers WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/teachers");
});

app.get("/dashboard/finance", requireAuth, async (req, res) => {
  try {
    const records = await dbAll("SELECT * FROM finance_records ORDER BY occurred_on DESC, id DESC");
    res.render("finance", { records });
  } catch (err) {
    res.status(500).send("Failed to load finance records");
  }
});

app.post("/dashboard/finance", requireAuth, async (req, res) => {
  const { title, category, amount, type, occurred_on, notes } = req.body;
  if (!title || !category || !amount || !type || !occurred_on) {
    return res.status(400).send("Missing finance fields");
  }
  await dbRun(
    `INSERT INTO finance_records (title, category, amount, type, occurred_on, notes, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title.trim(), category.trim(), Number(amount), type, occurred_on, notes ? notes.trim() : "", new Date().toISOString()]
  );
  res.redirect("/dashboard/finance");
});

app.post("/dashboard/finance/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM finance_records WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/finance");
});

app.get("/dashboard/exams", requireAuth, async (req, res) => {
  try {
    const exams = await dbAll("SELECT * FROM exams ORDER BY exam_date DESC, id DESC");
    res.render("exams", { exams, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load exams");
  }
});

app.post("/dashboard/exams", requireAuth, async (req, res) => {
  const { name, term, session, class_name, exam_date } = req.body;
  if (!name || !term || !session || !class_name || !exam_date) {
    return res.status(400).send("Missing exam fields");
  }
  await dbRun(
    `INSERT INTO exams (name, term, session, class_name, exam_date, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name.trim(), term.trim(), session.trim(), class_name.trim(), exam_date, new Date().toISOString()]
  );
  res.redirect("/dashboard/exams");
});

app.post("/dashboard/exams/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM exams WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/exams");
});

app.get("/dashboard/results", requireAuth, async (req, res) => {
  try {
    const [results, students, exams] = await Promise.all([
      dbAll(
        `SELECT results.*, students.first_name, students.last_name, exams.name as exam_name
         FROM results
         JOIN students ON students.id = results.student_id
         JOIN exams ON exams.id = results.exam_id
         ORDER BY results.id DESC`
      ),
      dbAll("SELECT id, first_name, last_name FROM students ORDER BY first_name"),
      dbAll("SELECT id, name, class_name FROM exams ORDER BY exam_date DESC")
    ]);
    res.render("results", { results, students, exams });
  } catch (err) {
    res.status(500).send("Failed to load results");
  }
});

app.post("/dashboard/results", requireAuth, async (req, res) => {
  const { student_id, exam_id, subject, score, grade, remark } = req.body;
  if (!student_id || !exam_id || !subject || !score || !grade) {
    return res.status(400).send("Missing result fields");
  }
  await dbRun(
    `INSERT INTO results (student_id, exam_id, subject, score, grade, remark, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [student_id, exam_id, subject.trim(), Number(score), grade.trim(), remark ? remark.trim() : "", new Date().toISOString()]
  );
  res.redirect("/dashboard/results");
});

app.post("/dashboard/results/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM results WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/results");
});

app.get("/dashboard/payments", requireAuth, async (req, res) => {
  try {
    const [payments, students] = await Promise.all([
      dbAll(
        `SELECT student_fees.*, students.first_name, students.last_name
         FROM student_fees
         JOIN students ON students.id = student_fees.student_id
         ORDER BY student_fees.id DESC`
      ),
      dbAll("SELECT id, first_name, last_name, class_name FROM students ORDER BY first_name")
    ]);
    res.render("payments", { payments, students, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load payments");
  }
});

app.post("/dashboard/payments", requireAuth, async (req, res) => {
  const { student_id, class_name, term, session, total_fee, amount_paid } = req.body;
  if (!student_id || !class_name || !term || !session || !total_fee || !amount_paid) {
    return res.status(400).send("Missing payment fields");
  }
  const total = Number(total_fee);
  const paid = Number(amount_paid);
  const status = paid >= total ? "paid" : "partial";
  await dbRun(
    `INSERT INTO student_fees (student_id, class_name, term, session, total_fee, amount_paid, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      student_id,
      class_name.trim(),
      term.trim(),
      session.trim(),
      total,
      paid,
      status,
      new Date().toISOString()
    ]
  );
  res.redirect("/dashboard/payments");
});

app.post("/dashboard/payments/:id/delete", requireAuth, async (req, res) => {
  await dbRun("DELETE FROM student_fees WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/payments");
});

app.get("/api/inquiries", (req, res) => {
  db.all(
    "SELECT id, name, email, phone, section, message, created_at FROM inquiries ORDER BY id DESC LIMIT 50",
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: "Failed to load inquiries" });
      }
      return res.json({ data: rows });
    }
  );
});

app.use((req, res) => {
  res.status(404).send("Page not found");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
