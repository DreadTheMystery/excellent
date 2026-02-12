require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const PDFDocument = require("pdfkit");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const axios = require("axios");
const compression = require("compression");

const app = express();
const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL. Set it to your Postgres connection string.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  family: 4
});

const toPgSql = (sql) => {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
};

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Enable Gzip compression
app.use(compression());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files with caching headers
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: process.env.NODE_ENV === "production" ? "1y" : 0,
  etag: true,
  lastModified: true
}));

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

const dbAll = async (sql, params = []) => {
  const result = await pool.query(toPgSql(sql), params);
  return result.rows;
};

const dbGet = async (sql, params = []) => {
  const result = await pool.query(toPgSql(sql), params);
  return result.rows[0] || null;
};

const dbRun = async (sql, params = []) => {
  return pool.query(toPgSql(sql), params);
};

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

const ROLE_OPTIONS = ["owner", "admin", "teacher", "accountant"];
const ROLE_SET = new Set(ROLE_OPTIONS);

const initDb = async () => {
  await dbRun(
    `CREATE TABLE IF NOT EXISTS inquiries (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      section TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS admissions (
      id SERIAL PRIMARY KEY,
      student_name TEXT NOT NULL,
      dob TEXT NOT NULL,
      gender TEXT NOT NULL,
      class_applied TEXT NOT NULL,
      parent_name TEXT NOT NULL,
      parent_phone TEXT NOT NULL,
      parent_email TEXT NOT NULL,
      address TEXT,
      previous_school TEXT,
      notes TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
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
  await dbRun(
    `CREATE TABLE IF NOT EXISTS teachers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      subject TEXT NOT NULL,
      class_name TEXT,
      qualification TEXT,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS finance_records (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      amount REAL NOT NULL,
      type TEXT NOT NULL,
      occurred_on TEXT NOT NULL,
      notes TEXT,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS exams (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      term TEXT NOT NULL,
      session TEXT NOT NULL,
      class_name TEXT NOT NULL,
      exam_date TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS results (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id),
      exam_id INTEGER NOT NULL REFERENCES exams(id),
      subject TEXT NOT NULL,
      score REAL NOT NULL,
      grade TEXT NOT NULL,
      remark TEXT,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS student_fees (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id),
      class_name TEXT NOT NULL,
      term TEXT NOT NULL,
      session TEXT NOT NULL,
      total_fee REAL NOT NULL,
      amount_paid REAL NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS assessments (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id),
      class_name TEXT NOT NULL,
      term TEXT NOT NULL,
      session TEXT NOT NULL,
      subject TEXT NOT NULL,
      assessment_type TEXT NOT NULL,
      score REAL NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      capacity INTEGER NOT NULL,
      class_teacher_id INTEGER REFERENCES teachers(id),
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS timetables (
      id SERIAL PRIMARY KEY,
      class_name TEXT NOT NULL,
      day TEXT NOT NULL,
      period TEXT NOT NULL,
      subject TEXT NOT NULL,
      teacher_name TEXT,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS attendance_students (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id),
      class_name TEXT NOT NULL,
      attendance_date TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS attendance_teachers (
      id SERIAL PRIMARY KEY,
      teacher_id INTEGER NOT NULL REFERENCES teachers(id),
      attendance_date TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS fee_plans (
      id SERIAL PRIMARY KEY,
      class_name TEXT NOT NULL,
      term TEXT NOT NULL,
      session TEXT NOT NULL,
      amount REAL NOT NULL,
      discount REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS invoices (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id),
      class_name TEXT NOT NULL,
      term TEXT NOT NULL,
      session TEXT NOT NULL,
      fee_plan_id INTEGER REFERENCES fee_plans(id),
      total REAL NOT NULL,
      discount REAL NOT NULL,
      amount_paid REAL NOT NULL,
      due_date TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun(
    `CREATE TABLE IF NOT EXISTS invoice_payments (
      id SERIAL PRIMARY KEY,
      invoice_id INTEGER NOT NULL REFERENCES invoices(id),
      amount REAL NOT NULL,
      method TEXT,
      paid_on TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`
  );
  await dbRun("ALTER TABLE teachers ADD COLUMN IF NOT EXISTS class_name TEXT");

  const row = await dbGet("SELECT COUNT(*) as count FROM users");
  if (row && Number(row.count) === 0) {
    const adminEmail = process.env.ADMIN_EMAIL || "owner@excellenceacademy.ng";
    const adminPass = process.env.ADMIN_PASSWORD || "ChangeMe123!";
    const hash = bcrypt.hashSync(adminPass, 10);
    await dbRun(
      "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
      ["School Owner", adminEmail, hash, "owner", new Date().toISOString()]
    );
    console.log("Default owner created:", adminEmail, adminPass);
  }
};

initDb().catch((err) => {
  console.error("Failed to initialize database", err);
  process.exit(1);
});

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

const requireRole = (...roles) => (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  if (!roles.includes(req.session.user.role)) {
    return res.status(403).render("forbidden");
  }
  return next();
};

const getTeacherClass = async (user) => {
  if (!user || user.role !== "teacher") return null;
  const teacher = await dbGet("SELECT class_name FROM teachers WHERE email = ?", [user.email]);
  return teacher && teacher.class_name ? teacher.class_name : null;
};

const createTransporter = () => {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
};

const sendAdmissionEmail = async ({ to, subject, text, html }) => {
  const transporter = createTransporter();
  if (!transporter) return false;
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  await transporter.sendMail({ from, to, subject, text, html });
  return true;
};

const sendAdmissionSms = async ({ to, message }) => {
  const apiKey = process.env.TERMII_API_KEY;
  const sender = process.env.TERMII_SENDER_ID || "N-Alert";
  if (!apiKey) {
    console.log("SMS not sent: TERMII_API_KEY not configured");
    return false;
  }
  
  // Format phone number for Termii (accepts 234XXXXXXXXXX format)
  let phone = String(to).replace(/\s+/g, '');
  if (phone.startsWith('0')) {
    phone = '234' + phone.substring(1);
  } else if (phone.startsWith('+234')) {
    phone = phone.substring(1);
  } else if (!phone.startsWith('234')) {
    phone = '234' + phone;
  }
  
  try {
    const response = await axios.post("https://api.ng.termii.com/api/sms/send", {
      to: phone,
      from: sender,
      sms: message,
      type: "plain",
      channel: "generic",
      api_key: apiKey
    });
    console.log("SMS sent successfully to", phone, "Response:", response.data);
    return true;
  } catch (error) {
    console.error("SMS send failed:", error.response?.data || error.message);
    return false;
  }
};

app.get("/", (req, res) => {
  const success = req.query.success === "1";
  res.render("index", { success });
});

app.get("/admissions", (req, res) => {
  const success = req.query.success === "1";
  res.render("admissions", { success, error: null, classOptions: CLASS_OPTIONS });
});

app.post("/admissions", async (req, res) => {
  const {
    student_name,
    dob,
    gender,
    class_applied,
    parent_name,
    parent_phone,
    parent_email,
    address,
    previous_school,
    notes
  } = req.body;

  if (!student_name || !dob || !gender || !class_applied || !parent_name || !parent_phone || !parent_email) {
    return res.status(400).render("admissions", {
      success: false,
      error: "Please fill all required fields.",
      classOptions: CLASS_OPTIONS
    });
  }

  await dbRun(
    `INSERT INTO admissions (student_name, dob, gender, class_applied, parent_name, parent_phone, parent_email, address, previous_school, notes, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      student_name.trim(),
      dob,
      gender,
      class_applied,
      parent_name.trim(),
      parent_phone.trim(),
      parent_email.trim(),
      address ? address.trim() : "",
      previous_school ? previous_school.trim() : "",
      notes ? notes.trim() : "",
      "pending",
      new Date().toISOString()
    ]
  );

  res.redirect("/admissions?success=1");
});

app.get("/login", (req, res) => {
  const error = req.query.error === "1" ? "Invalid credentials." : null;
  res.render("login", { error });
});

app.post("/login", async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role) {
    return res.redirect("/login?error=1");
  }
  try {
    const user = await dbGet("SELECT * FROM users WHERE email = ?", [email.trim()]);
    if (!user) return res.redirect("/login?error=1");
    if (user.role !== role) return res.redirect("/login?error=1");
    const isValid = bcrypt.compareSync(password, user.password_hash);
    if (!isValid) return res.redirect("/login?error=1");
    req.session.user = { id: user.id, name: user.name, role: user.role, email: user.email };
    if (user.role === "teacher") return res.redirect("/teacher");
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

app.get("/admin", requireRole("owner", "admin"), (req, res) => {
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

app.get("/dashboard", requireRole("owner", "admin", "teacher", "accountant"), async (req, res) => {
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
    const feeBalances =
      req.session.user.role === "owner"
        ? await dbAll(
            `SELECT students.id as student_id, students.first_name, students.last_name, students.class_name,
                    invoices.term, invoices.session, invoices.total, invoices.amount_paid,
                    (invoices.total - invoices.amount_paid) as balance, invoices.status
             FROM invoices
             JOIN students ON students.id = invoices.student_id
             ORDER BY students.class_name, students.first_name, invoices.session, invoices.term`
          )
        : [];

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
      },
      feeBalances
    });
  } catch (err) {
    res.status(500).send("Failed to load dashboard");
  }
});

app.get("/dashboard/admissions", requireRole("owner", "admin"), async (req, res) => {
  try {
    const applications = await dbAll("SELECT * FROM admissions ORDER BY id DESC");
    res.render("admissions-admin", { applications });
  } catch (err) {
    res.status(500).send("Failed to load admissions");
  }
});

app.post("/dashboard/admissions/:id/status", requireRole("owner", "admin"), async (req, res) => {
  const { status, note } = req.body;
  const allowed = new Set(["pending", "approved", "rejected", "waitlist"]);
  if (!allowed.has(status)) {
    return res.status(400).send("Invalid status");
  }
  const admission = await dbGet("SELECT * FROM admissions WHERE id = ?", [req.params.id]);
  if (!admission) return res.status(404).send("Application not found");

  await dbRun("UPDATE admissions SET status = ? WHERE id = ?", [status, req.params.id]);

  const message =
    `Hello ${admission.parent_name}, your child's admission status is ${status.toUpperCase()} ` +
    `for ${admission.student_name} (${admission.class_applied}).` +
    (note ? ` Note: ${note}` : "");

  const emailSubject = `Admission Update - ${admission.student_name}`;
  const emailHtml = `
    <p>Hello ${admission.parent_name},</p>
    <p>Your child's admission status is <strong>${status.toUpperCase()}</strong> for <strong>${admission.student_name}</strong> (${admission.class_applied}).</p>
    ${note ? `<p><strong>Note:</strong> ${note}</p>` : ""}
    <p>Thank you for choosing Excellence Academy.</p>
  `;

  console.log(`Processing admission status update for ${admission.student_name}`);
  console.log(`Email: ${admission.parent_email}, Phone: ${admission.parent_phone}`);
  
  try {
    const emailSent = await sendAdmissionEmail({
      to: admission.parent_email,
      subject: emailSubject,
      text: message,
      html: emailHtml
    });
    if (emailSent) {
      console.log("Email notification sent successfully");
    } else {
      console.log("Email not sent: SMTP not configured");
    }
  } catch (err) {
    console.error("Email send failed:", err.message);
  }

  try {
    const smsSent = await sendAdmissionSms({ to: admission.parent_phone, message });
    if (smsSent) {
      console.log("SMS notification sent successfully");
    } else {
      console.log("SMS not sent: Check configuration");
    }
  } catch (err) {
    console.error("SMS send error:", err.message);
  }

  res.redirect("/dashboard/admissions");
});

app.get("/dashboard/students", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      return res.status(403).render("forbidden");
    }
    const [students, teachers] = await Promise.all([
      req.session.user.role === "teacher" && teacherClass
        ? dbAll("SELECT * FROM students WHERE class_name = ? ORDER BY id DESC", [teacherClass])
        : dbAll("SELECT * FROM students ORDER BY id DESC"),
      dbAll("SELECT name, class_name FROM teachers WHERE class_name IS NOT NULL AND class_name <> ''")
    ]);
    const classTeachers = teachers.reduce((acc, teacher) => {
      if (!acc[teacher.class_name]) acc[teacher.class_name] = [];
      acc[teacher.class_name].push(teacher.name);
      return acc;
    }, {});
    res.render("students", {
      students,
      classOptions: req.session.user.role === "teacher" && teacherClass ? [teacherClass] : CLASS_OPTIONS,
      classTeachers
    });
  } catch (err) {
    res.status(500).send("Failed to load students");
  }
});

app.get("/dashboard/classes", requireRole("owner"), async (req, res) => {
  try {
    const existing = await dbGet("SELECT COUNT(*) as count FROM classes");
    if (existing.count === 0) {
      for (const className of CLASS_OPTIONS) {
        await dbRun(
          "INSERT INTO classes (name, capacity, class_teacher_id, created_at) VALUES (?, ?, ?, ?)",
          [className, 30, null, new Date().toISOString()]
        );
      }
    }
    const [classes, teachers] = await Promise.all([
      dbAll(
        `SELECT classes.*, teachers.name as teacher_name
         FROM classes
         LEFT JOIN teachers ON teachers.id = classes.class_teacher_id
         ORDER BY classes.name`
      ),
      dbAll("SELECT id, name FROM teachers ORDER BY name")
    ]);
    res.render("classes", { classes, teachers, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load classes");
  }
});

app.get("/teacher", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      // Teacher not assigned to a class yet - show empty state
      return res.render("teacher", {
        students: [],
        assessments: [],
        classOptions: [],
        notAssigned: true
      });
    }
    const [students, assessments] = await Promise.all([
      req.session.user.role === "teacher" && teacherClass
        ? dbAll("SELECT id, first_name, last_name, class_name FROM students WHERE class_name = ? ORDER BY first_name", [teacherClass])
        : dbAll("SELECT id, first_name, last_name, class_name FROM students ORDER BY first_name"),
      dbAll(
        `SELECT assessments.*, students.first_name, students.last_name
         FROM assessments
         JOIN students ON students.id = assessments.student_id
         ${req.session.user.role === "teacher" && teacherClass ? "WHERE assessments.class_name = ?" : ""}
         ORDER BY assessments.id DESC LIMIT 100`,
        req.session.user.role === "teacher" && teacherClass ? [teacherClass] : []
      )
    ]);
    res.render("teacher", {
      students,
      assessments,
      classOptions: req.session.user.role === "teacher" && teacherClass ? [teacherClass] : CLASS_OPTIONS,
      notAssigned: false
    });
  } catch (err) {
    res.status(500).send("Failed to load teacher workspace");
  }
});

app.post("/teacher/assessments", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { student_id, class_name, term, session, subject, assessment_type, score } = req.body;
  if (!student_id || !class_name || !term || !session || !subject || !assessment_type || !score) {
    return res.status(400).send("Missing assessment fields");
  }
  if (req.session.user.role === "teacher") {
    const teacherClass = await getTeacherClass(req.session.user);
    if (teacherClass && class_name !== teacherClass) {
      return res.status(403).render("forbidden");
    }
  }
  await dbRun(
    `INSERT INTO assessments (student_id, class_name, term, session, subject, assessment_type, score, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      student_id,
      class_name,
      term.trim(),
      session.trim(),
      subject.trim(),
      assessment_type.trim(),
      Number(score),
      new Date().toISOString()
    ]
  );
  res.redirect("/teacher");
});

app.post("/dashboard/classes", requireRole("owner"), async (req, res) => {
  const { class_id, capacity, class_teacher_id } = req.body;
  if (!class_id || !capacity) {
    return res.status(400).send("Missing class fields");
  }
  const classRow = await dbGet("SELECT name FROM classes WHERE id = ?", [class_id]);
  await dbRun(
    "UPDATE classes SET capacity = ?, class_teacher_id = ? WHERE id = ?",
    [Number(capacity), class_teacher_id || null, class_id]
  );
  if (classRow && classRow.name) {
    await dbRun("UPDATE teachers SET class_name = NULL WHERE class_name = ?", [classRow.name]);
    if (class_teacher_id) {
      await dbRun("UPDATE teachers SET class_name = ? WHERE id = ?", [classRow.name, class_teacher_id]);
    }
  }
  res.redirect("/dashboard/classes");
});

app.post("/dashboard/students", requireRole("owner", "admin", "teacher"), async (req, res) => {
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

app.post("/dashboard/students/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM students WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/students");
});

app.get("/dashboard/teachers", requireRole("owner", "admin"), async (req, res) => {
  try {
    const teachers = await dbAll("SELECT * FROM teachers ORDER BY id DESC");
    res.render("teachers", { teachers, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load teachers");
  }
});

app.post("/dashboard/teachers", requireRole("owner", "admin"), async (req, res) => {
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

app.post("/dashboard/teachers/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM teachers WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/teachers");
});

app.get("/dashboard/timetable", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      return res.status(403).render("forbidden");
    }
    const [timetables, teachers] = await Promise.all([
      req.session.user.role === "teacher" && teacherClass
        ? dbAll("SELECT * FROM timetables WHERE class_name = ? ORDER BY day, period", [teacherClass])
        : dbAll("SELECT * FROM timetables ORDER BY class_name, day, period"),
      dbAll("SELECT name FROM teachers ORDER BY name")
    ]);
    res.render("timetable", {
      timetables,
      classOptions: req.session.user.role === "teacher" && teacherClass ? [teacherClass] : CLASS_OPTIONS,
      teachers
    });
  } catch (err) {
    res.status(500).send("Failed to load timetable");
  }
});

app.post("/dashboard/timetable", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { class_name, day, period, subject, teacher_name } = req.body;
  const teacherClass = await getTeacherClass(req.session.user);
  const finalClass = req.session.user.role === "teacher" && teacherClass ? teacherClass : class_name;
  if (!finalClass || !day || !period || !subject) {
    return res.status(400).send("Missing timetable fields");
  }
  await dbRun(
    `INSERT INTO timetables (class_name, day, period, subject, teacher_name, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [finalClass, day, period.trim(), subject.trim(), teacher_name || "", new Date().toISOString()]
  );
  res.redirect("/dashboard/timetable");
});

app.post("/dashboard/timetable/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM timetables WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/timetable");
});

app.get("/dashboard/attendance/students", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().slice(0, 10);
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      return res.status(403).render("forbidden");
    }
    const [students, records] = await Promise.all([
      req.session.user.role === "teacher" && teacherClass
        ? dbAll(
            "SELECT id, first_name, last_name, class_name FROM students WHERE class_name = ? ORDER BY first_name",
            [teacherClass]
          )
        : dbAll("SELECT id, first_name, last_name, class_name FROM students ORDER BY first_name"),
      dbAll(
        `SELECT attendance_students.*, students.first_name, students.last_name
         FROM attendance_students
         JOIN students ON students.id = attendance_students.student_id
         WHERE attendance_date = ?
         ${req.session.user.role === "teacher" && teacherClass ? "AND attendance_students.class_name = ?" : ""}
         ORDER BY students.first_name`,
        req.session.user.role === "teacher" && teacherClass ? [date, teacherClass] : [date]
      )
    ]);
    res.render("attendance-students", {
      students,
      records,
      date,
      classOptions: req.session.user.role === "teacher" && teacherClass ? [teacherClass] : CLASS_OPTIONS
    });
  } catch (err) {
    res.status(500).send("Failed to load student attendance");
  }
});

app.post("/dashboard/attendance/students", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { student_id, class_name, attendance_date, status } = req.body;
  if (!student_id || !class_name || !attendance_date || !status) {
    return res.status(400).send("Missing attendance fields");
  }
  const teacherClass = await getTeacherClass(req.session.user);
  if (req.session.user.role === "teacher" && teacherClass && class_name !== teacherClass) {
    return res.status(403).render("forbidden");
  }
  await dbRun(
    `INSERT INTO attendance_students (student_id, class_name, attendance_date, status, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [student_id, class_name, attendance_date, status, new Date().toISOString()]
  );
  res.redirect(`/dashboard/attendance/students?date=${attendance_date}`);
});

app.get("/dashboard/attendance/teachers", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().slice(0, 10);
    const [teachers, records] = await Promise.all([
      dbAll("SELECT id, name FROM teachers ORDER BY name"),
      dbAll(
        `SELECT attendance_teachers.*, teachers.name
         FROM attendance_teachers
         JOIN teachers ON teachers.id = attendance_teachers.teacher_id
         WHERE attendance_date = ?
         ORDER BY teachers.name`,
        [date]
      )
    ]);
    res.render("attendance-teachers", { teachers, records, date });
  } catch (err) {
    res.status(500).send("Failed to load teacher attendance");
  }
});

app.post("/dashboard/attendance/teachers", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { teacher_id, attendance_date, status } = req.body;
  if (!teacher_id || !attendance_date || !status) {
    return res.status(400).send("Missing attendance fields");
  }
  await dbRun(
    `INSERT INTO attendance_teachers (teacher_id, attendance_date, status, created_at)
     VALUES (?, ?, ?, ?)`,
    [teacher_id, attendance_date, status, new Date().toISOString()]
  );
  res.redirect(`/dashboard/attendance/teachers?date=${attendance_date}`);
});

app.get("/dashboard/finance", requireRole("owner", "admin", "accountant"), async (req, res) => {
  try {
    const records = await dbAll("SELECT * FROM finance_records ORDER BY occurred_on DESC, id DESC");
    res.render("finance", { records });
  } catch (err) {
    res.status(500).send("Failed to load finance records");
  }
});

app.post("/dashboard/finance", requireRole("owner", "admin", "accountant"), async (req, res) => {
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

app.post("/dashboard/finance/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM finance_records WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/finance");
});

app.get("/dashboard/fee-plans", requireRole("owner", "admin", "accountant"), async (req, res) => {
  try {
    const plans = await dbAll("SELECT * FROM fee_plans ORDER BY id DESC");
    res.render("fee-plans", { plans, classOptions: CLASS_OPTIONS });
  } catch (err) {
    res.status(500).send("Failed to load fee plans");
  }
});

app.post("/dashboard/fee-plans", requireRole("owner", "admin", "accountant"), async (req, res) => {
  const { class_name, term, session, amount, discount } = req.body;
  if (!class_name || !term || !session || !amount) {
    return res.status(400).send("Missing fee plan fields");
  }
  await dbRun(
    `INSERT INTO fee_plans (class_name, term, session, amount, discount, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [class_name, term.trim(), session.trim(), Number(amount), Number(discount || 0), new Date().toISOString()]
  );
  res.redirect("/dashboard/fee-plans");
});

app.post("/dashboard/fee-plans/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM fee_plans WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/fee-plans");
});

app.get("/dashboard/invoices", requireRole("owner", "admin", "accountant"), async (req, res) => {
  try {
    const [invoices, students, plans] = await Promise.all([
      dbAll(
        `SELECT invoices.*, students.first_name, students.last_name
         FROM invoices
         JOIN students ON students.id = invoices.student_id
         ORDER BY invoices.id DESC`
      ),
      dbAll("SELECT id, first_name, last_name, class_name FROM students ORDER BY first_name"),
      dbAll("SELECT * FROM fee_plans ORDER BY id DESC")
    ]);
    const today = new Date().toISOString().slice(0, 10);
    const arrears = invoices.filter(
      (invoice) => invoice.status !== "paid" && invoice.due_date < today
    );
    res.render("invoices", { invoices, students, plans, arrears, today });
  } catch (err) {
    res.status(500).send("Failed to load invoices");
  }
});

app.post("/dashboard/invoices", requireRole("owner", "admin", "accountant"), async (req, res) => {
  const { student_id, fee_plan_id, due_date } = req.body;
  if (!student_id || !fee_plan_id || !due_date) {
    return res.status(400).send("Missing invoice fields");
  }
  const plan = await dbGet("SELECT * FROM fee_plans WHERE id = ?", [fee_plan_id]);
  if (!plan) {
    return res.status(400).send("Invalid fee plan");
  }
  const total = Number(plan.amount);
  const discount = Number(plan.discount || 0);
  const amountPaid = 0;
  const status = "unpaid";
  await dbRun(
    `INSERT INTO invoices (student_id, class_name, term, session, fee_plan_id, total, discount, amount_paid, due_date, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      student_id,
      plan.class_name,
      plan.term,
      plan.session,
      plan.id,
      total,
      discount,
      amountPaid,
      due_date,
      status,
      new Date().toISOString()
    ]
  );
  res.redirect("/dashboard/invoices");
});

app.post("/dashboard/invoices/:id/pay", requireRole("owner", "admin", "accountant"), async (req, res) => {
  const { amount, method, paid_on } = req.body;
  if (!amount || !paid_on) {
    return res.status(400).send("Missing payment fields");
  }
  const invoice = await dbGet("SELECT * FROM invoices WHERE id = ?", [req.params.id]);
  if (!invoice) return res.status(404).send("Invoice not found");

  const newPaid = Number(invoice.amount_paid) + Number(amount);
  const balance = Number(invoice.total) - Number(invoice.discount) - newPaid;
  const status = balance <= 0 ? "paid" : newPaid > 0 ? "partial" : "unpaid";

  await dbRun(
    "UPDATE invoices SET amount_paid = ?, status = ? WHERE id = ?",
    [newPaid, status, req.params.id]
  );
  await dbRun(
    `INSERT INTO invoice_payments (invoice_id, amount, method, paid_on, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [req.params.id, Number(amount), method || "", paid_on, new Date().toISOString()]
  );
  res.redirect("/dashboard/invoices");
});

app.get("/dashboard/invoices/:id/receipt", requireRole("owner", "admin", "accountant"), async (req, res) => {
  const invoice = await dbGet(
    `SELECT invoices.*, students.first_name, students.last_name
     FROM invoices
     JOIN students ON students.id = invoices.student_id
     WHERE invoices.id = ?`,
    [req.params.id]
  );
  if (!invoice) return res.status(404).send("Invoice not found");
  const payments = await dbAll(
    "SELECT * FROM invoice_payments WHERE invoice_id = ? ORDER BY paid_on DESC",
    [req.params.id]
  );
  res.render("receipt", { invoice, payments });
});

app.post("/dashboard/invoices/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM invoice_payments WHERE invoice_id = ?", [req.params.id]);
  await dbRun("DELETE FROM invoices WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/invoices");
});

app.get("/dashboard/exams", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      return res.status(403).render("forbidden");
    }
    const exams = await dbAll(
      req.session.user.role === "teacher" && teacherClass
        ? "SELECT * FROM exams WHERE class_name = ? ORDER BY exam_date DESC, id DESC"
        : "SELECT * FROM exams ORDER BY exam_date DESC, id DESC",
      req.session.user.role === "teacher" && teacherClass ? [teacherClass] : []
    );
    res.render("exams", {
      exams,
      classOptions: req.session.user.role === "teacher" && teacherClass ? [teacherClass] : CLASS_OPTIONS
    });
  } catch (err) {
    res.status(500).send("Failed to load exams");
  }
});

app.post("/dashboard/exams", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { name, term, session, class_name, exam_date } = req.body;
  const teacherClass = await getTeacherClass(req.session.user);
  const finalClass = req.session.user.role === "teacher" && teacherClass ? teacherClass : class_name;
  if (!name || !term || !session || !finalClass || !exam_date) {
    return res.status(400).send("Missing exam fields");
  }
  await dbRun(
    `INSERT INTO exams (name, term, session, class_name, exam_date, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [name.trim(), term.trim(), session.trim(), finalClass.trim(), exam_date, new Date().toISOString()]
  );
  res.redirect("/dashboard/exams");
});

app.post("/dashboard/exams/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM exams WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/exams");
});

app.get("/dashboard/results", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    if (req.session.user.role === "teacher" && !teacherClass) {
      return res.status(403).render("forbidden");
    }
    const [results, students, exams] = await Promise.all([
      dbAll(
        `SELECT results.*, students.first_name, students.last_name, exams.name as exam_name
         FROM results
         JOIN students ON students.id = results.student_id
         JOIN exams ON exams.id = results.exam_id
         ${req.session.user.role === "teacher" && teacherClass ? "WHERE students.class_name = ?" : ""}
         ORDER BY results.id DESC`,
        req.session.user.role === "teacher" && teacherClass ? [teacherClass] : []
      ),
      req.session.user.role === "teacher" && teacherClass
        ? dbAll("SELECT id, first_name, last_name FROM students WHERE class_name = ? ORDER BY first_name", [teacherClass])
        : dbAll("SELECT id, first_name, last_name FROM students ORDER BY first_name"),
      req.session.user.role === "teacher" && teacherClass
        ? dbAll("SELECT id, name, class_name FROM exams WHERE class_name = ? ORDER BY exam_date DESC", [teacherClass])
        : dbAll("SELECT id, name, class_name FROM exams ORDER BY exam_date DESC")
    ]);
    res.render("results", { results, students, exams });
  } catch (err) {
    res.status(500).send("Failed to load results");
  }
});

app.get("/dashboard/report-cards", requireRole("owner", "admin", "teacher"), async (req, res) => {
  try {
    const teacherClass = await getTeacherClass(req.session.user);
    const students = await dbAll(
      req.session.user.role === "teacher" && teacherClass
        ? "SELECT id, first_name, last_name, class_name FROM students WHERE class_name = ? ORDER BY first_name"
        : "SELECT id, first_name, last_name, class_name FROM students ORDER BY first_name",
      req.session.user.role === "teacher" && teacherClass ? [teacherClass] : []
    );
    res.render("report-cards", { students });
  } catch (err) {
    res.status(500).send("Failed to load report cards");
  }
});

app.post("/dashboard/report-cards/generate", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { student_id, term, session } = req.body;
  if (!student_id || !term || !session) {
    return res.status(400).send("Missing report card fields");
  }
  const student = await dbGet("SELECT * FROM students WHERE id = ?", [student_id]);
  if (!student) return res.status(404).send("Student not found");

  if (req.session.user.role === "teacher") {
    const teacherClass = await getTeacherClass(req.session.user);
    if (!teacherClass || student.class_name !== teacherClass) {
      return res.status(403).render("forbidden");
    }
  }

  const assessments = await dbAll(
    `SELECT subject, assessment_type, score
     FROM assessments
     WHERE student_id = ? AND term = ? AND session = ?`,
    [student_id, term.trim(), session.trim()]
  );

  const examResults = await dbAll(
    `SELECT results.subject, results.score
     FROM results
     JOIN exams ON exams.id = results.exam_id
     WHERE results.student_id = ? AND exams.term = ? AND exams.session = ?`,
    [student_id, term.trim(), session.trim()]
  );

  const subjectMap = new Map();
  assessments.forEach((item) => {
    if (!subjectMap.has(item.subject)) {
      subjectMap.set(item.subject, { ca: 0, exam: 0 });
    }
    const current = subjectMap.get(item.subject);
    current.ca += Number(item.score);
  });
  examResults.forEach((item) => {
    if (!subjectMap.has(item.subject)) {
      subjectMap.set(item.subject, { ca: 0, exam: 0 });
    }
    const current = subjectMap.get(item.subject);
    current.exam = Number(item.score);
  });

  const rows = Array.from(subjectMap.entries()).map(([subject, scores]) => ({
    subject,
    ca: scores.ca,
    exam: scores.exam,
    total: scores.ca + scores.exam
  }));

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=report-card-${student.first_name}-${student.last_name}.pdf`
  );

  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(20).text("Excellence Academy", { align: "center" });
  doc.moveDown(0.5);
  doc.fontSize(14).text("Term Report Card", { align: "center" });
  doc.moveDown();

  doc.fontSize(12).text(`Student: ${student.first_name} ${student.last_name}`);
  doc.text(`Class: ${student.class_name}`);
  doc.text(`Term: ${term} | Session: ${session}`);
  doc.moveDown();

  doc.fontSize(12).text("Subject", 50, doc.y, { continued: true });
  doc.text("CA", 250, doc.y, { continued: true });
  doc.text("Exam", 330, doc.y, { continued: true });
  doc.text("Total", 420, doc.y);
  doc.moveDown(0.5);

  rows.forEach((row) => {
    doc.text(row.subject, 50, doc.y, { continued: true });
    doc.text(row.ca.toFixed(1), 250, doc.y, { continued: true });
    doc.text(row.exam.toFixed(1), 330, doc.y, { continued: true });
    doc.text(row.total.toFixed(1), 420, doc.y);
  });

  if (!rows.length) {
    doc.moveDown();
    doc.text("No assessment records found for this term.");
  }

  doc.end();
});

app.post("/dashboard/results", requireRole("owner", "admin", "teacher"), async (req, res) => {
  const { student_id, exam_id, subject, score, grade, remark } = req.body;
  if (!student_id || !exam_id || !subject || !score || !grade) {
    return res.status(400).send("Missing result fields");
  }
  if (req.session.user.role === "teacher") {
    const teacherClass = await getTeacherClass(req.session.user);
    const student = await dbGet("SELECT class_name FROM students WHERE id = ?", [student_id]);
    if (teacherClass && student && student.class_name !== teacherClass) {
      return res.status(403).render("forbidden");
    }
  }
  await dbRun(
    `INSERT INTO results (student_id, exam_id, subject, score, grade, remark, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [student_id, exam_id, subject.trim(), Number(score), grade.trim(), remark ? remark.trim() : "", new Date().toISOString()]
  );
  res.redirect("/dashboard/results");
});

app.post("/dashboard/results/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM results WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/results");
});

app.get("/dashboard/payments", requireRole("owner", "admin", "accountant"), async (req, res) => {
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

app.post("/dashboard/payments", requireRole("owner", "admin", "accountant"), async (req, res) => {
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

app.post("/dashboard/payments/:id/delete", requireRole("owner", "admin"), async (req, res) => {
  await dbRun("DELETE FROM student_fees WHERE id = ?", [req.params.id]);
  res.redirect("/dashboard/payments");
});

app.get("/dashboard/users", requireRole("owner"), async (req, res) => {
  try {
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    res.render("users", { users, roles: ROLE_OPTIONS, error: null, success: null });
  } catch (err) {
    res.status(500).send("Failed to load users");
  }
});

app.post("/dashboard/users", requireRole("owner"), async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    return res.status(400).render("users", {
      users,
      roles: ROLE_OPTIONS,
      error: "All fields are required.",
      success: null
    });
  }
  if (!ROLE_SET.has(role)) {
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    return res.status(400).render("users", {
      users,
      roles: ROLE_OPTIONS,
      error: "Invalid role selected.",
      success: null
    });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    await dbRun(
      "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
      [name.trim(), email.trim(), hash, role, new Date().toISOString()]
    );
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    return res.render("users", {
      users,
      roles: ROLE_OPTIONS,
      error: null,
      success: "User created successfully."
    });
  } catch (err) {
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    return res.status(400).render("users", {
      users,
      roles: ROLE_OPTIONS,
      error: "Failed to create user. Email may already exist.",
      success: null
    });
  }
});

app.post("/dashboard/users/:id/delete", requireRole("owner"), async (req, res) => {
  if (req.session.user && String(req.session.user.id) === String(req.params.id)) {
    const users = await dbAll("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC");
    return res.status(400).render("users", {
      users,
      roles: ROLE_OPTIONS,
      error: "You cannot delete your own account.",
      success: null
    });
  }
  await dbRun("DELETE FROM users WHERE id = ?", [req.params.id]);
  return res.redirect("/dashboard/users");
});

app.get("/api/inquiries", requireRole("owner", "admin"), (req, res) => {
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
