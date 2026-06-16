// ============================================================
//  TASK MANAGER API — JWT Auth + Role-Based Access Control
//  Roles: "user" (own tasks only) | "admin" (all tasks)
// ============================================================

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// ─── SECRET KEY (in production, store this in .env) ──────────
const JWT_SECRET = "mySecretKey123!";
const TOKEN_EXPIRY = "1h"; // token expires in 1 hour

// ─── IN-MEMORY "DATABASE" ────────────────────────────────────
// Pre-seeded users (passwords are bcrypt hashed)
const users = [
  {
    id: "u1",
    name: "Alice",
    email: "alice@example.com",
    // plain password: "alice123"
    password: bcrypt.hashSync("alice123", 10),
    role: "user",
  },
  {
    id: "u2",
    name: "Bob",
    email: "bob@example.com",
    // plain password: "bob123"
    password: bcrypt.hashSync("bob123", 10),
    role: "user",
  },
  {
    id: "admin1",
    name: "Admin",
    email: "admin@example.com",
    // plain password: "admin123"
    password: bcrypt.hashSync("admin123", 10),
    role: "admin",
  },
];

// Pre-seeded tasks
let tasks = [
  { id: "t1", title: "Buy groceries",    status: "pending",   userId: "u1" },
  { id: "t2", title: "Read a book",      status: "done",      userId: "u1" },
  { id: "t3", title: "Fix bike",         status: "pending",   userId: "u2" },
  { id: "t4", title: "Write report",     status: "in-progress", userId: "u2" },
];

// ─── MIDDLEWARE: Verify JWT Token ─────────────────────────────
function authenticate(req, res, next) {
  // Expect header:  Authorization: Bearer <token>
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided. Please login first." });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, name, email, role }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token. Please login again." });
  }
}

// ─── MIDDLEWARE: Restrict to Admin only ──────────────────────
function authorizeAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied. Admins only." });
  }
  next();
}

// ════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════

// POST /auth/register — Register a new user
app.post("/auth/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "name, email, and password are required." });
  }

  const existing = users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ error: "Email already registered." });
  }

  // Only allow "user" role on self-registration (admin must be pre-seeded)
  const safeRole = role === "admin" ? "user" : (role || "user");

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: uuidv4(), name, email, password: hashedPassword, role: safeRole };
  users.push(newUser);

  res.status(201).json({
    message: "User registered successfully!",
    user: { id: newUser.id, name, email, role: safeRole },
  });
});

// POST /auth/login — Login and receive a JWT token
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required." });
  }

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  // Sign a token with user info (never include password!)
  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );

  res.json({
    message: `Welcome, ${user.name}! You are logged in as "${user.role}".`,
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

// ════════════════════════════════════════════════════════════
//  TASK ROUTES — USER (own tasks only)
// ════════════════════════════════════════════════════════════

// GET /tasks — User sees only THEIR tasks
app.get("/tasks", authenticate, (req, res) => {
  if (req.user.role === "admin") {
    // Redirect admin to the admin endpoint logic
    return res.status(403).json({
      error: "Admins should use GET /admin/tasks to see all tasks.",
    });
  }

  const myTasks = tasks.filter((t) => t.userId === req.user.id);
  res.json({
    message: `Showing tasks for ${req.user.name}`,
    count: myTasks.length,
    tasks: myTasks,
  });
});

// POST /tasks — User creates a new task (assigned to themselves)
app.post("/tasks", authenticate, (req, res) => {
  if (req.user.role === "admin") {
    return res.status(403).json({ error: "Admins cannot create personal tasks via this route." });
  }

  const { title, status } = req.body;
  if (!title) return res.status(400).json({ error: "title is required." });

  const newTask = {
    id: uuidv4(),
    title,
    status: status || "pending",
    userId: req.user.id,
  };
  tasks.push(newTask);

  res.status(201).json({ message: "Task created!", task: newTask });
});

// PUT /tasks/:id — User updates their OWN task only
app.put("/tasks/:id", authenticate, (req, res) => {
  const task = tasks.find((t) => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found." });

  // Users can only edit their own tasks
  if (req.user.role !== "admin" && task.userId !== req.user.id) {
    return res.status(403).json({ error: "You can only edit your own tasks." });
  }

  const { title, status } = req.body;
  if (title) task.title = title;
  if (status) task.status = status;

  res.json({ message: "Task updated!", task });
});

// DELETE /tasks/:id — User deletes their OWN task only
app.delete("/tasks/:id", authenticate, (req, res) => {
  const taskIndex = tasks.findIndex((t) => t.id === req.params.id);
  if (taskIndex === -1) return res.status(404).json({ error: "Task not found." });

  const task = tasks[taskIndex];

  // Users can only delete their own tasks
  if (req.user.role !== "admin" && task.userId !== req.user.id) {
    return res.status(403).json({ error: "You can only delete your own tasks." });
  }

  tasks.splice(taskIndex, 1);
  res.json({ message: "Task deleted successfully!" });
});

// ════════════════════════════════════════════════════════════
//  ADMIN ROUTES — all protected by authenticate + authorizeAdmin
// ════════════════════════════════════════════════════════════

// GET /admin/tasks — Admin sees ALL tasks from ALL users
app.get("/admin/tasks", authenticate, authorizeAdmin, (req, res) => {
  res.json({
    message: "Admin view: All tasks",
    count: tasks.length,
    tasks,
  });
});

// GET /admin/users — Admin sees all registered users (no passwords)
app.get("/admin/users", authenticate, authorizeAdmin, (req, res) => {
  const safeUsers = users.map(({ password, ...rest }) => rest);
  res.json({ count: safeUsers.length, users: safeUsers });
});

// DELETE /admin/tasks/:id — Admin can delete ANY task
app.delete("/admin/tasks/:id", authenticate, authorizeAdmin, (req, res) => {
  const taskIndex = tasks.findIndex((t) => t.id === req.params.id);
  if (taskIndex === -1) return res.status(404).json({ error: "Task not found." });

  tasks.splice(taskIndex, 1);
  res.json({ message: "Task deleted by admin." });
});

// PUT /admin/tasks/:id — Admin can update ANY task
app.put("/admin/tasks/:id", authenticate, authorizeAdmin, (req, res) => {
  const task = tasks.find((t) => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found." });

  const { title, status } = req.body;
  if (title) task.title = title;
  if (status) task.status = status;

  res.json({ message: "Task updated by admin.", task });
});

// ─── START SERVER ─────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n✅ Task Manager API running on http://localhost:${PORT}`);
  console.log("\n📋 Pre-seeded accounts:");
  console.log("   👤 User:  alice@example.com / alice123");
  console.log("   👤 User:  bob@example.com   / bob123");
  console.log("   🔑 Admin: admin@example.com  / admin123\n");
});