import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

// Create database client based on connection method
let db;
console.log("Setting up database connection...");

// Try connection string approach if DATABASE_URL is provided
if (process.env.DATABASE_URL) {
  console.log("Using connection string approach");
  db = new pg.Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false // This allows self-signed certificates
    },
    connectionTimeoutMillis: 60000,
    query_timeout: 60000
  });
} else {
  // Use individual parameters approach
  console.log("Using individual parameters approach");
  db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
    ssl: {
      rejectUnauthorized: false // This allows self-signed certificates
    },
    connectionTimeoutMillis: 60000,
    query_timeout: 60000
  });
}

// Connect with error handling
console.log("Attempting database connection to:", process.env.DATABASE_URL || process.env.PG_HOST);
let dbConnected = false;

db.connect()
  .then(() => {
    console.log("Database connected successfully!");
    dbConnected = true;
  })
  .catch(err => {
    console.error("Database connection error:", err);
    console.log("Application will run with limited functionality.");
    // Continue running the app even if database connection fails
  });

// Middleware to check database connection
const checkDbConnection = (req, res, next) => {
  if (!dbConnected && (req.path.includes('/register') || req.path.includes('/login') || req.path.includes('/secrets') || req.path.includes('/submit'))) {
    return res.status(503).send('Database is currently unavailable. Please try again later.');
  }
  next();
};

app.use(checkDbConnection);

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE email = $1", [req.user.email]);
      console.log(result)
      const secret = result.rows[0].secret;
      if (secret) {
        res.render("secrets.ejs", {secret: secret})
      } else {
          res.render("secrets.ejs", {secret: "You should submit a secret!"});
      }
    } catch (err) {
      console.log(err);
    }

    //TODO: Update this to pull in the user secret to render in secrets.ejs
  } else {
    res.redirect("/login");
  }
});

//SUBMIT GET ROUTE
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs")
  } else {
    res.redirect("/login")
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  if (!dbConnected) {
    return res.status(503).send('Database is currently unavailable. Please try again later.');
  }
  
  const email = req.body.username;
  const password = req.body.password;

  try {
    console.log("Attempting to register user:", email);
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      console.log("User already exists, redirecting to login");
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          return res.status(500).send("Error during registration. Please try again.");
        } else {
          try {
            const result = await db.query(
              "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
              [email, hash]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
              if (err) {
                console.error("Login error after registration:", err);
                return res.status(500).send("Error during login. Please try again.");
              }
              console.log("Registration successful, redirecting to secrets");
              res.redirect("/secrets");
            });
          } catch (dbErr) {
            console.error("Database error during user creation:", dbErr);
            res.status(500).send("Error saving user. Please try again.");
          }
        }
      });
    }
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).send("Registration error. Please try again later.");
  }
});

//Submit POST ROUTE
app.post("/submit", async (req, res) => {
  const secret = req.body.secret;

  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      secret,
      req.user.email,
    ]);
    res.redirect("/secrets")
  } catch (err) {
    console.log(err);
  }

});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL || "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.get("/db-test", async (req, res) => {
  // Show connection details (excluding password)
  const connectionInfo = {
    host: process.env.PG_HOST,
    user: process.env.PG_USER,
    database: process.env.PG_DATABASE,
    port: process.env.PG_PORT,
    ssl: true,
    connected: dbConnected
  };
  
  // If we're already connected, show that
  if (dbConnected) {
    try {
      const result = await db.query("SELECT NOW() as time, current_database() as database, version() as version");
      return res.send({
        status: "connected",
        message: "Database connected successfully!",
        connection: connectionInfo,
        serverInfo: result.rows[0]
      });
    } catch (err) {
      console.error("Error in db-test route:", err);
      return res.status(500).send({
        status: "error",
        message: "Error querying database",
        connection: connectionInfo,
        error: err.message
      });
    }
  }
  
  // If not connected, try to connect now
  try {
    console.log("Attempting test connection to database");
    // Create a new client just for this test
    const testClient = new pg.Client({
      user: process.env.PG_USER,
      host: process.env.PG_HOST,
      database: process.env.PG_DATABASE,
      password: process.env.PG_PASSWORD,
      port: process.env.PG_PORT,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 15000 // 15 seconds
    });
    
    await testClient.connect();
    const result = await testClient.query("SELECT NOW()");
    await testClient.end();
    
    return res.send({
      status: "test_success",
      message: "Test connection successful, but main connection failed. App may need restart.",
      connection: connectionInfo,
      serverTime: result.rows[0].now
    });
  } catch (err) {
    console.error("Test connection failed:", err);
    return res.status(500).send({
      status: "test_failed",
      message: "Both main and test connections failed",
      connection: connectionInfo,
      error: err.message,
      errorDetail: err.toString()
    });
  }
});

// Add a new advanced test route
app.get("/db-advanced-test", async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  let response = "DATABASE CONNECTION DIAGNOSTIC\n";
  response += "================================\n\n";
  
  // Log environment variables (excluding password)
  response += "ENVIRONMENT VARIABLES:\n";
  response += `PG_HOST: ${process.env.PG_HOST}\n`;
  response += `PG_USER: ${process.env.PG_USER}\n`;
  response += `PG_DATABASE: ${process.env.PG_DATABASE}\n`;
  response += `PG_PORT: ${process.env.PG_PORT}\n`;
  response += `SSL Enabled: Yes\n\n`;
  
  // Try a fresh connection
  response += "ATTEMPTING NEW CONNECTION:\n";
  try {
    const testClient = new pg.Client({
      user: process.env.PG_USER,
      host: process.env.PG_HOST,
      database: process.env.PG_DATABASE,
      password: process.env.PG_PASSWORD,
      port: process.env.PG_PORT,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 20000
    });
    
    response += "- Opening connection...\n";
    
    // Detailed event listeners for connection process
    testClient.on('error', (err) => {
      response += `- ERROR EVENT: ${err.message}\n`;
      console.error("Client error event:", err);
    });
    
    await testClient.connect();
    response += "- Connection successful!\n\n";
    
    response += "TESTING QUERIES:\n";
    // Test basic query
    const timeResult = await testClient.query("SELECT NOW() as time");
    response += `- SELECT NOW(): ${timeResult.rows[0].time}\n`;
    
    // Check if users table exists
    try {
      const tableResult = await testClient.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
      );
      response += `- Users table exists: ${tableResult.rows[0].exists}\n`;
      
      if (tableResult.rows[0].exists) {
        // Count users
        const countResult = await testClient.query("SELECT COUNT(*) FROM users");
        response += `- Number of users in table: ${countResult.rows[0].count}\n`;
      } else {
        response += "- Users table does not exist! This is a problem.\n";
      }
    } catch (e) {
      response += `- Error checking users table: ${e.message}\n`;
    }
    
    await testClient.end();
    response += "\nCONCLUSION: Database connection successful!";
    
  } catch (err) {
    response += `- Connection failed: ${err.message}\n`;
    response += `- Error details: ${err.toString()}\n\n`;
    response += "CONCLUSION: Could not connect to the database. Check configuration.";
  }
  
  res.send(response);
});

// Add this new test route after the other test routes
app.get("/connection-fix-test", async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  let response = "CONNECTION FIX TEST\n";
  response += "===================\n\n";
  
  // Log the connection details
  response += `Testing connection to: ${process.env.PG_HOST}\n`;
  response += `Database: ${process.env.PG_DATABASE}\n`;
  response += `User: ${process.env.PG_USER}\n\n`;
  
  // Try to ping the host first to check basic connectivity
  response += "CHECKING HOST CONNECTIVITY:\n";
  
  try {
    // DNS lookup test
    const dns = await import('dns');
    const { promises: dnsPromises } = dns;
    try {
      response += `- Resolving hostname ${process.env.PG_HOST}...\n`;
      const addresses = await dnsPromises.lookup(process.env.PG_HOST);
      response += `- DNS lookup successful: ${JSON.stringify(addresses)}\n`;
    } catch (dnsErr) {
      response += `- DNS lookup failed: ${dnsErr.message}\n`;
      response += "- This suggests the hostname may be incorrect or DNS issues\n\n";
    }
    
    // Now try with a longer timeout and different SSL approach
    response += "\nATTEMPTING CONNECTION WITH MODIFIED SETTINGS:\n";
    
    // Create a special test client with very long timeout
    const testClient = new pg.Client({
      user: process.env.PG_USER,
      host: process.env.PG_HOST,
      database: process.env.PG_DATABASE,
      password: process.env.PG_PASSWORD,
      port: process.env.PG_PORT,
      ssl: {
        rejectUnauthorized: false
      },
      connectionTimeoutMillis: 60000 // Very long 60 second timeout
    });
    
    response += "- Opening connection with 60s timeout and simplified SSL...\n";
    await testClient.connect();
    
    // If we get here, connection succeeded
    response += "- Connection successful!\n";
    
    // Test a simple query
    const result = await testClient.query("SELECT current_database()");
    response += `- Connected to database: ${result.rows[0].current_database}\n`;
    
    await testClient.end();
    response += "\nCONCLUSION: Connection successful with modified settings!";
    response += "\nPlease update your main database configuration with these settings.";
    
  } catch (err) {
    response += `- Connection still failed: ${err.message}\n\n`;
    
    response += "TROUBLESHOOTING RECOMMENDATIONS:\n";
    response += "1. Check if Supabase has IP restrictions enabled\n";
    response += "2. Verify your database password is correct\n";
    response += "3. Make sure your Supabase database is active (not paused)\n";
    response += "4. Try enabling 'Allow All IPv4' in Supabase temporarily\n";
    response += "5. Reset your database password in Supabase\n";
    
    response += "\nCONCLUSION: Connection issues persist. See above recommendations.";
  }
  
  res.send(response);
});

// Add this final test route
app.get("/direct-connect-test", async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  let response = "DIRECT CONNECTION TEST\n";
  response += "======================\n\n";
  
  // Try different connection approaches
  
  // Approach 1: Direct connection string with minimal parameters
  response += "APPROACH 1: DIRECT CONNECTION STRING\n";
  try {
    const connectionString = `postgresql://${process.env.PG_USER}:${encodeURIComponent(process.env.PG_PASSWORD)}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DATABASE}`;
    response += "Connection string created (password hidden)\n";
    
    const testClient1 = new pg.Client({
      connectionString: connectionString,
      ssl: {
        rejectUnauthorized: false
      }
    });
    
    response += "- Attempting connection...\n";
    await testClient1.connect();
    const result1 = await testClient1.query("SELECT NOW()");
    response += `- Success! Server time: ${result1.rows[0].now}\n`;
    await testClient1.end();
    
    response += "Approach 1: CONNECTION SUCCESSFUL!\n\n";
    return res.send(response + "CONNECTION SUCCESSFUL! Use a connection string approach.");
    
  } catch (err) {
    response += `- Error: ${err.message}\n\n`;
  }
  
  // Approach 2: No SSL configuration
  response += "APPROACH 2: SSL REJECT UNAUTHORIZED FALSE\n";
  try {
    const testClient2 = new pg.Client({
      user: process.env.PG_USER,
      host: process.env.PG_HOST,
      database: process.env.PG_DATABASE,
      password: process.env.PG_PASSWORD,
      port: process.env.PG_PORT,
      ssl: {
        rejectUnauthorized: false
      }
    });
    
    response += "- Attempting connection...\n";
    await testClient2.connect();
    const result2 = await testClient2.query("SELECT NOW()");
    response += `- Success! Server time: ${result2.rows[0].now}\n`;
    await testClient2.end();
    
    response += "Approach 2: CONNECTION SUCCESSFUL!\n\n";
    return res.send(response + "CONNECTION SUCCESSFUL! Try with no SSL configuration.");
    
  } catch (err) {
    response += `- Error: ${err.message}\n\n`;
  }
  
  // Approach 3: sslmode=require in connection string
  response += "APPROACH 3: CONNECTION STRING WITH SSLMODE\n";
  try {
    const connectionString = `postgresql://${process.env.PG_USER}:${encodeURIComponent(process.env.PG_PASSWORD)}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DATABASE}?sslmode=require`;
    
    const testClient3 = new pg.Client({
      connectionString: connectionString,
      ssl: {
        rejectUnauthorized: false
      }
    });
    
    response += "- Attempting connection...\n";
    await testClient3.connect();
    const result3 = await testClient3.query("SELECT NOW()");
    response += `- Success! Server time: ${result3.rows[0].now}\n`;
    await testClient3.end();
    
    response += "Approach 3: CONNECTION SUCCESSFUL!\n\n";
    return res.send(response + "CONNECTION SUCCESSFUL! Use sslmode=require in connection string.");
    
  } catch (err) {
    response += `- Error: ${err.message}\n\n`;
  }
  
  // If all approaches failed
  response += "All connection approaches failed.\n\n";
  response += "RECOMMENDATIONS:\n";
  response += "1. Double-check your database password - reset it in Supabase\n";
  response += "2. Verify your database is active and not in maintenance mode\n";
  response += "3. Try a direct connection from another client like pgAdmin\n";
  
  res.send(response);
});

// Add this new test route
app.get("/pooler-test", async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  let response = "TRANSACTION POOLER TEST\n";
  response += "=======================\n\n";
  
  response += "Testing direct connection to Transaction Pooler...\n\n";
  
  // Check if DATABASE_URL is set
  if (!process.env.DATABASE_URL) {
    return res.send(response + "ERROR: DATABASE_URL environment variable is not set!");
  }
  
  response += `DATABASE_URL is set (not showing for security)\n`;
  response += `Length of connection string: ${process.env.DATABASE_URL.length} characters\n\n`;
  
  try {
    // Create a client specifically for the pooler
    const poolerClient = new pg.Client({
      connectionString: process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false
      },
      connectionTimeoutMillis: 60000
    });
    
    response += "Connecting to Transaction Pooler...\n";
    await poolerClient.connect();
    
    response += "Connection successful!\n\n";
    response += "Testing simple query...\n";
    
    const result = await poolerClient.query("SELECT current_database(), current_user, version()");
    response += `Database: ${result.rows[0].current_database}\n`;
    response += `User: ${result.rows[0].current_user}\n`;
    response += `Version: ${result.rows[0].version}\n\n`;
    
    // Test if users table exists
    try {
      const tableCheck = await poolerClient.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
      );
      response += `Users table exists: ${tableCheck.rows[0].exists}\n\n`;
      
      if (!tableCheck.rows[0].exists) {
        response += "Creating users table...\n";
        await poolerClient.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(100),
            secret TEXT
          )
        `);
        response += "Users table created successfully!\n";
      }
    } catch (tableErr) {
      response += `Error checking/creating users table: ${tableErr.message}\n`;
    }
    
    await poolerClient.end();
    response += "CONCLUSION: Transaction Pooler connection works perfectly!";
    
  } catch (err) {
    response += `Connection failed: ${err.message}\n`;
    response += `Error details: ${err.toString()}\n\n`;
    
    if (err.message.includes('timeout')) {
      response += "This is likely due to network connectivity issues between Render and Supabase.\n\n";
      response += "RECOMMENDATIONS:\n";
      response += "1. Double-check the Transaction Pooler URL format\n";
      response += "2. Try the Session Pooler URL instead\n";
      response += "3. Consider using a different database provider like Railway.app or Neon.tech\n";
    }
    
    response += "CONCLUSION: Could not connect to Transaction Pooler.";
  }
  
  res.send(response);
});

// Add this session pooler test route
app.get("/session-pooler-test", async (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  let response = "SESSION POOLER TEST\n";
  response += "===================\n\n";
  
  // Hardcode the session pooler URL for testing
  // Replace the password with asterisks for security in the response
  const sessionPoolerUrl = `postgresql://postgres.giokiuvzpilfrbeoyxye:[PASSWORD]@aws-0-ap-south-1.pooler.supabase.com:5432/postgres`;
  response += `Testing connection with Session Pooler URL: ${sessionPoolerUrl}\n\n`;
  
  try {
    // Create the actual client with the real password
    const actualSessionPoolerUrl = `postgresql://postgres.giokiuvzpilfrbeoyxye:${process.env.PG_PASSWORD}@aws-0-ap-south-1.pooler.supabase.com:5432/postgres`;
    
    const sessionClient = new pg.Client({
      connectionString: actualSessionPoolerUrl,
      ssl: {
        rejectUnauthorized: false
      },
      connectionTimeoutMillis: 60000
    });
    
    response += "Connecting to Session Pooler...\n";
    await sessionClient.connect();
    
    response += "Connection successful!\n\n";
    response += "Testing simple query...\n";
    
    const result = await sessionClient.query("SELECT NOW() as time");
    response += `Current time: ${result.rows[0].time}\n\n`;
    
    // Test if users table exists and create it if not
    try {
      const tableCheck = await sessionClient.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
      );
      response += `Users table exists: ${tableCheck.rows[0].exists}\n\n`;
      
      if (!tableCheck.rows[0].exists) {
        response += "Creating users table...\n";
        await sessionClient.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(100),
            secret TEXT
          )
        `);
        response += "Users table created successfully!\n";
      }
    } catch (tableErr) {
      response += `Error checking/creating users table: ${tableErr.message}\n`;
    }
    
    await sessionClient.end();
    response += "CONCLUSION: Session Pooler connection works! Use this connection string instead.";
    
  } catch (err) {
    response += `Connection failed: ${err.message}\n`;
    response += `Error details: ${err.toString()}\n\n`;
    
    response += "CONCLUSION: Could not connect to Session Pooler either.";
    response += "\n\nRECOMMENDATIONS:\n";
    response += "1. Consider using a different database provider like Railway.app or Neon.tech\n";
    response += "2. Check if Supabase is experiencing outages\n";
    response += "3. Verify your database password is correct\n";
  }
  
  res.send(response);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
