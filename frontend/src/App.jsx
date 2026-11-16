import { useState } from "react";
import "./App.css";

const API_URL = "http://localhost:5000/api/auth";
const SCAN_URL = "http://localhost:5000/api/scan";

const labelStyle = {
  display: "block",
  color: "#cbd5e1",
  fontSize: "13px",
  fontWeight: "600",
  marginBottom: "9px",
};

const inputStyle = {
  width: "100%",
  boxSizing: "border-box",
  padding: "14px 15px",
  borderRadius: "9px",
  border: "1px solid #263957",
  background: "#101e34",
  color: "#f1f5f9",
  fontSize: "14px",
  outline: "none"
};

const primaryButton = {
  border: "none",
  borderRadius: "9px",
  background: "linear-gradient(100deg, #2563eb, #3b82f6)",
  color: "#ffffff",
  fontSize: "13px",
  fontWeight: "700",
  padding: "12px 19px",
  cursor: "pointer",
};

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [indicator, setIndicator] = useState("");

  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("user") || "null");
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(
    localStorage.getItem("token")
  );

  const [isSignup, setIsSignup] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");

  const [history, setHistory] = useState([]);
  const [watchlist, setWatchlist] = useState([]);

  // AUTHENTICATION

  const handleAuth = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const endpoint = isSignup ? "signup" : "login";

      const response = await fetch(`${API_URL}/${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(
          isSignup
            ? { name, email, password }
            : { email, password }
        ),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Authentication failed");
      }

      if (!data.token || !data.user) {
        throw new Error("Invalid response received from server");
      }

      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));

      setToken(data.token);
      setUser(data.user);
      setError("");
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  // LOGOUT

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");

    setToken(null);
    setUser(null);
    setActivePage("Dashboard");
    setScanResult(null);
    setIndicator("");
  };

  // IOC SCANNER

  const handleScan = async (e) => {
    if (e) e.preventDefault();

    if (!indicator.trim()) {
      setScanError("Please enter an IP, domain, URL or file hash.");
      return;
    }

    setScanLoading(true);
    setScanError("");
    setScanResult(null);

    try {
      const response = await fetch(SCAN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          indicator: indicator.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "IOC analysis failed");
      }

      setScanResult(data);

      const newRecord = {
        ...data,
        indicator: data.indicator || indicator.trim(),
        scannedAt: new Date().toLocaleString(),
      };

      setHistory((previous) => [newRecord, ...previous]);
    } catch (err) {
      setScanError(err.message || "Unable to analyze indicator");
    } finally {
      setScanLoading(false);
    }
  };

  // WATCHLIST

  const addToWatchlist = (item) => {
    const value = item?.indicator;

    if (!value) return;

    setWatchlist((previous) => {
      if (previous.some((entry) => entry.indicator === value)) {
        return previous;
      }

      return [...previous, item];
    });
  };

  const removeFromWatchlist = (value) => {
    setWatchlist((previous) =>
      previous.filter((item) => item.indicator !== value)
    );
  };

  // EXPORT REPORT

  const exportReport = () => {
    if (history.length === 0) {
      alert("No investigation records available to export.");
      return;
    }

    const rows = [
      ["Indicator", "Type", "Severity", "Risk Score", "Scanned At"],
      ...history.map((item) => [
        item.indicator || "",
        item.type || "",
        item.severity || "",
        item.riskScore ?? "",
        item.scannedAt || "",
      ]),
    ];

    const csv = rows
      .map((row) =>
        row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(",")
      )
      .join("\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "ThreatForge-Investigation-Report.csv";
    link.click();

    URL.revokeObjectURL(url);
  };

  const menuItems = [
    { name: "Dashboard", icon: "▦" },
    { name: "IOC Scanner", icon: "⌕" },
    { name: "Investigation History", icon: "◷" },
    { name: "Watchlist", icon: "☆" },
    { name: "Reports", icon: "▤" },
  ];

  const maliciousCount = history.filter(
    (item) => item.severity?.toLowerCase() === "malicious"
  ).length;

  const suspiciousCount = history.filter(
    (item) => item.severity?.toLowerCase() === "suspicious"
  ).length;

  // LOGIN / SIGNUP PAGE

  if (!token) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "grid",
          gridTemplateColumns: "1.1fr 0.9fr",
          background: "#080f20",
          fontFamily: "Inter, sans-serif",
          color: "#e2e8f0",
        }}
      >
        {/* LEFT COLUMN */}

        <div
          style={{
            position: "relative",
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            padding: "55px 65px",
            background:
              "linear-gradient(145deg, #102c62 0%, #0c1d42 48%, #080f20 100%)",
            borderRight: "1px solid #1e3a65",
          }}
        >
          <div
            style={{
              position: "absolute",
              width: "450px",
              height: "450px",
              borderRadius: "50%",
              background: "rgba(37, 99, 235, 0.16)",
              filter: "blur(90px)",
              top: "20%",
              left: "15%",
            }}
          />

          <div
            style={{
              position: "relative",
              zIndex: 1,
              display: "flex",
              alignItems: "center",
              gap: "13px",
            }}
          >
            <div
              style={{
                width: "43px",
                height: "43px",
                borderRadius: "12px",
                background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "23px",
                fontWeight: "800",
                color: "white",
                boxShadow: "0 5px 25px rgba(37, 99, 235, 0.35)",
              }}
            >
              T
            </div>

            <span
              style={{
                fontSize: "23px",
                fontWeight: "800",
                letterSpacing: "-0.7px",
                color: "#ffffff",
              }}
            >
              ThreatForge
            </span>
          </div>

          <div
            style={{
              position: "relative",
              zIndex: 1,
              maxWidth: "520px",
            }}
          >
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "9px",
                padding: "9px 15px",
                border: "1px solid rgba(96, 165, 250, 0.3)",
                borderRadius: "30px",
                background: "rgba(30, 64, 175, 0.18)",
                color: "#93c5fd",
                fontSize: "12px",
                fontWeight: "600",
                letterSpacing: "1px",
                marginBottom: "28px",
              }}
            >
              <span
                style={{
                  width: "7px",
                  height: "7px",
                  borderRadius: "50%",
                  background: "#60a5fa",
                }}
              />
              CYBER THREAT INTELLIGENCE
            </div>

            <h1
              style={{
                fontSize: "clamp(38px, 4vw, 54px)",
                lineHeight: "1.15",
                fontWeight: "800",
                letterSpacing: "-2px",
                margin: "0 0 22px",
                color: "#ffffff",
              }}
            >
              Stay Ahead of
              <br />
              <span style={{ color: "#60a5fa" }}>
                Cyber Threats.
              </span>
            </h1>

            <p
              style={{
                fontSize: "15px",
                lineHeight: "1.9",
                color: "#a9bad5",
                maxWidth: "430px",
                margin: 0,
              }}
            >
              Investigate suspicious indicators, analyze potential
              threats, and manage security intelligence from one
              centralized platform.
            </p>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "19px",
                marginTop: "42px",
              }}
            >
              {[
                "IOC Investigation and Analysis",
                "Threat Intelligence Monitoring",
                "Centralized Security Dashboard",
              ].map((item, index) => (
                <div
                  key={index}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "13px",
                    color: "#dbeafe",
                    fontSize: "14px",
                  }}
                >
                  <span
                    style={{
                      width: "23px",
                      height: "23px",
                      borderRadius: "7px",
                      background: "rgba(59, 130, 246, 0.2)",
                      border: "1px solid rgba(96, 165, 250, 0.35)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "#60a5fa",
                      fontSize: "13px",
                    }}
                  >
                    ✓
                  </span>
                  {item}
                </div>
              ))}
            </div>
          </div>

          <div
            style={{
              position: "relative",
              zIndex: 1,
              color: "#7186a8",
              fontSize: "12px",
            }}
          >
            © 2026 ThreatForge. Cyber Intelligence Platform.
          </div>
        </div>

        {/* RIGHT COLUMN */}

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px",
            background: "#0b1426",
          }}
        >
          <div style={{ width: "100%", maxWidth: "390px" }}>
            <div style={{ marginBottom: "35px" }}>
              <p
                style={{
                  color: "#60a5fa",
                  fontSize: "12px",
                  fontWeight: "700",
                  letterSpacing: "2px",
                  marginBottom: "13px",
                }}
              >
                {isSignup ? "CREATE YOUR ACCOUNT" : "WELCOME BACK"}
              </p>

              <h2
                style={{
                  fontSize: "32px",
                  fontWeight: "750",
                  color: "#f8fafc",
                  letterSpacing: "-1px",
                  margin: "0 0 10px",
                }}
              >
                {isSignup ? "Get Started" : "Sign in"}
              </h2>

              <p
                style={{
                  color: "#8495b2",
                  fontSize: "14px",
                  margin: 0,
                }}
              >
                {isSignup
                  ? "Create your ThreatForge account to continue."
                  : "Enter your credentials to access your dashboard."}
              </p>
            </div>

            <form
              onSubmit={handleAuth}
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "19px",
              }}
            >
              {isSignup && (
                <div>
                  <label style={labelStyle}>Full Name</label>
                  <input
                    type="text"
                    placeholder="Enter your name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    style={inputStyle}
                  />
                </div>
              )}

              <div>
                <label style={labelStyle}>Email Address</label>
                <input
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  style={inputStyle}
                />
              </div>

              <div>
                <label style={labelStyle}>Password</label>
                <input
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  style={inputStyle}
                />
              </div>

              {error && (
                <div
                  style={{
                    padding: "12px 14px",
                    borderRadius: "9px",
                    background: "rgba(239, 68, 68, 0.1)",
                    border: "1px solid rgba(239, 68, 68, 0.25)",
                    color: "#fca5a5",
                    fontSize: "13px",
                  }}
                >
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                style={{
                  ...primaryButton,
                  width: "100%",
                  padding: "14px",
                  marginTop: "7px",
                  fontSize: "14px",
                  boxShadow: "0 7px 22px rgba(37, 99, 235, 0.22)",
                  opacity: loading ? 0.7 : 1,
                  cursor: loading ? "not-allowed" : "pointer",
                }}
              >
                {loading
                  ? "Please wait..."
                  : isSignup
                  ? "Create Account"
                  : "Sign In"}
              </button>
            </form>

            <div
              style={{
                textAlign: "center",
                marginTop: "27px",
                color: "#8495b2",
                fontSize: "13px",
              }}
            >
              {isSignup
                ? "Already have an account?"
                : "Don't have an account?"}

              <button
                type="button"
                onClick={() => {
                  setIsSignup(!isSignup);
                  setError("");
                }}
                style={{
                  background: "none",
                  border: "none",
                  color: "#60a5fa",
                  fontWeight: "700",
                  fontSize: "13px",
                  marginLeft: "6px",
                  cursor: "pointer",
                }}
              >
                {isSignup ? "Sign In" : "Create Account"}
              </button>
            </div>

            <div
              style={{
                borderTop: "1px solid #1e2c43",
                marginTop: "40px",
                paddingTop: "20px",
                textAlign: "center",
                color: "#52647f",
                fontSize: "11px",
                letterSpacing: "0.4px",
              }}
            >
              SECURE ACCESS · THREATFORGE
            </div>
          </div>
        </div>
      </div>
    );
  }

  // MAIN DASHBOARD

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        background: "#080f1e",
        color: "#e2e8f0",
        fontFamily: "Inter, sans-serif",
      }}
    >
      {/* SIDEBAR */}

      <aside
        style={{
          width: "245px",
          minWidth: "245px",
          minHeight: "100vh",
          background: "#0d192d",
          borderRight: "1px solid #1d304b",
          display: "flex",
          flexDirection: "column",
          padding: "28px 17px",
          boxSizing: "border-box",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "11px",
            padding: "0 8px",
            marginBottom: "48px",
          }}
        >
          <div
            style={{
              width: "39px",
              height: "39px",
              borderRadius: "11px",
              background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: "800",
              fontSize: "21px",
            }}
          >
            T
          </div>

          <span
            style={{
              fontSize: "20px",
              fontWeight: "800",
              color: "#ffffff",
            }}
          >
            ThreatForge
          </span>
        </div>

        <p
          style={{
            color: "#627895",
            fontSize: "10px",
            fontWeight: "700",
            letterSpacing: "1.7px",
            paddingLeft: "12px",
            marginBottom: "13px",
          }}
        >
          WORKSPACE
        </p>

        <nav style={{ display: "flex", flexDirection: "column", gap: "7px" }}>
          {menuItems.map((item) => (
            <button
              key={item.name}
              onClick={() => setActivePage(item.name)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "13px",
                width: "100%",
                padding: "13px 14px",
                border: "none",
                borderRadius: "9px",
                textAlign: "left",
                cursor: "pointer",
                background:
                  activePage === item.name
                    ? "linear-gradient(100deg, #173c78, #142c53)"
                    : "transparent",
                color: activePage === item.name ? "#93c5fd" : "#91a3bd",
                fontSize: "13px",
                fontWeight: activePage === item.name ? "700" : "500",
              }}
            >
              <span style={{ fontSize: "19px", width: "22px" }}>
                {item.icon}
              </span>
              {item.name}
            </button>
          ))}
        </nav>

        <div style={{ marginTop: "auto" }}>
          <div
            style={{
              padding: "15px",
              borderRadius: "11px",
              background: "#112542",
              border: "1px solid #203c62",
              marginBottom: "20px",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                color: "#93c5fd",
                fontSize: "12px",
                fontWeight: "700",
                marginBottom: "8px",
              }}
            >
              <span
                style={{
                  width: "7px",
                  height: "7px",
                  background: "#22c55e",
                  borderRadius: "50%",
                }}
              />
              SYSTEM STATUS
            </div>

            <p
              style={{
                color: "#91a3bd",
                fontSize: "11px",
                margin: 0,
                lineHeight: "1.6",
              }}
            >
              ThreatForge workspace is ready.
            </p>
          </div>

          <div
            style={{
              color: "#526783",
              fontSize: "11px",
              paddingLeft: "8px",
            }}
          >
            THREATFORGE v1.0.0
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}

      <main
        style={{
          flex: 1,
          minWidth: 0,
          padding: "30px 38px",
          boxSizing: "border-box",
        }}
      >
        {/* TOP BAR */}

        <header
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "20px",
            paddingBottom: "24px",
            borderBottom: "1px solid #1b2a40",
            marginBottom: "32px",
          }}
        >
          <div>
            <p
              style={{
                color: "#7186a5",
                fontSize: "12px",
                margin: "0 0 7px",
              }}
            >
              ThreatForge / {activePage}
            </p>

            <h2
              style={{
                color: "#f8fafc",
                fontSize: "23px",
                fontWeight: "750",
                margin: 0,
              }}
            >
              {activePage}
            </h2>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "13px",
            }}
          >
            <div
              style={{
                width: "37px",
                height: "37px",
                borderRadius: "50%",
                background: "#173b70",
                border: "1px solid #3263a2",
                color: "#bfdbfe",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: "700",
              }}
            >
              {(user?.name || user?.email || "U")
                .charAt(0)
                .toUpperCase()}
            </div>

            <div>
              <p
                style={{
                  color: "#e2e8f0",
                  fontSize: "12px",
                  fontWeight: "700",
                  margin: "0 0 4px",
                }}
              >
                {user?.name || "User"}
              </p>

              <p
                style={{
                  color: "#7186a5",
                  fontSize: "10px",
                  margin: 0,
                }}
              >
                Security Analyst
              </p>
            </div>

            <button
              onClick={handleLogout}
              style={{
                ...primaryButton,
                marginLeft: "12px",
                background: "#172a45",
                border: "1px solid #2a4264",
                color: "#bfdbfe",
              }}
            >
              Logout
            </button>
          </div>
        </header>

        {/* DASHBOARD PAGE */}

        {activePage === "Dashboard" && (
          <div>
            <section
              style={{
                padding: "32px",
                borderRadius: "15px",
                background:
                  "linear-gradient(110deg, #12346a 0%, #10264b 60%, #10203b 100%)",
                border: "1px solid #244779",
                marginBottom: "27px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "20px",
                flexWrap: "wrap",
              }}
            >
              <div>
                <p
                  style={{
                    color: "#93c5fd",
                    fontSize: "11px",
                    fontWeight: "700",
                    letterSpacing: "1.5px",
                    margin: "0 0 12px",
                  }}
                >
                  SECURITY OVERVIEW
                </p>

                <h1
                  style={{
                    fontSize: "27px",
                    color: "#ffffff",
                    margin: "0 0 10px",
                    letterSpacing: "-0.7px",
                  }}
                >
                  Welcome back, {user?.name?.split(" ")[0] || "Analyst"}
                </h1>

                <p
                  style={{
                    color: "#b1c7e7",
                    fontSize: "13px",
                    margin: 0,
                  }}
                >
                  Monitor, investigate and manage cyber threats.
                </p>
              </div>

              <button
                onClick={() => setActivePage("IOC Scanner")}
                style={{
                  ...primaryButton,
                  padding: "14px 21px",
                }}
              >
                + New Investigation
              </button>
            </section>

            {/* STATISTICS */}

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "17px",
                marginBottom: "27px",
              }}
            >
              {[
                {
                  title: "Total Investigations",
                  value: history.length,
                  icon: "⌕",
                  color: "#60a5fa",
                },
                {
                  title: "Malicious Findings",
                  value: maliciousCount,
                  icon: "⚠",
                  color: "#f87171",
                },
                {
                  title: "Suspicious Findings",
                  value: suspiciousCount,
                  icon: "◈",
                  color: "#fbbf24",
                },
                {
                  title: "Watchlist Items",
                  value: watchlist.length,
                  icon: "☆",
                  color: "#a78bfa",
                },
              ].map((stat) => (
                <div
                  key={stat.title}
                  style={{
                    background: "#101e32",
                    border: "1px solid #20334f",
                    borderRadius: "12px",
                    padding: "21px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "19px",
                    }}
                  >
                    <span
                      style={{
                        color: "#91a3bd",
                        fontSize: "12px",
                      }}
                    >
                      {stat.title}
                    </span>

                    <span
                      style={{
                        width: "34px",
                        height: "34px",
                        borderRadius: "9px",
                        background: "#172e50",
                        color: stat.color,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: "19px",
                      }}
                    >
                      {stat.icon}
                    </span>
                  </div>

                  <h2
                    style={{
                      color: "#f8fafc",
                      fontSize: "29px",
                      margin: 0,
                    }}
                  >
                    {stat.value}
                  </h2>
                </div>
              ))}
            </div>

            {/* QUICK INVESTIGATION */}

            <section
              style={{
                background: "#101e32",
                border: "1px solid #20334f",
                borderRadius: "13px",
                padding: "25px",
                marginBottom: "25px",
              }}
            >
              <div style={{ marginBottom: "20px" }}>
                <h3
                  style={{
                    color: "#f1f5f9",
                    fontSize: "16px",
                    margin: "0 0 7px",
                  }}
                >
                  Quick IOC Investigation
                </h3>

                <p
                  style={{
                    color: "#8195b2",
                    fontSize: "12px",
                    margin: 0,
                  }}
                >
                  Analyze an IP address, domain, URL or file hash.
                </p>
              </div>

              <form
                onSubmit={(e) => {
                  setActivePage("IOC Scanner");
                  handleScan(e);
                }}
                style={{
                  display: "flex",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                <input
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  placeholder="Enter IOC to investigate..."
                  style={{
                    ...inputStyle,
                    flex: 1,
                    minWidth: "200px",
                  }}
                />

                <button
                  type="submit"
                  disabled={scanLoading}
                  style={{
                    ...primaryButton,
                    minWidth: "140px",
                  }}
                >
                  {scanLoading ? "Analyzing..." : "Analyze IOC"}
                </button>
              </form>

              {scanError && (
                <p
                  style={{
                    color: "#fca5a5",
                    fontSize: "12px",
                    marginBottom: 0,
                  }}
                >
                  {scanError}
                </p>
              )}
            </section>

            {/* LOWER PANELS */}

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1.2fr 0.8fr",
                gap: "18px",
              }}
            >
              <section
                style={{
                  background: "#101e32",
                  border: "1px solid #20334f",
                  borderRadius: "13px",
                  padding: "23px",
                }}
              >
                <h3
                  style={{
                    fontSize: "15px",
                    color: "#f1f5f9",
                    margin: "0 0 19px",
                  }}
                >
                  Recent Investigations
                </h3>

                {history.length === 0 ? (
                  <div
                    style={{
                      padding: "30px 10px",
                      textAlign: "center",
                      color: "#7186a5",
                      fontSize: "13px",
                    }}
                  >
                    No investigations yet.
                    <br />
                    Start by scanning an IOC.
                  </div>
                ) : (
                  history.slice(0, 5).map((item, index) => (
                    <div
                      key={index}
                      style={{
                        padding: "13px 0",
                        borderBottom: "1px solid #20334f",
                        display: "flex",
                        justifyContent: "space-between",
                        gap: "10px",
                        flexWrap: "wrap",
                      }}
                    >
                      <div>
                        <p
                          style={{
                            color: "#dbeafe",
                            fontSize: "13px",
                            margin: "0 0 5px",
                          }}
                        >
                          {item.indicator}
                        </p>

                        <p
                          style={{
                            color: "#7186a5",
                            fontSize: "11px",
                            margin: 0,
                          }}
                        >
                          {item.scannedAt}
                        </p>
                      </div>

                      <span
                        style={{
                          color: "#93c5fd",
                          fontSize: "12px",
                        }}
                      >
                        {item.severity || "Analyzed"}
                      </span>
                    </div>
                  ))
                )}
              </section>

              <section
                style={{
                  background: "#101e32",
                  border: "1px solid #20334f",
                  borderRadius: "13px",
                  padding: "23px",
                }}
              >
                <h3
                  style={{
                    fontSize: "15px",
                    color: "#f1f5f9",
                    margin: "0 0 19px",
                  }}
                >
                  Platform Overview
                </h3>

                {[
                  ["IOC Analysis", "Available"],
                  ["Threat Monitoring", "Available"],
                  ["Investigation History", "Active"],
                  ["Watchlist", "Active"],
                ].map(([title, status]) => (
                  <div
                    key={title}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      padding: "14px 0",
                      borderBottom: "1px solid #20334f",
                      gap: "10px",
                    }}
                  >
                    <span
                      style={{
                        color: "#9aabc2",
                        fontSize: "12px",
                      }}
                    >
                      {title}
                    </span>

                    <span
                      style={{
                        color: "#60a5fa",
                        fontSize: "11px",
                        fontWeight: "600",
                      }}
                    >
                      {status}
                    </span>
                  </div>
                ))}
              </section>
            </div>
          </div>
        )}

        {/* IOC SCANNER PAGE */}

        {activePage === "IOC Scanner" && (
          <div>
            <section
              style={{
                background: "#101e32",
                border: "1px solid #20334f",
                borderRadius: "13px",
                padding: "28px",
                marginBottom: "22px",
              }}
            >
              <h3
                style={{
                  color: "#f1f5f9",
                  fontSize: "18px",
                  margin: "0 0 9px",
                }}
              >
                Indicator of Compromise Scanner
              </h3>

              <p
                style={{
                  color: "#8195b2",
                  fontSize: "13px",
                  margin: "0 0 24px",
                }}
              >
                Submit an indicator to analyze its threat intelligence.
              </p>

              <form
                onSubmit={handleScan}
                style={{
                  display: "flex",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                <input
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  placeholder="IP address / Domain / URL / File hash"
                  style={{
                    ...inputStyle,
                    flex: 1,
                    minWidth: "200px",
                  }}
                />

                <button
                  type="submit"
                  disabled={scanLoading}
                  style={{
                    ...primaryButton,
                    minWidth: "145px",
                  }}
                >
                  {scanLoading ? "Analyzing..." : "Analyze IOC"}
                </button>
              </form>

              <p
                style={{
                  color: "#647b9a",
                  fontSize: "11px",
                  marginTop: "15px",
                  marginBottom: 0,
                }}
              >
                Supported indicators: IPv4, domains, URLs and file hashes.
              </p>

              {scanError && (
                <p
                  style={{
                    color: "#fca5a5",
                    fontSize: "13px",
                    marginBottom: 0,
                  }}
                >
                  {scanError}
                </p>
              )}
            </section>

            {scanResult && (
              <section
                style={{
                  background: "#101e32",
                  border: "1px solid #20334f",
                  borderRadius: "13px",
                  padding: "27px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "15px",
                    flexWrap: "wrap",
                    marginBottom: "25px",
                  }}
                >
                  <div>
                    <p
                      style={{
                        color: "#7186a5",
                        fontSize: "11px",
                        margin: "0 0 8px",
                      }}
                    >
                      ANALYSIS RESULT
                    </p>

                    <h3
                      style={{
                        color: "#f1f5f9",
                        fontSize: "18px",
                        margin: 0,
                        wordBreak: "break-all",
                      }}
                    >
                      {scanResult.indicator || indicator}
                    </h3>
                  </div>

                  <button
                    onClick={() => addToWatchlist(scanResult)}
                    style={primaryButton}
                  >
                    + Add to Watchlist
                  </button>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
                    gap: "14px",
                  }}
                >
                  {[
                    ["Indicator Type", scanResult.type || "Unknown"],
                    ["Risk Score", `${scanResult.riskScore ?? "N/A"}/100`],
                    ["Severity", scanResult.severity || "Unknown"],
                  ].map(([title, value]) => (
                    <div
                      key={title}
                      style={{
                        background: "#142641",
                        border: "1px solid #294466",
                        borderRadius: "10px",
                        padding: "17px",
                      }}
                    >
                      <p
                        style={{
                          color: "#8298b7",
                          fontSize: "11px",
                          margin: "0 0 10px",
                        }}
                      >
                        {title}
                      </p>

                      <h3
                        style={{
                          color: "#dbeafe",
                          fontSize: "18px",
                          margin: 0,
                        }}
                      >
                        {value}
                      </h3>
                    </div>
                  ))}
                </div>

                <h4
                  style={{
                    color: "#dbeafe",
                    fontSize: "14px",
                    margin: "26px 0 15px",
                  }}
                >
                  Detection Statistics
                </h4>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
                    gap: "12px",
                  }}
                >
                  {[
                    ["Malicious", scanResult.statistics?.malicious ?? 0, "#f87171"],
                    ["Suspicious", scanResult.statistics?.suspicious ?? 0, "#fbbf24"],
                    ["Harmless", scanResult.statistics?.harmless ?? 0, "#4ade80"],
                    ["Undetected", scanResult.statistics?.undetected ?? 0, "#93c5fd"],
                  ].map(([title, value, color]) => (
                    <div
                      key={title}
                      style={{
                        background: "#0c192b",
                        border: "1px solid #20334f",
                        borderRadius: "9px",
                        padding: "16px",
                      }}
                    >
                      <p
                        style={{
                          color: "#8195b2",
                          fontSize: "11px",
                          margin: "0 0 8px",
                        }}
                      >
                        {title}
                      </p>

                      <h3
                        style={{
                          color,
                          fontSize: "23px",
                          margin: 0,
                        }}
                      >
                        {value}
                      </h3>
                    </div>
                  ))}
                </div>

                <div
                  style={{
                    marginTop: "22px",
                    padding: "16px",
                    background: "#142641",
                    borderRadius: "9px",
                    color: "#a8bad4",
                    fontSize: "12px",
                  }}
                >
                  <strong style={{ color: "#dbeafe" }}>
                    Reputation:
                  </strong>{" "}
                  {scanResult.reputation ?? "Not available"}
                  <br />
                  <br />
                  <strong style={{ color: "#dbeafe" }}>
                    Source:
                  </strong>{" "}
                  {scanResult.source || "Threat intelligence API"}
                </div>
              </section>
            )}
          </div>
        )}

        {/* INVESTIGATION HISTORY */}

        {activePage === "Investigation History" && (
          <section
            style={{
              background: "#101e32",
              border: "1px solid #20334f",
              borderRadius: "13px",
              padding: "26px",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "15px",
                flexWrap: "wrap",
                marginBottom: "22px",
              }}
            >
              <div>
                <h3
                  style={{
                    color: "#f1f5f9",
                    fontSize: "17px",
                    margin: "0 0 7px",
                  }}
                >
                  Investigation Records
                </h3>

                <p
                  style={{
                    color: "#8195b2",
                    fontSize: "12px",
                    margin: 0,
                  }}
                >
                  Your investigations during this session.
                </p>
              </div>

              <button onClick={exportReport} style={primaryButton}>
                Export CSV
              </button>
            </div>

            {history.length === 0 ? (
              <div
                style={{
                  textAlign: "center",
                  padding: "50px 15px",
                  color: "#7186a5",
                  fontSize: "13px",
                }}
              >
                No investigation records found.
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table
                  style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    textAlign: "left",
                  }}
                >
                  <thead>
                    <tr style={{ color: "#8298b7", fontSize: "11px" }}>
                      {["Indicator", "Type", "Severity", "Risk Score", "Date"].map(
                        (heading) => (
                          <th
                            key={heading}
                            style={{
                              padding: "13px",
                              borderBottom: "1px solid #29405e",
                            }}
                          >
                            {heading}
                          </th>
                        )
                      )}
                    </tr>
                  </thead>

                  <tbody>
                    {history.map((item, index) => (
                      <tr
                        key={index}
                        style={{
                          color: "#dbeafe",
                          fontSize: "12px",
                        }}
                      >
                        <td
                          style={{
                            padding: "15px 13px",
                            borderBottom: "1px solid #1d304b",
                          }}
                        >
                          {item.indicator}
                        </td>
                        <td
                          style={{
                            padding: "15px 13px",
                            borderBottom: "1px solid #1d304b",
                          }}
                        >
                          {item.type || "Unknown"}
                        </td>
                        <td
                          style={{
                            padding: "15px 13px",
                            borderBottom: "1px solid #1d304b",
                          }}
                        >
                          {item.severity || "Unknown"}
                        </td>
                        <td
                          style={{
                            padding: "15px 13px",
                            borderBottom: "1px solid #1d304b",
                          }}
                        >
                          {item.riskScore ?? "N/A"}
                        </td>
                        <td
                          style={{
                            padding: "15px 13px",
                            borderBottom: "1px solid #1d304b",
                          }}
                        >
                          {item.scannedAt}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {/* WATCHLIST */}

        {activePage === "Watchlist" && (
          <section
            style={{
              background: "#101e32",
              border: "1px solid #20334f",
              borderRadius: "13px",
              padding: "26px",
            }}
          >
            <h3
              style={{
                color: "#f1f5f9",
                fontSize: "17px",
                margin: "0 0 8px",
              }}
            >
              Threat Watchlist
            </h3>

            <p
              style={{
                color: "#8195b2",
                fontSize: "12px",
                margin: "0 0 24px",
              }}
            >
              Keep track of indicators that need further attention.
            </p>

            {watchlist.length === 0 ? (
              <div
                style={{
                  textAlign: "center",
                  padding: "50px 15px",
                  color: "#7186a5",
                  fontSize: "13px",
                }}
              >
                Your watchlist is currently empty.
                <br />
                Add an indicator from the IOC Scanner.
              </div>
            ) : (
              watchlist.map((item, index) => (
                <div
                  key={index}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "15px",
                    flexWrap: "wrap",
                    padding: "17px 0",
                    borderBottom: "1px solid #20334f",
                  }}
                >
                  <div>
                    <p
                      style={{
                        color: "#dbeafe",
                        fontSize: "13px",
                        margin: "0 0 6px",
                      }}
                    >
                      {item.indicator}
                    </p>

                    <p
                      style={{
                        color: "#8195b2",
                        fontSize: "11px",
                        margin: 0,
                      }}
                    >
                      {item.type || "Unknown"} · {item.severity || "Unknown"}
                    </p>
                  </div>

                  <button
                    onClick={() => removeFromWatchlist(item.indicator)}
                    style={{
                      ...primaryButton,
                      background: "#321e2a",
                      color: "#fca5a5",
                      border: "1px solid #633047",
                    }}
                  >
                    Remove
                  </button>
                </div>
              ))
            )}
          </section>
        )}

        {/* REPORTS */}

        {activePage === "Reports" && (
          <section
            style={{
              background: "#101e32",
              border: "1px solid #20334f",
              borderRadius: "13px",
              padding: "30px",
            }}
          >
            <h3
              style={{
                color: "#f1f5f9",
                fontSize: "18px",
                margin: "0 0 10px",
              }}
            >
              Investigation Reports
            </h3>

            <p
              style={{
                color: "#8195b2",
                fontSize: "13px",
                margin: "0 0 25px",
                lineHeight: "1.7",
              }}
            >
              Generate a CSV report containing the investigation
              records collected during your current session.
            </p>

            <div
              style={{
                background: "#142641",
                border: "1px solid #294466",
                borderRadius: "11px",
                padding: "22px",
                maxWidth: "450px",
                marginBottom: "23px",
              }}
            >
              <p
                style={{
                  color: "#93c5fd",
                  fontSize: "11px",
                  fontWeight: "700",
                  letterSpacing: "1px",
                  margin: "0 0 10px",
                }}
              >
                REPORT SUMMARY
              </p>

              <h2
                style={{
                  color: "#ffffff",
                  fontSize: "31px",
                  margin: "0 0 7px",
                }}
              >
                {history.length}
              </h2>

              <p
                style={{
                  color: "#8195b2",
                  fontSize: "12px",
                  margin: 0,
                }}
              >
                Total investigation records
              </p>
            </div>

            <button onClick={exportReport} style={primaryButton}>
              Download Investigation Report
            </button>
          </section>
        )}

        <footer
          style={{
            borderTop: "1px solid #1b2a40",
            marginTop: "38px",
            paddingTop: "20px",
            color: "#526783",
            fontSize: "11px",
            textAlign: "center",
          }}
        >
          ThreatForge © 2026 · Cyber Threat Intelligence Dashboard
        </footer>
      </main>
    </div>
  );
}

export default App;