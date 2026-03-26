import { useState, useRef } from "react";
import axios from "axios";

const API = process.env.REACT_APP_API_URL || "http://localhost:5000";

const RISK_COLORS = {
  critical: { bg: "#ff000018", border: "#ff4444", text: "#ff4444", badge: "#ff4444" },
  high:     { bg: "#ff660018", border: "#ff6600", text: "#ff6600", badge: "#ff6600" },
  medium:   { bg: "#ffaa0018", border: "#ffaa00", text: "#b87a00", badge: "#ffaa00" },
  low:      { bg: "#00ff8818", border: "#00cc66", text: "#00aa55", badge: "#00cc66" },
};

const TYPE_ICONS = {
  email: "✉", password: "🔑", api_key: "🗝", token: "🎫",
  stack_trace: "💥", brute_force: "🔨", hardcoded_secret: "🔒",
  debug_leak: "🐛", phone_number: "📞", sql_injection: "💉",
  destructive_query: "💣", select_all: "👁", password_in_chat: "🔑",
  social_engineering: "🎭", credit_card: "💳", default: "⚠",
};

const T = {
  dark: {
    root:         { background: "#0a0f16", color: "#d8e0ea" },
    header:       { background: "rgba(10,15,22,0.98)", borderBottom: "1px solid rgba(0,255,136,0.15)" },
    card:         { background: "rgba(16,24,38,0.75)", border: "1px solid rgba(0,255,136,0.18)" },
    textarea:     { background: "rgba(0,0,0,0.4)", color: "#d8e0ea", border: "1px solid rgba(0,255,136,0.22)" },
    btn:          { background: "linear-gradient(135deg,#00ff88,#00cc66)", color: "#000" },
    accent:       "#00ff88",
    accentFaint:  "rgba(0,255,136,0.12)",
    accentBorder: "rgba(0,255,136,0.35)",
    subText:      "#8a9ab0",
    mutedText:    "#536070",
    codeBg:       "rgba(0,0,0,0.3)",
    divider:      "rgba(0,255,136,0.12)",
    tabActive:    { background: "rgba(0,255,136,0.15)", border: "1px solid rgba(0,255,136,0.5)", color: "#00ff88" },
    tabInactive:  { background: "rgba(255,255,255,0.04)", border: "1px solid rgba(0,255,136,0.14)", color: "#536070" },
    grid:         "rgba(0,255,136,0.025)",
    // upload box hover colors (dark)
    uploadHoverBg:     "rgba(0,255,136,0.07)",
    uploadHoverBorder: "#00ff88",
    uploadHoverText:   "#00ff88",
  },
  light: {
    root:         { background: "#f5f0e8", color: "#2c1a0e" },
    header:       { background: "#fff8f0", borderBottom: "1px solid #e0c8a8" },
    card:         { background: "#fffcf8", border: "1px solid #e0c8a8" },
    textarea:     { background: "#fffdf9", color: "#2c1a0e", border: "1px solid #e0c8a8" },
    btn:          { background: "linear-gradient(135deg,#c0722a,#e0903a)", color: "#fff" },
    accent:       "#b86020",
    accentFaint:  "rgba(192,114,42,0.1)",
    accentBorder: "rgba(192,114,42,0.4)",
    subText:      "#6a4a2a",
    mutedText:    "#9a7a5a",
    codeBg:       "#f5ece0",
    divider:      "#e0c8a8",
    tabActive:    { background: "rgba(192,114,42,0.12)", border: "1px solid rgba(192,114,42,0.5)", color: "#b86020" },
    tabInactive:  { background: "#fdf5eb", border: "1px solid #e0c8a8", color: "#9a7a5a" },
    grid:         "rgba(192,114,42,0.04)",
    // upload box hover colors (light)
    uploadHoverBg:     "rgba(192,114,42,0.08)",
    uploadHoverBorder: "#c0722a",
    uploadHoverText:   "#b86020",
  },
};

export default function App() {
  const [inputType, setInputType]   = useState("log");
  const [content, setContent]       = useState("");
  const [file, setFile]             = useState(null);
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState(null);
  const [error, setError]           = useState(null);
  const [dragOver, setDragOver]     = useState(false);
  const [theme, setTheme]           = useState("dark");
  const [fileError, setFileError]   = useState(null);
  const [maskValues, setMaskValues] = useState(true);
  // FIX 2: track hover state for upload box
  const [uploadHover, setUploadHover] = useState(false);
  const fileRef = useRef();

  const t = T[theme];

  const inputTypes = [
    { value: "log",  label: "Log File" },
    { value: "text", label: "Text"     },
    { value: "sql",  label: "SQL"      },
    { value: "chat", label: "Chat"     },
  ];

  const handleFileChange = (f) => {
    setFileError(null);
    if (f && f.size > 50 * 1024 * 1024) { setFileError("File exceeds 50 MB limit"); return; }
    setFile(f); setContent("");
  };

  const handleAnalyze = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      let res;
      if (file) {
        const form = new FormData();
        form.append("file", file);
        form.append("options", JSON.stringify({ mask: maskValues, block_high_risk: false, log_analysis: true }));
        res = await axios.post(`${API}/analyze/file`, form);
      } else {
        res = await axios.post(`${API}/analyze`, {
          content, input_type: inputType,
          options: { mask: maskValues, block_high_risk: false, log_analysis: true },
        });
      }
      setResult(res.data);
    } catch (e) {
      setError(e.response?.data?.error || "Something went wrong. Is the backend running?");
    } finally { setLoading(false); }
  };

  const riskLevel = result?.risk_level || "low";
  const riskColor = RISK_COLORS[riskLevel] || RISK_COLORS.low;

  const getHighlightedLogs = () =>
    content.split("\n").slice(0, 100).map((line, idx) => {
      const lineNum = idx + 1;
      const finding = result?.findings.find(f => f.line === lineNum);
      return { lineNum, content: line, finding, riskColor: finding ? RISK_COLORS[finding.risk] : null };
    });

  const card = { ...t.card, borderRadius: 10, padding: 32 };
  const sectionLabel = { fontSize: 20, fontWeight: "bold", letterSpacing: 3, color: t.accent, textTransform: "uppercase" };

  // FIX 2: compute upload box border/bg based on hover OR dragOver
  const uploadActive = dragOver || uploadHover;
  const uploadBoxStyle = {
    border: `2px dashed ${uploadActive ? t.uploadHoverBorder : t.divider}`,
    borderRadius: 8,
    padding: "36px 24px",
    textAlign: "center",
    cursor: "pointer",
    marginBottom: 18,
    background: uploadActive ? t.uploadHoverBg : "transparent",
    // smooth scale + glow on hover
    transform: uploadActive ? "scale(1.012)" : "scale(1)",
    boxShadow: uploadActive ? `0 0 18px ${t.uploadHoverBorder}44` : "none",
    transition: "all 0.22s ease",
  };

  return (
    <div style={{ minHeight: "100vh", fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace", fontSize: 17, position: "relative", overflowX: "hidden", ...t.root }}>

      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: `linear-gradient(${t.grid} 1px,transparent 1px),linear-gradient(90deg,${t.grid} 1px,transparent 1px)`, backgroundSize: "48px 48px" }} />

      <header style={{ position: "sticky", top: 0, zIndex: 10, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "22px 44px", ...t.header }}>
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <span style={{ fontSize: 40 }}>🛡</span>
          <div>
            <div style={{ fontSize: 24, fontWeight: "bold", color: t.accent, letterSpacing: 2, lineHeight: 1.2 }}>AI Security Platform</div>
            <div style={{ fontSize: 15, color: t.subText, letterSpacing: 1, marginTop: 3 }}>Intelligent Log & Data Analysis</div>
          </div>
        </div>
        <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          style={{ padding: "10px 22px", background: t.accentFaint, border: `1px solid ${t.accentBorder}`, borderRadius: 24, color: t.accent, fontSize: 15, fontWeight: 700, cursor: "pointer", fontFamily: "inherit", letterSpacing: 1 }}>
          {theme === "dark" ? "🌙 Dark" : "☀️ Light"}
        </button>
      </header>

      <main style={{ position: "relative", zIndex: 1, maxWidth: 1200, margin: "0 auto", padding: "36px 32px", display: "flex", flexDirection: "column", gap: 28 }}>

        <section style={card}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28, gap: 12, flexWrap: "wrap" }}>
            <span style={sectionLabel}>Input Analyzer</span>
            <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
              {inputTypes.map(tp => (
                <button key={tp.value}
                  onClick={() => {
                    setInputType(tp.value);
                    setFile(null);
                    setResult(null);
                    setFileError(null);
                    // FIX 1: clear the text box when switching tabs
                    setContent("");
                    // reset file input so same file can be re-uploaded
                    if (fileRef.current) fileRef.current.value = "";
                  }}
                  style={{ padding: "10px 22px", borderRadius: 4, cursor: "pointer", fontSize: 18, fontWeight: 600, fontFamily: "inherit", transition: "all 0.15s", ...(inputType === tp.value ? t.tabActive : t.tabInactive) }}>
                  {tp.label}
                </button>
              ))}
            </div>
          </div>

          {/* FIX 2: upload box now has onMouseEnter/Leave for hover animation */}
          <div
            onClick={() => fileRef.current.click()}
            onMouseEnter={() => setUploadHover(true)}
            onMouseLeave={() => setUploadHover(false)}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { e.preventDefault(); setDragOver(false); handleFileChange(e.dataTransfer.files[0]); }}
            style={uploadBoxStyle}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".log,.txt,.pdf,.doc,.docx"
              style={{ display: "none" }}
              onChange={e => { handleFileChange(e.target.files[0]); e.target.value = ""; }}
            />
            {file ? (
              <div style={{ display: "flex", alignItems: "center", gap: 14, justifyContent: "center" }}>
                <span style={{ fontSize: 28 }}>📄</span>
                <span style={{ color: t.accent, fontWeight: 600, fontSize: 17 }}>{file.name}</span>
                <button
                  onClick={e => { e.stopPropagation(); setFile(null); setFileError(null); if (fileRef.current) fileRef.current.value = ""; }}
                  style={{ background: "rgba(255,68,68,0.15)", border: "1px solid #ff4444", color: "#ff4444", borderRadius: 4, padding: "4px 12px", cursor: "pointer", fontSize: 15, fontFamily: "inherit" }}>
                  ✕
                </button>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "center", color: uploadActive ? t.uploadHoverText : t.subText, transition: "color 0.22s" }}>
                <span style={{ fontSize: 36, opacity: uploadActive ? 0.9 : 0.5, transition: "opacity 0.22s", transform: uploadActive ? "translateY(-3px)" : "translateY(0)", display: "inline-block" }}>⬆</span>
                <span style={{ fontSize: 17 }}>Drop file here or click to upload</span>
                <span style={{ fontSize: 15, color: t.mutedText }}>.log · .txt · .pdf · .doc · .docx · max 10 MB</span>
              </div>
            )}
          </div>

          {fileError && <div style={{ padding: 16, marginBottom: 16, background: "rgba(255,68,68,0.12)", border: "1px solid #ff4444", borderRadius: 6, color: "#ff6666", fontSize: 16 }}>⚠ {fileError}</div>}

          {!file && (<>
            <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "18px 0" }}>
              <div style={{ flex: 1, height: 1, background: t.divider }} />
              <span style={{ fontSize: 13, color: t.mutedText, letterSpacing: 2 }}>OR PASTE CONTENT</span>
              <div style={{ flex: 1, height: 1, background: t.divider }} />
            </div>
            <textarea rows={9} value={content} onChange={e => setContent(e.target.value)}
              placeholder={
                inputType === "sql"  ? "SELECT * FROM users;\nDROP TABLE users;\n..." :
                inputType === "chat" ? "Hey my password is admin123\napi_key: sk-..." :
                                       "2026-03-10 10:00:01 INFO email=admin@company.com\npassword=admin123\napi_key=sk-prod-xyz..."
              }
              style={{ width: "100%", borderRadius: 6, padding: 18, fontSize: 16, resize: "vertical", outline: "none", lineHeight: 1.8, boxSizing: "border-box", fontFamily: "inherit", ...t.textarea }} />
          </>)}

          <div style={{ display: "flex", alignItems: "center", gap: 16, marginTop: 20 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer", fontSize: 15, color: t.subText, userSelect: "none", flexShrink: 0 }}>
              <div onClick={() => setMaskValues(!maskValues)} style={{ width: 44, height: 24, borderRadius: 12, position: "relative", cursor: "pointer", background: maskValues ? t.accent : t.divider, transition: "background 0.2s" }}>
                <div style={{ position: "absolute", top: 3, left: maskValues ? 22 : 3, width: 18, height: 18, borderRadius: "50%", background: "#fff", transition: "left 0.2s" }} />
              </div>
              Mask values
            </label>
            <button onClick={handleAnalyze} disabled={loading || (!content && !file)}
              style={{ flex: 1, padding: "16px 0", border: "none", borderRadius: 6, fontSize: 17, fontWeight: "bold", letterSpacing: 2, cursor: loading || (!content && !file) ? "not-allowed" : "pointer", opacity: loading || (!content && !file) ? 0.5 : 1, fontFamily: "inherit", transition: "all 0.2s", ...t.btn }}>
              {loading ? "⟳  Analyzing..." : "⚡  Analyze"}
            </button>
          </div>

          {error && <div style={{ marginTop: 16, padding: 16, background: "rgba(255,68,68,0.1)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: 6, color: "#ff6666", fontSize: 16 }}>⚠ {error}</div>}
        </section>

        {result && (<>
          <section style={{ ...card, display: "flex", justifyContent: "space-between", alignItems: "center", borderLeft: `5px solid ${riskColor.border}`, background: riskColor.bg, padding: "32px 36px" }}>
            <div style={{ flex: 1, paddingRight: 28 }}>
              <div style={{ fontSize: 26, fontWeight: "bold", letterSpacing: 2, color: riskColor.text, marginBottom: 12 }}>{result.risk_level.toUpperCase()} RISK</div>
              <div style={{ fontSize: 17, color: t.subText, lineHeight: 1.8 }}>{result.summary}</div>
            </div>
            <div style={{ textAlign: "center", flexShrink: 0 }}>
              <div style={{ fontSize: 64, fontWeight: "bold", color: riskColor.text, lineHeight: 1 }}>{result.risk_score}</div>
              <div style={{ fontSize: 13, letterSpacing: 2, color: t.mutedText, marginTop: 8 }}>SCORE</div>
            </div>
          </section>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16 }}>
            {[
              { label: "Total Findings", value: result.meta.total_findings },
              { label: "Critical", value: result.findings.filter(f => f.risk === "critical").length, color: "#ff4444" },
              { label: "High", value: result.findings.filter(f => f.risk === "high").length, color: "#ff6600" },
              { label: "Lines Scanned", value: result.meta.total_lines },
            ].map(s => (
              <div key={s.label} style={{ ...card, textAlign: "center", padding: 26 }}>
                <div style={{ fontSize: 40, fontWeight: "bold", color: s.color || t.accent }}>{s.value}</div>
                <div style={{ fontSize: 14, letterSpacing: 1, color: t.mutedText, marginTop: 8 }}>{s.label}</div>
              </div>
            ))}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 28, alignItems: "start" }}>
            <section style={card}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 22 }}>
                <span style={sectionLabel}>Findings</span>
                <span style={{ background: t.accentFaint, border: `1px solid ${t.accentBorder}`, color: t.accent, padding: "5px 14px", borderRadius: 4, fontSize: 15, fontWeight: "bold" }}>{result.findings.length}</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                {result.findings.map((f, i) => {
                  const rc = RISK_COLORS[f.risk] || RISK_COLORS.low;
                  return (
                    <div key={i} style={{ borderLeft: `4px solid ${rc.border}`, borderRadius: "0 6px 6px 0", padding: "14px 18px", background: rc.bg }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 18 }}>{TYPE_ICONS[f.type] || TYPE_ICONS.default}</span>
                        <span style={{ fontSize: 15, fontWeight: "bold", flex: 1 }}>{f.type.replace(/_/g, " ").toUpperCase()}</span>
                        {f.line && <span style={{ fontSize: 13, color: t.mutedText, background: t.accentFaint, padding: "3px 10px", borderRadius: 3 }}>Line {f.line}</span>}
                        <span style={{ fontSize: 13, fontWeight: "bold", color: "#fff", background: rc.badge, padding: "3px 12px", borderRadius: 3 }}>{f.risk}</span>
                      </div>
                      <div style={{ fontSize: 14, color: t.subText, fontFamily: "monospace", wordBreak: "break-all", background: t.codeBg, padding: "10px 12px", borderRadius: 4, lineHeight: 1.7 }}>{f.value}</div>
                    </div>
                  );
                })}
              </div>
            </section>

            {content && (
              <section style={card}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 22 }}>
                  <span style={sectionLabel}>Log Preview</span>
                  <span style={{ background: t.accentFaint, border: `1px solid ${t.accentBorder}`, color: t.accent, padding: "5px 14px", borderRadius: 4, fontSize: 15, fontWeight: "bold" }}>{getHighlightedLogs().filter(l => l.finding).length} flagged</span>
                </div>
                <div style={{ background: t.codeBg, borderRadius: 6, padding: 14, maxHeight: 460, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
                  {getHighlightedLogs().map((item, idx) => (
                    <div key={idx} style={{ display: "flex", gap: 12, padding: "5px 10px", background: item.finding ? item.riskColor?.bg : "transparent", borderLeft: item.finding ? `3px solid ${item.riskColor?.border}` : "3px solid transparent", color: item.finding ? item.riskColor?.text : t.mutedText, borderRadius: 3 }}>
                      <span style={{ minWidth: 36, opacity: 0.5, fontSize: 14, flexShrink: 0 }}>{item.lineNum}</span>
                      <span style={{ flex: 1, fontSize: 14, wordBreak: "break-all", lineHeight: 1.6 }}>{item.content.substring(0, 70)}{item.content.length > 70 ? "…" : ""}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>

          <section style={card}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 22 }}>
              <span style={sectionLabel}>AI Insights</span>
              <span style={{ background: result.insight_source === "ai" ? t.accentFaint : t.divider, border: `1px solid ${result.insight_source === "ai" ? t.accentBorder : t.divider}`, color: result.insight_source === "ai" ? t.accent : t.mutedText, padding: "5px 14px", borderRadius: 4, fontSize: 15, fontWeight: "bold" }}>
                {result.insight_source === "ai" ? "● AI" : "● Static"}
              </span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 16, marginBottom: 20 }}>
              {result.insights.map((ins, i) => (
                <div key={i} style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
                  <span style={{ fontSize: 15, fontWeight: "bold", color: t.accent, minWidth: 30, marginTop: 2, flexShrink: 0 }}>{String(i + 1).padStart(2, "0")}</span>
                  <span style={{ fontSize: 17, color: t.subText, lineHeight: 1.8 }}>{ins}</span>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 18px", background: t.accentFaint, border: `1px solid ${t.accentBorder}`, borderRadius: 6 }}>
              <span style={{ fontSize: 14, letterSpacing: 2, color: t.mutedText }}>ACTION TAKEN</span>
              <span style={{ fontSize: 16, fontWeight: "bold", color: t.accent }}>{result.action}</span>
            </div>
          </section>

          {result.timeline?.length > 0 && (
            <section style={card}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 22 }}>
                <span style={sectionLabel}>Timeline Replay</span>
                <span style={{ background: t.accentFaint, border: `1px solid ${t.accentBorder}`, color: t.accent, padding: "5px 14px", borderRadius: 4, fontSize: 15, fontWeight: "bold" }}>{result.timeline.length} events</span>
              </div>
              <div style={{ paddingLeft: 34 }}>
                {result.timeline.map((t2, i) => {
                  const rc = RISK_COLORS[t2.risk] || RISK_COLORS.low;
                  return (
                    <div key={i} style={{ position: "relative", paddingBottom: 28 }}>
                      <div style={{ position: "absolute", left: -40, top: 5, width: 16, height: 16, borderRadius: "50%", background: rc.badge }} />
                      {i < result.timeline.length - 1 && <div style={{ position: "absolute", left: -33, top: 23, width: 2, height: "100%", background: t.divider }} />}
                      <div style={{ fontSize: 14, color: t.mutedText, marginBottom: 5 }}>{t2.timestamp}</div>
                      <div style={{ fontSize: 16, fontWeight: "bold", color: rc.text, marginBottom: 8 }}>{t2.event.replace(/_/g, " ").toUpperCase()} — Line {t2.line}</div>
                      <div style={{ fontSize: 14, color: t.subText, fontFamily: "monospace", background: t.codeBg, padding: "10px 12px", borderRadius: 4, wordBreak: "break-all", lineHeight: 1.7 }}>{t2.raw}</div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          <div style={{ textAlign: "center", fontSize: 15, color: t.mutedText, paddingBottom: 52 }}>
            Analyzed {new Date(result.meta.analyzed_at).toLocaleString()} · {result.content_type} · {result.meta.total_lines} lines
          </div>
        </>)}
      </main>
    </div>
  );
}