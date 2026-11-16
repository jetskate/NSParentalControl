#!/usr/bin/env python3
"""
web_admin.py - Mobile-first web management UI & API for Switch Parental Control.

Runs inside the switch-server process on port 8788 (proxied via OpenResty HTTPS),
providing 4-digit PIN lock (HMAC cookie), brute-force protection, and dual-layer
control over both switch-server command queue and Raspberry Pi transition service.
"""

from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import html
import json
import math
import os
import secrets
import subprocess
import threading
import time
import urllib.request

SESSION_COOKIE_NAME = "switch_admin_session"
SESSION_MAX_AGE_S = 2592000  # 30 days
PIN_FAIL_LIMIT = 5
PIN_LOCK_SECONDS = 300
COMMAND_COOLDOWN_SECONDS = 10


def parse_hhmm_to_minutes(hhmm):
    s = str(hhmm).strip()
    if ":" in s:
        parts = s.split(":")
        if len(parts) != 2:
            raise ValueError(f"invalid HH:MM: {s}")
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError(f"time out of range: {s}")
        return h * 60 + m
    val = int(s)
    if not (0 <= val <= 1439):
        raise ValueError(f"minutes out of range: {val}")
    return val


def minutes_to_hhmm(mins):
    mins = int(mins)
    return f"{mins // 60:02d}:{mins % 60:02d}"


def build_html_page(app_version, initial_authed):
    ver_esc = html.escape(app_version)
    authed_js = "true" if initial_authed else "false"
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Switch 管控">
<meta name="theme-color" content="#F6F4EF">
<title>Switch 家长管控台</title>
<style>
  :root {{
    --bg: #F6F4EF;
    --surface: #FAF8F4;
    --surface-2: #EDE9E0;
    --ink: #181816;
    --ink-2: #5C5952;
    --muted: #888379;
    --line: #DDD7CA;
    --pine: #1D6B52;
    --pine-soft: #E5F0EC;
    --amber: #C86D1F;
    --amber-soft: #F7EBDD;
    --cinnabar: #B83A2D;
    --cinnabar-soft: #F6E4E2;
  }}
  * {{ box-sizing: border-box; -webkit-tap-highlight-color: transparent; }}
  html, body {{
    margin: 0; padding: 0;
    background: var(--bg); color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Noto Sans SC", "Microsoft YaHei", sans-serif;
    line-height: 1.45;
  }}
  .wrap {{
    max-width: 480px;
    margin: 0 auto;
    padding: max(18px, env(safe-area-inset-top)) 16px max(28px, env(safe-area-inset-bottom));
  }}
  .hidden {{ display: none !important; }}
  header.topbar {{
    display: flex; align-items: baseline; justify-content: space-between;
    padding-bottom: 14px; border-bottom: 1px solid var(--line); margin-bottom: 18px;
  }}
  header.topbar h1 {{
    margin: 0; font-size: 18px; font-weight: 650; letter-spacing: -0.01em;
    display: flex; align-items: baseline; flex-wrap: wrap;
  }}
  .top-actions {{ display: flex; gap: 8px; align-items: center; }}
  .pill {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 600;
    background: var(--surface-2); color: var(--ink-2); border: 1px solid var(--line);
  }}
  .btn-ghost {{
    background: transparent; border: 1px solid var(--line); color: var(--ink-2);
    border-radius: 10px; padding: 5px 10px; font-size: 12px; cursor: pointer;
  }}
  /* Login Keypad */
  .login-box {{
    padding-top: 24px;
    display: flex; flex-direction: column; align-items: center;
  }}
  .login-title {{
    margin: 0 0 6px; font-size: 20px; font-weight: 650;
    display: flex; align-items: baseline; justify-content: center;
  }}
  .login-sub {{ margin: 0 0 24px; font-size: 13px; color: var(--ink-2); }}
  .pin-dots {{
    display: flex; gap: 16px; margin-bottom: 14px;
  }}
  .pin-dot {{
    width: 16px; height: 16px; border-radius: 50%;
    border: 2px solid var(--ink-2); background: transparent;
    transition: background .12s, border-color .12s, transform .12s;
  }}
  .pin-dot.filled {{
    background: var(--pine); border-color: var(--pine); transform: scale(1.08);
  }}
  .pin-err {{
    min-height: 20px; font-size: 13px; color: var(--cinnabar); margin-bottom: 14px; text-align: center;
  }}
  .keypad {{
    display: grid; grid-template-columns: repeat(3, 76px); gap: 12px;
  }}
  .key-btn {{
    height: 62px; border-radius: 16px;
    border: 1px solid var(--line); background: var(--surface); color: var(--ink);
    font-size: 24px; font-weight: 500; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 1px 0 rgba(24,24,22,0.05);
  }}
  .key-btn:active {{ background: var(--surface-2); transform: scale(0.97); }}
  .key-btn.fn {{ font-size: 14px; color: var(--ink-2); background: var(--surface-2); }}
  /* Hero */
  .hero {{
    padding: 4px 2px 18px;
    border-bottom: 1px solid var(--line);
    margin-bottom: 18px;
  }}
  .hero-label {{
    display: flex; align-items: center; justify-content: space-between;
    font-size: 12px; color: var(--ink-2); margin-bottom: 4px;
  }}
  .status-dot {{
    display: inline-flex; align-items: center; gap: 6px; font-weight: 600;
  }}
  .dot {{
    width: 8px; height: 8px; border-radius: 50%; background: var(--muted);
  }}
  .dot.online {{
    background: var(--pine);
    box-shadow: 0 0 0 4px rgba(29, 107, 82, 0.16);
  }}
  .hero-num-row {{
    display: flex; align-items: baseline; gap: 8px;
  }}
  .hero-num {{
    font-size: 56px; font-weight: 700; line-height: 1.05;
    letter-spacing: -0.03em; font-variant-numeric: tabular-nums;
    color: var(--ink);
  }}
  .hero-num.warn {{ color: var(--amber); }}
  .hero-num.over {{ color: var(--cinnabar); }}
  .hero-unit {{ font-size: 15px; color: var(--ink-2); font-weight: 500; }}
  .bar {{
    height: 7px; border-radius: 999px; background: var(--surface-2);
    overflow: hidden; margin: 12px 0 10px;
  }}
  .bar-fill {{
    height: 100%; width: 0%; background: var(--pine);
    transition: width .3s ease, background .2s ease;
  }}
  .bar-fill.warn {{ background: var(--amber); }}
  .bar-fill.over {{ background: var(--cinnabar); }}
  .hero-meta {{
    display: flex; flex-wrap: wrap; gap: 8px 14px;
    font-size: 13px; color: var(--ink-2);
  }}
  .tag-curfew {{ color: var(--amber); font-weight: 600; }}
  /* Sections */
  .section {{
    background: var(--surface); border: 1px solid var(--line);
    border-radius: 16px; padding: 15px 16px; margin-bottom: 14px;
  }}
  .sec-head {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 10px;
  }}
  .sec-title {{ font-size: 14px; font-weight: 650; color: var(--ink); margin: 0; }}
  .sec-sub {{ font-size: 12px; color: var(--ink-2); margin: 2px 0 0; }}
  /* Master Enforce Toggle */
  .enforce-row {{
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
  }}
  .switch {{
    position: relative; width: 62px; height: 36px; flex-shrink: 0;
  }}
  .switch input {{ opacity: 0; width: 0; height: 0; }}
  .slider {{
    position: absolute; inset: 0; border-radius: 999px; cursor: pointer;
    background: var(--surface-2); border: 1px solid var(--line);
    transition: .2s;
  }}
  .slider::before {{
    content: ""; position: absolute; left: 3px; top: 3px;
    width: 28px; height: 28px; border-radius: 50%;
    background: var(--surface); border: 1px solid var(--line);
    box-shadow: 0 1px 3px rgba(24,24,22,0.18);
    transition: .2s;
  }}
  .switch input:checked + .slider {{
    background: var(--pine); border-color: var(--pine);
  }}
  .switch input:checked + .slider::before {{
    transform: translateX(26px); border-color: var(--pine);
  }}
  .lock-row {{
    margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--line);
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
  }}
  .btn-danger {{
    background: var(--cinnabar-soft); color: var(--cinnabar);
    border: 1px solid rgba(184,58,45,0.28);
    border-radius: 10px; padding: 8px 14px; font-size: 13px; font-weight: 600; cursor: pointer;
  }}
  .btn-danger:active {{ opacity: 0.85; }}
  /* Asymmetric Grant Buttons */
  .grant-grid {{
    display: grid; grid-template-columns: 1.45fr 1fr 1fr; gap: 9px;
  }}
  .btn-primary {{
    background: var(--pine); color: #FAF8F4; border: none;
    border-radius: 12px; padding: 13px 12px; font-size: 15px; font-weight: 650; cursor: pointer;
  }}
  .btn-primary:active {{ opacity: 0.9; }}
  .btn-secondary {{
    background: var(--pine-soft); color: var(--pine);
    border: 1px solid rgba(29,107,82,0.22);
    border-radius: 12px; padding: 13px 10px; font-size: 14px; font-weight: 600; cursor: pointer;
  }}
  .custom-grant {{
    display: flex; gap: 8px; margin-top: 10px;
  }}
  input[type="number"], input[type="time"], input[type="password"], input[type="text"] {{
    background: var(--bg); color: var(--ink);
    border: 1px solid var(--line); border-radius: 10px;
    padding: 9px 11px; font-size: 15px; width: 100%;
    font-family: inherit;
  }}
  .btn-outline {{
    background: var(--surface-2); color: var(--ink); border: 1px solid var(--line);
    border-radius: 10px; padding: 9px 14px; font-size: 14px; font-weight: 600; cursor: pointer;
    white-space: nowrap;
  }}
  button:disabled, input:disabled {{ opacity: 0.45; cursor: not-allowed; }}
  .switch input:disabled + .slider {{ opacity: 0.45; cursor: not-allowed; pointer-events: none; }}
  /* Policy Form */
  .policy-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;
  }}
  .field label {{
    display: block; font-size: 12px; color: var(--ink-2); margin-bottom: 4px;
  }}
  details summary {{
    cursor: pointer; list-style: none; font-size: 14px; font-weight: 650;
    display: flex; align-items: center; justify-content: space-between;
  }}
  details summary::-webkit-details-marker {{ display: none; }}
  /* Command log */
  .cmd-list {{ display: flex; flex-direction: column; gap: 8px; }}
  .cmd-item {{
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    font-size: 12px; padding: 8px 10px; border-radius: 10px; background: var(--bg);
    border: 1px solid var(--line);
  }}
  .badge {{
    padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 600;
  }}
  .badge.pending {{ background: var(--amber-soft); color: var(--amber); }}
  .badge.acked {{ background: var(--pine-soft); color: var(--pine); }}
  .badge.expired {{ background: var(--surface-2); color: var(--muted); }}
  .toast {{
    position: fixed; left: 50%; bottom: max(22px, env(safe-area-inset-bottom));
    transform: translateX(-50%);
    background: var(--ink); color: var(--bg);
    padding: 10px 16px; border-radius: 999px; font-size: 13px; font-weight: 500;
    box-shadow: 0 6px 20px rgba(24,24,22,0.22);
    z-index: 999; max-width: 90vw; text-align: center;
  }}
</style>
</head>
<body>
<div class="wrap">
  <!-- Login View -->
  <section id="loginView" class="login-box{' hidden' if initial_authed else ''}">
    <h1 class="login-title">Switch 家长管控台<span id="loginAppVersion" style="font-size: 9px; color: #888; margin-left: 8px; font-weight: normal;">{ver_esc}</span></h1>
    <p class="login-sub">请输入 4 位管理 PIN 码解锁</p>
    <div class="pin-dots" id="pinDots">
      <div class="pin-dot"></div><div class="pin-dot"></div><div class="pin-dot"></div><div class="pin-dot"></div>
    </div>
    <div class="pin-err" id="pinErr"></div>
    <div class="keypad">
      <button class="key-btn" data-k="1">1</button>
      <button class="key-btn" data-k="2">2</button>
      <button class="key-btn" data-k="3">3</button>
      <button class="key-btn" data-k="4">4</button>
      <button class="key-btn" data-k="5">5</button>
      <button class="key-btn" data-k="6">6</button>
      <button class="key-btn" data-k="7">7</button>
      <button class="key-btn" data-k="8">8</button>
      <button class="key-btn" data-k="9">9</button>
      <button class="key-btn fn" data-k="clr">清空</button>
      <button class="key-btn" data-k="0">0</button>
      <button class="key-btn fn" data-k="del">退格</button>
    </div>
  </section>

  <!-- Main Dashboard View -->
  <section id="appView" class="{'' if initial_authed else 'hidden'}">
    <header class="topbar">
      <h1>Switch 管控<span id="appVersion" style="font-size: 9px; color: #888; margin-left: 8px; font-weight: normal;">{ver_esc}</span></h1>
      <div class="top-actions">
        <span class="pill" id="sourcePill">--</span>
        <button class="btn-ghost" id="btnRefresh" title="刷新">刷新</button>
        <button class="btn-ghost" id="btnLogout" title="锁定">锁屏</button>
      </div>
    </header>

    <div class="hero">
      <div class="hero-label">
        <span>今日剩余可玩时长</span>
        <span class="status-dot"><span class="dot" id="onlineDot"></span><span id="onlineText">读取中</span></span>
      </div>
      <div class="hero-num-row">
        <div class="hero-num" id="heroRemain">--</div>
        <div class="hero-unit">分钟</div>
      </div>
      <div class="bar"><div class="bar-fill" id="heroBar"></div></div>
      <div class="hero-meta">
        <span id="heroUsage">今日已用 -- / -- 分钟</span>
        <span id="heroGame">游戏：--</span>
        <span id="heroCurfew">宵禁：--</span>
      </div>
    </div>

    <!-- 1. Enforce Master Switch + Emergency Lock -->
    <div class="section">
      <div class="enforce-row">
        <div>
          <p class="sec-title" id="enforceTitle">是否开启时间限制</p>
          <p class="sec-sub" id="enforceDesc">同步控制 Switch 模块与树莓派过渡层</p>
        </div>
        <label class="switch">
          <input type="checkbox" id="enforceToggle">
          <span class="slider"></span>
        </label>
      </div>
      <div class="lock-row">
        <span class="sec-sub">需要立刻让孩子停玩？</span>
        <button class="btn-danger" id="btnLockNow">立即锁机</button>
      </div>
    </div>

    <!-- 2. Quick & Custom Grant -->
    <div class="section">
      <div class="sec-head">
        <p class="sec-title">临时调整今日时间</p>
        <span class="sec-sub" id="grantSubHint">10秒防连点 · 同步双层</span>
      </div>
      <div class="grant-grid">
        <button class="btn-primary" data-grant="30">+30 分钟</button>
        <button class="btn-secondary" data-grant="15">+15</button>
        <button class="btn-secondary" data-grant="60">+60</button>
      </div>
      <div class="custom-grant">
        <input type="number" id="customMinutes" placeholder="自定义分钟 (-60 ~ 720)" min="-60" max="720">
        <button class="btn-outline" id="btnCustomGrant">确定</button>
      </div>
    </div>

    <!-- 3. Daily Limits & Curfew -->
    <div class="section">
      <details id="policyDetails">
        <summary>
          <span>日常限额与宵禁时段</span>
          <span class="sec-sub" id="policySummary">60/120分 · 07:00-23:00</span>
        </summary>
        <div style="margin-top: 12px;">
          <div class="policy-grid">
            <div class="field">
              <label for="inWeekday">工作日限额（分钟）</label>
              <input type="number" id="inWeekday" min="0" max="1440" value="60">
            </div>
            <div class="field">
              <label for="inWeekend">周末限额（分钟）</label>
              <input type="number" id="inWeekend" min="0" max="1440" value="120">
            </div>
            <div class="field">
              <label for="inGameStart">可玩开始（宵禁结束）</label>
              <input type="time" id="inGameStart" value="07:00">
            </div>
            <div class="field">
              <label for="inBedtime">可玩结束（宵禁开始）</label>
              <input type="time" id="inBedtime" value="23:00">
            </div>
          </div>
          <button class="btn-primary" style="width:100%;" id="btnSavePolicy">保存日常策略并同步</button>
        </div>
      </details>
    </div>

    <!-- 4. Recent Commands & Change PIN -->
    <div class="section">
      <div class="sec-head">
        <p class="sec-title">最近下行指令流水</p>
        <span class="sec-sub">最多显示 5 条</span>
      </div>
      <div class="cmd-list" id="cmdList">
        <div class="sec-sub">暂无指令记录</div>
      </div>
    </div>

    <div class="section">
      <details id="pinDetails">
        <summary>
          <span>修改 4 位管理 PIN 码</span>
          <span class="sec-sub">安全设置</span>
        </summary>
        <div style="margin-top: 12px;">
          <div class="field" style="margin-bottom: 12px;">
            <label for="inNewPin">新 4 位数字 PIN</label>
            <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" id="inNewPin" placeholder="输入 4 位数字 PIN">
          </div>
          <button class="btn-outline" style="width:100%;" id="btnChangePin">更新管理 PIN</button>
        </div>
      </details>
    </div>
  </section>
</div>
<div class="toast hidden" id="toast"></div>

<script>
const INITIAL_AUTHED = {authed_js};
let pinBuf = "";
let busy = false;
let actionBusy = false;
let cooldownUntil = 0;
let lockConfirmUntil = 0;

function updateCooldownUI() {{
  const now = Date.now();
  const remainingMs = cooldownUntil - now;
  const inCooldown = remainingMs > 0;
  const shouldDisable = actionBusy || inCooldown;

  document.querySelectorAll("[data-grant]").forEach(b => b.disabled = shouldDisable);
  const customBtn = document.getElementById("btnCustomGrant");
  if (customBtn) customBtn.disabled = shouldDisable;
  const enfToggle = document.getElementById("enforceToggle");
  if (enfToggle) enfToggle.disabled = shouldDisable;
  const lockBtn = document.getElementById("btnLockNow");
  if (lockBtn) lockBtn.disabled = shouldDisable;
  const polBtn = document.getElementById("btnSavePolicy");
  if (polBtn) polBtn.disabled = shouldDisable;

  const hintEl = document.getElementById("grantSubHint");
  if (hintEl) {{
    if (inCooldown) {{
      const sec = Math.max(1, Math.ceil(remainingMs / 1000));
      hintEl.textContent = "冷却中 " + sec + "s";
      hintEl.style.color = "var(--amber)";
      hintEl.style.fontWeight = "600";
    }} else if (actionBusy) {{
      hintEl.textContent = "处理中...";
      hintEl.style.color = "var(--amber)";
      hintEl.style.fontWeight = "600";
    }} else {{
      hintEl.textContent = "10秒防连点 · 同步双层";
      hintEl.style.color = "";
      hintEl.style.fontWeight = "";
    }}
  }}
}}

function startCooldown(seconds) {{
  if (!seconds || seconds <= 0) return;
  const target = Date.now() + Number(seconds) * 1000;
  if (target > cooldownUntil) {{
    cooldownUntil = target;
  }}
  updateCooldownUI();
}}

setInterval(updateCooldownUI, 500);

function showToast(msg) {{
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.add("hidden"), 2600);
}}

function renderPinDots() {{
  const dots = document.querySelectorAll("#pinDots .pin-dot");
  dots.forEach((d, idx) => d.classList.toggle("filled", idx < pinBuf.length));
}}

async function api(path, method="GET", body=null) {{
  const opts = {{ method, credentials: "same-origin", headers: {{}} }};
  if (body !== null) {{
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }}
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({{ ok: false, error: "invalid_response" }}));
  if (res.status === 401 && path !== "/api/login") {{
    document.getElementById("appView").classList.add("hidden");
    document.getElementById("loginView").classList.remove("hidden");
    throw new Error("unauthorized");
  }}
  if (!res.ok) {{
    const err = new Error(data.error || ("HTTP " + res.status));
    err.status = res.status;
    err.data = data;
    throw err;
  }}
  return data;
}}

async function tryLogin(pin) {{
  if (busy) return;
  busy = true;
  document.getElementById("pinErr").textContent = "";
  try {{
    await api("/api/login", "POST", {{ pin }});
    pinBuf = "";
    renderPinDots();
    document.getElementById("loginView").classList.add("hidden");
    document.getElementById("appView").classList.remove("hidden");
    await loadStatus();
  }} catch (e) {{
    pinBuf = "";
    renderPinDots();
    if (e.status === 429) {{
      const s = (e.data && e.data.retry_after_s) || 300;
      document.getElementById("pinErr").textContent = "输错次数过多，请 " + s + " 秒后再试";
    }} else {{
      document.getElementById("pinErr").textContent = "PIN 码错误，请重试";
    }}
  }} finally {{
    busy = false;
  }}
}}

document.querySelectorAll(".key-btn").forEach(btn => {{
  btn.addEventListener("click", () => {{
    const k = btn.dataset.k;
    if (k === "clr") pinBuf = "";
    else if (k === "del") pinBuf = pinBuf.slice(0, -1);
    else if (pinBuf.length < 4) pinBuf += k;
    renderPinDots();
    if (pinBuf.length === 4) tryLogin(pinBuf);
  }});
}});

function cmdTypeLabel(c) {{
  if (c.type === "grant_minutes") return "加时 +" + c.minutes + " 分";
  if (c.type === "set_policy") return "策略 " + c.weekday_limit + "/" + c.weekend_limit + "分";
  if (c.type === "lock_now") return "立即锁机";
  return c.type;
}}

function statusBadge(s) {{
  if (s === "acked") return '<span class="badge acked">已生效</span>';
  if (s === "expired") return '<span class="badge expired">已过期</span>';
  return '<span class="badge pending">排队中</span>';
}}

function renderStatus(d) {{
  const rem = Number(d.remaining_min ?? 0);
  const used = Number(d.used_min ?? 0);
  const lim = Number(d.limit_min ?? 0);

  document.getElementById("sourcePill").textContent = d.active_source === "switch-server" ? "模块直连" : "树莓派过渡";

  const remEl = document.getElementById("heroRemain");
  remEl.textContent = rem;
  remEl.classList.remove("warn", "over");
  const barEl = document.getElementById("heroBar");
  barEl.classList.remove("warn", "over");
  if (rem <= 0) {{ remEl.classList.add("over"); barEl.classList.add("over"); }}
  else if (rem <= 10) {{ remEl.classList.add("warn"); barEl.classList.add("warn"); }}

  const pct = lim > 0 ? Math.min(100, Math.max(0, Math.round((used / lim) * 100))) : 0;
  barEl.style.width = pct + "%";

  const dotEl = document.getElementById("onlineDot");
  dotEl.classList.toggle("online", !!d.online);
  document.getElementById("onlineText").textContent = d.online ? "游戏中" : "待机 / 离线";

  document.getElementById("heroUsage").textContent = (d.day || "") + " · 已用 " + used + " / " + lim + " 分钟";
  document.getElementById("heroGame").textContent = "游戏：" + (d.game || "空闲");
  const curfewEl = document.getElementById("heroCurfew");
  curfewEl.textContent = "宵禁：" + (d.curfew || "无");
  curfewEl.classList.toggle("tag-curfew", d.curfew && d.curfew !== "无");

  const enf = !!d.enforce_enabled;
  document.getElementById("enforceToggle").checked = enf;
  document.getElementById("enforceTitle").textContent = enf ? "已开启强制限制（到点封锁）" : "已解除限制（自由模式）";
  document.getElementById("enforceDesc").textContent = enf ? "超时或宵禁将强制关游戏/锁屏" : "仅统计时长不踢出，随时可恢复限制";

  const p = d.saved_policy || {{}};
  if (p.weekday_limit !== undefined) {{
    document.getElementById("inWeekday").value = p.weekday_limit;
    document.getElementById("inWeekend").value = p.weekend_limit;
    document.getElementById("inGameStart").value = p.game_start || "07:00";
    document.getElementById("inBedtime").value = p.bedtime || "23:00";
    document.getElementById("policySummary").textContent =
      p.weekday_limit + "/" + p.weekend_limit + "分 · " + (p.game_start || "07:00") + "-" + (p.bedtime || "23:00");
  }}

  const listEl = document.getElementById("cmdList");
  const cmds = d.recent_commands || [];
  if (!cmds.length) {{
    listEl.innerHTML = '<div class="sec-sub">暂无指令记录</div>';
  }} else {{
    listEl.innerHTML = cmds.map(c =>
      `<div class="cmd-item"><span>${{cmdTypeLabel(c)}} <span style="color:var(--muted)">(${{c.command_id}})</span></span>${{statusBadge(c.status)}}</div>`
    ).join("");
  }}

  if (d.cooldown_remaining_s && Number(d.cooldown_remaining_s) > 0) {{
    startCooldown(Number(d.cooldown_remaining_s));
  }}
}}

async function loadStatus() {{
  try {{
    const data = await api("/api/status");
    renderStatus(data);
  }} catch (e) {{
    if (e.message !== "unauthorized") showToast("刷新失败: " + e.message);
  }}
}}

document.getElementById("btnRefresh").addEventListener("click", loadStatus);
document.getElementById("btnLogout").addEventListener("click", async () => {{
  await api("/api/logout", "POST", {{}}).catch(() => {{}});
  document.getElementById("appView").classList.add("hidden");
  document.getElementById("loginView").classList.remove("hidden");
}});

document.getElementById("enforceToggle").addEventListener("change", async (ev) => {{
  if (actionBusy || Date.now() < cooldownUntil) {{
    ev.preventDefault();
    ev.target.checked = !ev.target.checked;
    showToast("操作过于频繁，请等待冷却");
    return;
  }}
  const target = ev.target.checked;
  actionBusy = true;
  updateCooldownUI();
  try {{
    const res = await api("/api/toggle-enforce", "POST", {{ enforce_enabled: target }});
    startCooldown(res.cooldown_remaining_s || 10);
    showToast(target ? "已开启强制限制（双层已同步）" : "已切换为自由模式（只统计不踢人）");
    await loadStatus();
  }} catch (e) {{
    ev.target.checked = !target;
    if (e.status === 429 && e.data && e.data.retry_after_s) {{
      startCooldown(e.data.retry_after_s);
    }}
    showToast("切换失败: " + e.message);
  }} finally {{
    actionBusy = false;
    updateCooldownUI();
  }}
}});

document.getElementById("btnLockNow").addEventListener("click", async () => {{
  if (actionBusy || Date.now() < cooldownUntil) {{
    showToast("操作过于频繁，请等待冷却");
    return;
  }}
  const now = Date.now();
  const btn = document.getElementById("btnLockNow");
  if (now > lockConfirmUntil) {{
    lockConfirmUntil = now + 4000;
    btn.textContent = "再次点击确认锁机";
    setTimeout(() => {{
      if (Date.now() >= lockConfirmUntil) btn.textContent = "立即锁机";
    }}, 4100);
    return;
  }}
  lockConfirmUntil = 0;
  btn.textContent = "立即锁机";
  actionBusy = true;
  updateCooldownUI();
  try {{
    const res = await api("/api/lock-now", "POST", {{}});
    startCooldown(res.cooldown_remaining_s || 10);
    showToast("锁机指令已下发");
    await loadStatus();
  }} catch (e) {{
    if (e.status === 429 && e.data && e.data.retry_after_s) {{
      startCooldown(e.data.retry_after_s);
    }}
    showToast("锁机失败: " + e.message);
  }} finally {{
    actionBusy = false;
    updateCooldownUI();
  }}
}});

async function sendGrant(minutes) {{
  if (actionBusy || Date.now() < cooldownUntil) {{
    showToast("操作过于频繁，请等待冷却");
    return;
  }}
  actionBusy = true;
  updateCooldownUI();
  try {{
    const res = await api("/api/grant", "POST", {{ minutes }});
    startCooldown(res.cooldown_remaining_s || 10);
    showToast((minutes > 0 ? "已加时 +" : "已调整 ") + minutes + " 分钟");
    await loadStatus();
  }} catch (e) {{
    if (e.status === 429 && e.data && e.data.retry_after_s) {{
      startCooldown(e.data.retry_after_s);
    }}
    showToast("加时失败: " + e.message);
  }} finally {{
    actionBusy = false;
    updateCooldownUI();
  }}
}}

document.querySelectorAll("[data-grant]").forEach(btn => {{
  btn.addEventListener("click", () => sendGrant(Number(btn.dataset.grant)));
}});

document.getElementById("btnCustomGrant").addEventListener("click", () => {{
  const v = Number(document.getElementById("customMinutes").value);
  if (!Number.isInteger(v) || v === 0 || v < -60 || v > 720) {{
    showToast("请输入 -60 ~ 720 之间的非零整数");
    return;
  }}
  sendGrant(v);
}});

document.getElementById("btnSavePolicy").addEventListener("click", async () => {{
  if (actionBusy || Date.now() < cooldownUntil) {{
    showToast("操作过于频繁，请等待冷却");
    return;
  }}
  const body = {{
    weekday_limit: Number(document.getElementById("inWeekday").value),
    weekend_limit: Number(document.getElementById("inWeekend").value),
    game_start: document.getElementById("inGameStart").value,
    bedtime: document.getElementById("inBedtime").value,
  }};
  actionBusy = true;
  updateCooldownUI();
  try {{
    const res = await api("/api/policy", "POST", body);
    startCooldown(res.cooldown_remaining_s || 10);
    showToast("日常策略已保存并同步双层");
    await loadStatus();
  }} catch (e) {{
    if (e.status === 429 && e.data && e.data.retry_after_s) {{
      startCooldown(e.data.retry_after_s);
    }}
    showToast("保存失败: " + e.message);
  }} finally {{
    actionBusy = false;
    updateCooldownUI();
  }}
}});

document.getElementById("btnChangePin").addEventListener("click", async () => {{
  const new_pin = document.getElementById("inNewPin").value.trim();
  if (!/^\\d{{4}}$/.test(new_pin)) {{
    showToast("新 PIN 必须是 4 位数字");
    return;
  }}
  try {{
    await api("/api/pin", "POST", {{ new_pin }});
    document.getElementById("inNewPin").value = "";
    showToast("管理 PIN 已更新");
  }} catch (e) {{
    showToast("修改失败: " + e.message);
  }}
}});

if (INITIAL_AUTHED) {{
  loadStatus();
}}
setInterval(() => {{
  if (!document.getElementById("appView").classList.contains("hidden")) loadStatus();
}}, 30000);
</script>
</body>
</html>
"""


class WebAdminManager:
    """Manages session auth, brute-force lockout, admin_state, and Pi SSH dual-write."""

    def __init__(self, server_ctx, config, config_path, app_version):
        self.ctx = server_ctx
        self.config = config
        self.config_path = config_path
        self.app_version = app_version

        self.admin_state_path = os.path.join(self.ctx.data_dir, "admin_state.json")
        self._admin_lock = threading.RLock()
        self._auth_lock = threading.RLock()
        self._fail_tracker = {}  # ip -> {"count": int, "locked_until": float}

        self.last_command_at = 0.0
        state_pin = None
        if os.path.exists(self.admin_state_path):
            try:
                with open(self.admin_state_path, "r", encoding="utf-8") as f:
                    st = json.load(f)
                    self.last_command_at = float(st.get("last_command_at", 0))
                    cand = str(st.get("admin_pin", "")).strip()
                    if len(cand) == 4 and cand.isdigit():
                        state_pin = cand
            except Exception:
                pass

        cfg_pin = str(config.get("admin_pin", "2580")).strip()
        self.admin_pin = state_pin if state_pin else (cfg_pin if (len(cfg_pin) == 4 and cfg_pin.isdigit()) else "2580")

        secret_hex = str(config.get("web_session_secret") or config["heartbeat_token"])
        self.session_secret = secret_hex.encode("utf-8")

        self.pi_host = config.get("pi_host", "100.85.73.80")
        self.pi_user = config.get("pi_user", "pi")
        self.pi_status_url = config.get("pi_status_url", "http://100.85.73.80:8787/status")
        self.pi_ssh_key = config.get("pi_ssh_key", "/home/ai-agent/.ssh/id_ed25519")
        self.pi_known_hosts = config.get("pi_known_hosts", "/home/ai-agent/.ssh/known_hosts")

        self._ensure_admin_state()

    def _default_saved_policy(self):
        dp = self.ctx.default_policy
        return {
            "weekday_limit": int(dp.get("weekday_limit", 60)),
            "weekend_limit": int(dp.get("weekend_limit", 120)),
            "game_start": minutes_to_hhmm(dp.get("game_start", 420)),
            "bedtime": minutes_to_hhmm(dp.get("bedtime", 1380)),
        }

    def _ensure_admin_state(self):
        state = None
        if os.path.exists(self.admin_state_path):
            try:
                with open(self.admin_state_path, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception:
                state = None
        if state is None:
            self.save_admin_state({
                "admin_pin": self.admin_pin,
                "last_command_at": int(self.last_command_at),
                "enforce_enabled": False,
                "saved_policy": self._default_saved_policy(),
                "updated_at": int(time.time()),
            })
        else:
            dirty = False
            if "admin_pin" not in state or not (isinstance(state["admin_pin"], str) and len(state["admin_pin"]) == 4 and state["admin_pin"].isdigit()):
                state["admin_pin"] = self.admin_pin
                dirty = True
            if "last_command_at" not in state:
                state["last_command_at"] = int(self.last_command_at)
                dirty = True
            if dirty:
                self.save_admin_state(state)

    def load_admin_state(self):
        with self.ctx._locked_file(".admin.lock", self._admin_lock):
            if not os.path.exists(self.admin_state_path):
                return {
                    "admin_pin": self.admin_pin,
                    "last_command_at": int(self.last_command_at),
                    "enforce_enabled": False,
                    "saved_policy": self._default_saved_policy(),
                    "updated_at": 0,
                }
            with open(self.admin_state_path, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_admin_state(self, state):
        from switch_server import atomic_write_json
        state["updated_at"] = int(time.time())
        with self.ctx._locked_file(".admin.lock", self._admin_lock):
            atomic_write_json(self.admin_state_path, state)

    def check_cooldown(self):
        now = time.time()
        with self._admin_lock:
            elapsed = now - getattr(self, "last_command_at", 0.0)
            if elapsed < COMMAND_COOLDOWN_SECONDS:
                return max(1, int(math.ceil(COMMAND_COOLDOWN_SECONDS - elapsed)))
            self.last_command_at = now
            return 0

    def mark_cooldown_success(self):
        now = time.time()
        with self._admin_lock:
            self.last_command_at = now
        try:
            st = self.load_admin_state()
            st["last_command_at"] = int(now)
            self.save_admin_state(st)
        except Exception:
            pass

    def get_cooldown_remaining(self):
        now = time.time()
        with self._admin_lock:
            elapsed = now - getattr(self, "last_command_at", 0.0)
            if elapsed < COMMAND_COOLDOWN_SECONDS:
                return max(1, int(math.ceil(COMMAND_COOLDOWN_SECONDS - elapsed)))
            return 0

    def make_session_token(self):
        exp = int(time.time()) + SESSION_MAX_AGE_S
        nonce = secrets.token_hex(12)
        payload = f"{exp}.{nonce}"
        sig = hmac.new(self.session_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def verify_session_token(self, token):
        if not token or token.count(".") != 2:
            return False
        exp_s, nonce, sig = token.split(".", 2)
        try:
            exp = int(exp_s)
        except ValueError:
            return False
        if exp <= int(time.time()):
            return False
        expected = hmac.new(
            self.session_secret, f"{exp_s}.{nonce}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, sig)

    def check_pin_lockout(self, client_ip):
        now = time.time()
        with self._auth_lock:
            rec = self._fail_tracker.get(client_ip)
            if rec and rec.get("locked_until", 0) > now:
                return int(rec["locked_until"] - now) + 1
            return 0

    def record_pin_attempt(self, client_ip, pin_ok):
        now = time.time()
        with self._auth_lock:
            if pin_ok:
                self._fail_tracker.pop(client_ip, None)
                return 0
            rec = self._fail_tracker.setdefault(client_ip, {"count": 0, "locked_until": 0})
            if rec["locked_until"] and rec["locked_until"] <= now:
                rec["count"] = 0
                rec["locked_until"] = 0
            rec["count"] += 1
            if rec["count"] >= PIN_FAIL_LIMIT:
                rec["locked_until"] = now + PIN_LOCK_SECONDS
                rec["count"] = 0
                return PIN_LOCK_SECONDS
            return 0

    def enqueue_server_command(self, cmd_body):
        from switch_server import atomic_write_json
        commands_path = self.ctx.commands_path
        now_ts = int(time.time())
        with self.ctx._locked_file(".commands.lock", self.ctx._cmd_thread_lock):
            if os.path.exists(commands_path):
                with open(commands_path, "r", encoding="utf-8") as f:
                    qdata = json.load(f)
            else:
                qdata = {"config_rev": 1, "seq": 0, "commands": []}

            seq = int(qdata.get("seq", 0)) + 1
            qdata["seq"] = seq
            if cmd_body["type"] == "set_policy":
                qdata["config_rev"] = int(qdata.get("config_rev", 1)) + 1

            command_id = f"c{now_ts}-{seq}"
            entry = {
                "command_id": command_id,
                "created_at": now_ts,
                "status": "pending",
            }
            entry.update(cmd_body)
            qdata.setdefault("commands", []).append(entry)
            atomic_write_json(commands_path, qdata)

        self.ctx.log_event("command_queued", command_id=command_id, type=cmd_body["type"], source="web_admin")
        return command_id

    def fetch_pi_status(self):
        try:
            req = urllib.request.Request(self.pi_status_url, headers={"User-Agent": "SwitchWebAdmin/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                return {"ok": True, "data": json.loads(resp.read().decode("utf-8"))}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def run_pi_python(self, py_script):
        if not os.path.exists(self.pi_ssh_key):
            return {"ok": False, "error": f"ssh key not found: {self.pi_ssh_key}"}
        cmd = [
            "ssh",
            "-i", self.pi_ssh_key,
            "-o", f"UserKnownHostsFile={self.pi_known_hosts}",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=4",
            "-o", "StrictHostKeyChecking=accept-new",
            f"{self.pi_user}@{self.pi_host}",
            "python3", "-",
        ]
        try:
            res = subprocess.run(cmd, input=py_script, capture_output=True, text=True, timeout=14)
            if res.returncode != 0:
                return {"ok": False, "rc": res.returncode, "stderr": res.stderr.strip(), "stdout": res.stdout.strip()}
            out = res.stdout.strip()
            try:
                return json.loads(out.splitlines()[-1]) if out else {"ok": True}
            except Exception:
                return {"ok": True, "stdout": out}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def pi_sync_config(self, enforce_mode=None, weekday_limit=None, weekend_limit=None, curfew=None):
        payload = json.dumps({
            "enforce_mode": enforce_mode,
            "weekday_limit": weekday_limit,
            "weekend_limit": weekend_limit,
            "curfew": curfew,
        })
        script = f"""
import json, os, subprocess
upd = json.loads({payload!r})
cfg_path = os.path.expanduser('~/switch-parental/config.json')
with open(cfg_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
if upd['enforce_mode'] is not None:
    cfg['enforce_mode'] = upd['enforce_mode']
if upd['weekday_limit'] is not None:
    cfg.setdefault('limits', {{}})['weekday_minutes'] = int(upd['weekday_limit'])
if upd['weekend_limit'] is not None:
    cfg.setdefault('limits', {{}})['weekend_minutes'] = int(upd['weekend_limit'])
if upd['curfew'] is not None:
    cfg['curfew'] = upd['curfew']
tmp = cfg_path + '.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
os.replace(tmp, cfg_path)
r = subprocess.run(['sudo', '-n', 'systemctl', 'restart', 'switch-parental'], capture_output=True, text=True)
print(json.dumps({{'ok': r.returncode == 0, 'enforce_mode': cfg.get('enforce_mode'), 'limits': cfg.get('limits'), 'curfew': cfg.get('curfew'), 'stderr': r.stderr.strip()}}))
"""
        return self.run_pi_python(script)

    def pi_grant(self, minutes):
        script = f"""
import json, os, subprocess
mins = int({int(minutes)})
st_path = os.path.expanduser('~/switch-parental/state.json')
subprocess.run(['sudo', '-n', 'systemctl', 'stop', 'switch-parental'], check=True)
try:
    if mins > 0:
        subprocess.run(['python3', os.path.expanduser('~/switch-parental/switch_parental.py'), 'grant', str(mins)], check=True, capture_output=True, text=True)
    else:
        with open(st_path, 'r', encoding='utf-8') as f:
            st = json.load(f)
        st['granted_seconds'] = int(st.get('granted_seconds', 0)) + mins * 60
        tmp = st_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(st, f, ensure_ascii=False, indent=2)
        os.replace(tmp, st_path)
    with open(st_path, 'r', encoding='utf-8') as f:
        st = json.load(f)
finally:
    subprocess.run(['sudo', '-n', 'systemctl', 'start', 'switch-parental'], check=True)
print(json.dumps({{'ok': True, 'granted_seconds': st.get('granted_seconds', 0)}}))
"""
        return self.run_pi_python(script)

    def pi_lock_now(self):
        script = """
import json, os, sys
sys.path.insert(0, os.path.expanduser('~/switch-parental'))
from switch_parental import load_config, BotBase
cfg = load_config()
try:
    with BotBase(cfg['switch_host'], int(cfg['switch_port']), 2.5) as bb:
        bb.kick_home()
    print(json.dumps({'ok': True, 'pi_triggered': True}))
except Exception as e:
    print(json.dumps({'ok': True, 'pi_triggered': False, 'detail': str(e)}))
"""
        return self.run_pi_python(script)

    def get_aggregated_status(self):
        from switch_server import read_json_safe
        now_ts = int(time.time())
        admin = self.load_admin_state()
        server_state = read_json_safe(self.ctx.state_path, {"devices": {}, "updated_at": 0})
        poller_view = read_json_safe(self.ctx.poller_view_path, {})
        qdata = read_json_safe(self.ctx.commands_path, {"config_rev": 1, "seq": 0, "commands": []})

        devices = server_state.get("devices", {})
        fresh_device = None
        for dev in devices.values():
            if now_ts - int(dev.get("last_seen", 0)) <= 300:
                fresh_device = dev
                break

        pi_res = self.fetch_pi_status()
        pi_data = pi_res.get("data") if pi_res.get("ok") else None

        if fresh_device is not None and poller_view:
            active_source = "switch-server"
            summary = {
                "day": poller_view.get("day", ""),
                "remaining_min": int(poller_view.get("remaining_min", 0)),
                "used_min": int(poller_view.get("used_min", 0)),
                "limit_min": int(poller_view.get("limit_min", 0)),
                "game": poller_view.get("game", "空闲"),
                "online": bool(poller_view.get("online", False)),
                "curfew": poller_view.get("宵禁", "无"),
            }
        elif pi_data is not None:
            active_source = "pi"
            summary = {
                "day": pi_data.get("日期", ""),
                "remaining_min": int(pi_data.get("剩余_分钟", 0)),
                "used_min": int(pi_data.get("已用_分钟", 0)),
                "limit_min": int(pi_data.get("今日额度_分钟", 0)),
                "game": pi_data.get("正在玩", "空闲"),
                "online": bool(pi_data.get("在线", False)),
                "curfew": pi_data.get("宵禁", "无"),
            }
        else:
            active_source = "switch-server"
            summary = {
                "day": datetime.now().strftime("%Y-%m-%d"),
                "remaining_min": 0,
                "used_min": 0,
                "limit_min": int(admin["saved_policy"]["weekday_limit"]),
                "game": "等待签到",
                "online": False,
                "curfew": "无",
            }

        recent_commands = list(reversed(qdata.get("commands", [])))[:5]
        return {
            "ok": True,
            "version": self.app_version,
            "active_source": active_source,
            **summary,
            "enforce_enabled": bool(admin.get("enforce_enabled", False)),
            "saved_policy": admin.get("saved_policy", self._default_saved_policy()),
            "recent_commands": recent_commands,
            "server_state": server_state,
            "pi_state": pi_res,
            "cooldown_remaining_s": self.get_cooldown_remaining(),
        }

    def update_pin(self, new_pin):
        st = self.load_admin_state()
        st["admin_pin"] = new_pin
        self.save_admin_state(st)

        def _in_place_update_pin(path, pin_val):
            if not os.path.exists(path):
                return
            with open(path, "r+", encoding="utf-8") as wf:
                data = json.load(wf)
                data["admin_pin"] = pin_val
                wf.seek(0)
                json.dump(data, wf, ensure_ascii=False, indent=2)
                wf.write("\n")
                wf.truncate()
                wf.flush()
                os.fsync(wf.fileno())

        _in_place_update_pin(self.config_path, new_pin)
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass

        vault_path = "/home/ai-agent/workspace/projects/switch-parental/vault/credentials.vne"
        if os.path.exists(vault_path):
            try:
                _in_place_update_pin(vault_path, new_pin)
                os.chmod(vault_path, 0o600)
            except OSError:
                pass

        self.admin_pin = new_pin
        if isinstance(self.config, dict):
            self.config["admin_pin"] = new_pin


def make_http_handler(mgr):
    class WebAdminHandler(BaseHTTPRequestHandler):
        def _client_ip(self):
            xff = self.headers.get("X-Forwarded-For", "").strip()
            if xff:
                return xff.split(",")[0].strip()
            xri = self.headers.get("X-Real-IP", "").strip()
            if xri:
                return xri
            return self.client_address[0]

        def _is_authed(self):
            raw = self.headers.get("Cookie", "")
            if not raw:
                return False
            c = cookies.SimpleCookie()
            try:
                c.load(raw)
            except cookies.CookieError:
                return False
            morsel = c.get(SESSION_COOKIE_NAME)
            return bool(morsel and mgr.verify_session_token(morsel.value))

        def _send_json(self, code, obj, extra_headers=None):
            body = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for k, v in extra_headers:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0 or length > 65536:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))

        def log_message(self, format, *args):
            pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/api/health":
                return self._send_json(200, {
                    "ok": True,
                    "version": mgr.app_version,
                    "tcp_port": int(mgr.config.get("listen_port", 39107)),
                    "web_port": int(mgr.config.get("web_listen_port", 8788)),
                    "ts": int(time.time()),
                })

            if path == "/":
                authed = self._is_authed()
                body = build_html_page(mgr.app_version, authed).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/status":
                if not self._is_authed():
                    return self._send_json(401, {"ok": False, "error": "unauthorized"})
                return self._send_json(200, mgr.get_aggregated_status())

            return self._send_json(404, {"ok": False, "error": "not_found"})

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            try:
                body = self._read_json()
            except Exception:
                return self._send_json(400, {"ok": False, "error": "invalid_json"})

            if path == "/api/login":
                ip = self._client_ip()
                locked = mgr.check_pin_lockout(ip)
                if locked > 0:
                    return self._send_json(429, {"ok": False, "error": "too_many_attempts", "retry_after_s": locked})

                pin = str(body.get("pin", "")).strip()
                ok = hmac.compare_digest(pin.encode("utf-8"), mgr.admin_pin.encode("utf-8"))
                if not ok:
                    lock_s = mgr.record_pin_attempt(ip, False)
                    if lock_s > 0:
                        return self._send_json(429, {"ok": False, "error": "too_many_attempts", "retry_after_s": lock_s})
                    return self._send_json(403, {"ok": False, "error": "invalid_pin"})

                mgr.record_pin_attempt(ip, True)
                tok = mgr.make_session_token()
                cookie_val = (
                    f"{SESSION_COOKIE_NAME}={tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_MAX_AGE_S}"
                )
                return self._send_json(200, {"ok": True}, [("Set-Cookie", cookie_val)])

            if not self._is_authed():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})

            if path == "/api/logout":
                cookie_val = f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
                return self._send_json(200, {"ok": True}, [("Set-Cookie", cookie_val)])

            if path == "/api/toggle-enforce":
                admin = mgr.load_admin_state()
                if "enforce_enabled" in body:
                    target = bool(body["enforce_enabled"])
                else:
                    target = not bool(admin.get("enforce_enabled", False))

                cd_remain = mgr.check_cooldown()
                if cd_remain > 0:
                    return self._send_json(429, {
                        "ok": False,
                        "error": f"操作过于频繁，请 {cd_remain} 秒后再试",
                        "retry_after_s": cd_remain,
                    })

                admin["enforce_enabled"] = target
                mgr.save_admin_state(admin)

                sp = admin["saved_policy"]
                if target:
                    cid = mgr.enqueue_server_command({
                        "type": "set_policy",
                        "weekday_limit": int(sp["weekday_limit"]),
                        "weekend_limit": int(sp["weekend_limit"]),
                        "game_start": parse_hhmm_to_minutes(sp["game_start"]),
                        "bedtime": parse_hhmm_to_minutes(sp["bedtime"]),
                    })
                    pi_res = mgr.pi_sync_config(
                        enforce_mode="close",
                        weekday_limit=int(sp["weekday_limit"]),
                        weekend_limit=int(sp["weekend_limit"]),
                        curfew=[f"{sp['bedtime']}-{sp['game_start']}"] if sp["bedtime"] != sp["game_start"] else [],
                    )
                else:
                    cid = mgr.enqueue_server_command({
                        "type": "set_policy",
                        "weekday_limit": 1440,
                        "weekend_limit": 1440,
                        "game_start": 0,
                        "bedtime": 0,
                    })
                    pi_res = mgr.pi_sync_config(enforce_mode="none")

                mgr.mark_cooldown_success()
                return self._send_json(200, {
                    "ok": True,
                    "enforce_enabled": target,
                    "server": {"command_id": cid},
                    "pi": pi_res,
                    "cooldown_remaining_s": mgr.get_cooldown_remaining(),
                })

            if path == "/api/lock-now":
                cd_remain = mgr.check_cooldown()
                if cd_remain > 0:
                    return self._send_json(429, {
                        "ok": False,
                        "error": f"操作过于频繁，请 {cd_remain} 秒后再试",
                        "retry_after_s": cd_remain,
                    })

                cid = mgr.enqueue_server_command({"type": "lock_now"})
                pi_res = mgr.pi_lock_now()
                mgr.mark_cooldown_success()
                return self._send_json(200, {
                    "ok": True,
                    "server": {"command_id": cid},
                    "pi": pi_res,
                    "cooldown_remaining_s": mgr.get_cooldown_remaining(),
                })

            if path == "/api/grant":
                try:
                    mins = int(body.get("minutes", 0))
                except (TypeError, ValueError):
                    return self._send_json(400, {"ok": False, "error": "invalid_minutes"})
                if mins == 0 or mins < -60 or mins > 720:
                    return self._send_json(400, {"ok": False, "error": "minutes_out_of_range"})

                cd_remain = mgr.check_cooldown()
                if cd_remain > 0:
                    return self._send_json(429, {
                        "ok": False,
                        "error": f"操作过于频繁，请 {cd_remain} 秒后再试",
                        "retry_after_s": cd_remain,
                    })

                if mins > 0:
                    cid = mgr.enqueue_server_command({"type": "grant_minutes", "minutes": mins})
                    srv_res = {"command_id": cid}
                else:
                    srv_res = {"skipped": True, "reason": "negative_grant_pi_only"}

                pi_res = mgr.pi_grant(mins)
                mgr.mark_cooldown_success()
                return self._send_json(200, {
                    "ok": True,
                    "minutes": mins,
                    "server": srv_res,
                    "pi": pi_res,
                    "cooldown_remaining_s": mgr.get_cooldown_remaining(),
                })

            if path == "/api/policy":
                try:
                    wd = int(body["weekday_limit"])
                    we = int(body["weekend_limit"])
                    gs_str = str(body["game_start"]).strip()
                    bt_str = str(body["bedtime"]).strip()
                    gs_min = parse_hhmm_to_minutes(gs_str)
                    bt_min = parse_hhmm_to_minutes(bt_str)
                    if not (0 <= wd <= 1440 and 0 <= we <= 1440):
                        raise ValueError("limit out of range 0..1440")
                except Exception as exc:
                    return self._send_json(400, {"ok": False, "error": f"invalid_policy: {exc}"})

                cd_remain = mgr.check_cooldown()
                if cd_remain > 0:
                    return self._send_json(429, {
                        "ok": False,
                        "error": f"操作过于频繁，请 {cd_remain} 秒后再试",
                        "retry_after_s": cd_remain,
                    })

                admin = mgr.load_admin_state()
                admin["saved_policy"] = {
                    "weekday_limit": wd,
                    "weekend_limit": we,
                    "game_start": minutes_to_hhmm(gs_min),
                    "bedtime": minutes_to_hhmm(bt_min),
                }
                mgr.save_admin_state(admin)

                srv_res = {"queued": False}
                if admin.get("enforce_enabled", False):
                    cid = mgr.enqueue_server_command({
                        "type": "set_policy",
                        "weekday_limit": wd,
                        "weekend_limit": we,
                        "game_start": gs_min,
                        "bedtime": bt_min,
                    })
                    srv_res = {"queued": True, "command_id": cid}

                curfew_list = [] if gs_min == bt_min else [f"{minutes_to_hhmm(bt_min)}-{minutes_to_hhmm(gs_min)}"]
                pi_res = mgr.pi_sync_config(
                    weekday_limit=wd,
                    weekend_limit=we,
                    curfew=curfew_list,
                )
                mgr.mark_cooldown_success()
                return self._send_json(200, {
                    "ok": True,
                    "saved_policy": admin["saved_policy"],
                    "server": srv_res,
                    "pi": pi_res,
                    "cooldown_remaining_s": mgr.get_cooldown_remaining(),
                })

            if path == "/api/pin":
                cur = str(body.get("current_pin", "")).strip()
                nxt = str(body.get("new_pin", "")).strip()
                if cur:
                    if not hmac.compare_digest(cur.encode("utf-8"), mgr.admin_pin.encode("utf-8")):
                        return self._send_json(403, {"ok": False, "error": "current_pin_incorrect"})
                if not (len(nxt) == 4 and nxt.isdigit()):
                    return self._send_json(400, {"ok": False, "error": "new_pin_must_be_4_digits"})
                mgr.update_pin(nxt)
                return self._send_json(200, {"ok": True})

            return self._send_json(404, {"ok": False, "error": "not_found"})

    return WebAdminHandler


def start_web_admin_server(server_ctx, config, config_path, app_version):
    host = config.get("web_listen_host", "0.0.0.0")
    port = int(config.get("web_listen_port", 8788))
    mgr = WebAdminManager(server_ctx, config, config_path, app_version)
    handler_cls = make_http_handler(mgr)

    class ReusableThreadingHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    httpd = ReusableThreadingHTTPServer((host, port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
    t.start()
    print(f"[switch-web] listening on {host}:{port}, version={app_version}", flush=True)
    return httpd
