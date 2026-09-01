---
icon: fas fa-info-circle
order: 4
---

<style>
.cv {
  --cv-accent: #ff4d6a;
  --cv-mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
}
html[data-mode="light"] .cv { --cv-accent: #b8002e; }

/* ---- Intro ---- */
.cv .cv-head {
  display: flex;
  gap: 1.75rem;
  align-items: flex-start;
}
.cv .cv-head .avatar {
  width: 92px;
  height: 92px;
  border-radius: 50%;
  object-fit: cover;
  flex-shrink: 0;
  border: 1px solid var(--main-border-color);
  transition: border-color 0.25s ease;
}
.cv .cv-head .avatar:hover { border-color: var(--cv-accent); }
.cv .cv-head h1 {
  margin: 0 0 0.15rem;
  font-size: 1.7rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--heading-color);
}
.cv .cv-head .role {
  margin: 0 0 0.7rem;
  color: var(--cv-accent);
  font-family: var(--cv-mono);
  font-size: 0.82rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.cv .cv-head .bio { margin: 0; }

/* ---- Section headings: short accent tick under a plain title ---- */
.cv h2 {
  position: relative;
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--heading-color);
  margin: 3rem 0 1rem;
  padding-bottom: 0.55rem;
  border-bottom: 1px solid var(--main-border-color);
}
.cv h2::after {
  content: "";
  position: absolute;
  left: 0;
  bottom: -1px;
  width: 2.25rem;
  height: 2px;
  background: var(--cv-accent);
}

/* ---- Education: name left, period right ---- */
.cv .simple-row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 1.5rem;
  padding: 0.4rem 0;
}
.cv .simple-row .name {
  font-weight: 600;
  color: var(--heading-color);
}
.cv .simple-row .sub {
  display: block;
  color: var(--text-muted-color);
  font-weight: 400;
}
.cv .simple-row .period {
  font-family: var(--cv-mono);
  font-size: 0.82rem;
  color: var(--text-muted-color);
  white-space: nowrap;
}

/* ---- Scoreboard ---- */
.cv .board { display: flex; flex-direction: column; }
.cv .board-head,
.cv .board-row {
  display: grid;
  grid-template-columns: 4rem 1fr minmax(0, 12rem) 3.25rem;
  gap: 1rem;
  align-items: baseline;
}
.cv .board-head {
  font-family: var(--cv-mono);
  font-size: 0.68rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-muted-color);
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--main-border-color);
}
.cv .board-row {
  padding: 0.7rem 0;
  border-bottom: 1px solid var(--main-border-color);
}
.cv .board-row:last-child { border-bottom: none; }
.cv .board .rank {
  font-family: var(--cv-mono);
  font-variant-numeric: tabular-nums;
  font-size: 0.95rem;
  color: var(--text-muted-color);
}
.cv .board .rank.top {
  color: var(--cv-accent);
  font-weight: 600;
}
.cv .board .rank.na { font-size: 0.7rem; letter-spacing: 0.1em; }
.cv .board .event { color: var(--heading-color); font-weight: 600; }
.cv .board .team { color: var(--text-muted-color); }
.cv .board .year {
  font-family: var(--cv-mono);
  font-variant-numeric: tabular-nums;
  font-size: 0.82rem;
  color: var(--text-muted-color);
  text-align: right;
}

/* ---- Disclosures ---- */
.cv .vulns { display: flex; flex-direction: column; }
.cv .vuln-head,
.cv .vuln-row {
  display: grid;
  grid-template-columns: 10.5rem 1fr 3.25rem;
  gap: 1rem;
  align-items: baseline;
}
.cv .vuln-head {
  font-family: var(--cv-mono);
  font-size: 0.68rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text-muted-color);
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--main-border-color);
}
.cv .vuln-row {
  padding: 0.7rem 0;
  border-bottom: 1px solid var(--main-border-color);
}
.cv .vuln-row:last-child { border-bottom: none; }
.cv .vuln-row .cve {
  font-family: var(--cv-mono);
  font-size: 0.85rem;
  white-space: nowrap;
}
/* No CVE ID assigned yet — reported / pending */
.cv .vuln-row .cve.na {
  font-size: 0.68rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-muted-color);
}
.cv .vuln-row .target { color: var(--heading-color); font-weight: 600; }
.cv .vuln-row .desc {
  display: block;
  font-weight: 400;
  color: var(--text-muted-color);
  font-size: 0.92rem;
}
.cv .vuln-row .desc code {
  font-family: var(--cv-mono);
  font-size: 0.85em;
}
.cv .vuln-row .year {
  font-family: var(--cv-mono);
  font-variant-numeric: tabular-nums;
  font-size: 0.82rem;
  color: var(--text-muted-color);
  text-align: right;
}

/* ---- Contact ---- */
.cv .contact {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem 1.75rem;
}
.cv .contact .label {
  color: var(--text-muted-color);
  font-family: var(--cv-mono);
  font-size: 0.7rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-right: 0.45rem;
}

@media (max-width: 768px) {
  .cv .cv-head { flex-direction: column; gap: 1.1rem; }
  .cv .cv-head .avatar { width: 78px; height: 78px; }
  .cv .simple-row { flex-direction: column; gap: 0.15rem; }
  .cv .board-head { display: none; }
  .cv .board-row {
    grid-template-columns: 4rem 1fr;
    gap: 0.15rem 1rem;
  }
  .cv .board .event { grid-column: 2; }
  .cv .board .team  { grid-column: 2; }
  .cv .board .year  { grid-column: 2; text-align: left; }
  .cv .vuln-head { display: none; }
  .cv .vuln-row {
    grid-template-columns: 1fr;
    gap: 0.15rem;
  }
  .cv .vuln-row .year { text-align: left; }
}
</style>

<div class="cv" markdown="0">

<div class="cv-head">
  <img src="/assets/img/profile.jpg" alt="storm" class="avatar">
  <div>
    <h1>storm</h1>
    <p class="role">Windows Kernel · System Security Research</p>
    <p class="bio">
      Cyber Security undergraduate at Ajou University. I work on Windows kernel and system
      security — 1-day analysis, exploit development, and vulnerability discovery. This blog
      documents what I study and build along the way.
    </p>
  </div>
</div>

<h2>Education</h2>
<div class="simple-row">
  <div>
    <span class="name">Ajou University, Suwon</span>
    <span class="sub">B.S. in Cyber Security</span>
  </div>
  <div class="period">2022 — now</div>
</div>

<h2>Competitions</h2>
<div class="board">
  <div class="board-head">
    <span>Rank</span><span>Event</span><span>Team</span><span>Year</span>
  </div>
  <div class="board-row">
    <span class="rank">8th</span>
    <span class="event">UofTCTF</span>
    <span class="team">RubiyaLab</span>
    <span class="year">2026</span>
  </div>
    <div class="board-row">
    <span class="rank na">FINAL</span>
    <span class="event">INCOGNITO CTF</span>
    <span class="team">일단 조니워커 블랙을 마셔봐</span>
    <span class="year">2026</span>
  </div>
    <div class="board-row">
    <span class="rank top">1st</span>
    <span class="event">HyperSonic CTF</span>
    <span class="team">Whois</span>
    <span class="year">2026</span>
  </div>
  <div class="board-row">
    <span class="rank">9th</span>
    <span class="event">KISIA 정보보호 경진대회</span>
    <span class="team">Whois</span>
    <span class="year">2026</span>
  </div>

  <div class="board-row">
    <span class="rank na">FINAL</span>
    <span class="event">HACKSIUM BUSAN</span>
    <span class="team">일단 조니워커 블루를 마셔봐</span>
    <span class="year">2026</span>
  </div>
</div>

<h2>Disclosures</h2>
<!--
  One .vuln-row per finding, strongest public evidence first.
  Column 1 carries the CVE ID when there is one, otherwise a status:
  <span class="cve na">Reported</span> / "CVE pending" / a linked "Fixed".
-->
<div class="vulns">
  <div class="vuln-head">
    <span>ID / Status</span><span>Issue</span><span>Year</span>
  </div>
  <div class="vuln-row">
    <span class="cve"><a href="https://www.cve.org/CVERecord?id=CVE-2026-6791" target="_blank" rel="noopener">CVE-2026-6791</a></span>
    <span class="target">GNU glibc — Stack Clash in Tilde Expansion
      <span class="desc"><code>strndupa</code> puts an attacker-controlled username length on the stack while <code>wordexp()</code> expands a tilde path, exhausting the thread stack. Credited as finder on the CVE record (<a href="https://sourceware.org/bugzilla/show_bug.cgi?id=34091" target="_blank" rel="noopener">bug 34091</a>).</span>
    </span>
    <span class="year">2026</span>
  </div>
  <div class="vuln-row">
    <span class="cve"><a href="https://www.cve.org/CVERecord?id=CVE-2026-44663" target="_blank" rel="noopener">CVE-2026-44663</a></span>
    <span class="target">OpenEXR — Integer Overflow to Heap Buffer Overflow
      <span class="desc">Three unguarded multiplications in the HTJ2K decoder, found by patch-gap analysis against the CVE-2026-34378…34589 fixes. Demonstrated with a 788-byte PoC; fixed in 3.4.12 (<a href="https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-777r-f9x8-7r84" target="_blank" rel="noopener">advisory</a>).</span>
    </span>
    <span class="year">2026</span>
  </div>
  <div class="vuln-row">
    <span class="cve na"><a href="https://www.bandisoft.com/bandizip/history/" target="_blank" rel="noopener">Fixed</a></span>
    <span class="target">Bandisoft Bandizip — Integer Overflow to Buffer Overflow
      <span class="desc">Size fields on the PAX and GNU LongLink long-filename paths wrap on an int32 cast in the TAR parser. Fixed in v7.42, credited in the release notes.</span>
    </span>
    <span class="year">2026</span>
  </div>
  <div class="vuln-row">
    <span class="cve na">Rewarded</span>
    <span class="target">AhnLab V3 Lite — Authentication Bypass
      <span class="desc">Referer-based authentication on a SYSTEM-privileged local HTTP API is bypassable, leading to system file disclosure and AV evasion. KISA bug bounty program, 2026 Q2.</span>
    </span>
    <span class="year">2026</span>
  </div>
  <div class="vuln-row">
    <span class="cve na">Acknowledged</span>
    <span class="target">Google jpegli — Uncontrolled Memory Allocation
      <span class="desc">Patch-gap variant: the <code>SafeMul</code> guards added in commit <code>7cdf212</code> never reached the EXR decoder, so a 329-byte file still drives a 15 GB allocation and aborts the process. Confirmed a valid product vulnerability by Google OSS VRP.</span>
    </span>
    <span class="year">2026</span>
  </div>
</div>

<h2>Contact</h2>
<div class="contact">
  <div><span class="label">email</span><a href="mailto:rhwnsdyd1112@gmail.com">rhwnsdyd1112@gmail.com</a></div>
  <div><span class="label">github</span><a href="https://github.com/storm-0rigin" target="_blank" rel="noopener">@storm-0rigin</a></div>
  <div><span class="label">linkedin</span><a href="https://www.linkedin.com/in/junyong-ko-052b1b419" target="_blank" rel="noopener">JunYong-Ko</a></div>
  <div><span class="label">loc</span>Suwon, Korea</div>
</div>

</div>
