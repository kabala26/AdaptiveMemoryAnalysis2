import { jsPDF } from 'jspdf'

const BRAND = 'MemShield'
const DARK  = [17,  24,  39]
const MID   = [107, 114, 128]
const LIGHT = [229, 231, 235]
const RED   = [239, 68,  68]
const GREEN = [34,  197, 94]
const AMBER = [245, 158, 11]
const BLUE  = [59,  130, 246]
const ORANGE= [249, 115,  22]

const RECOMMENDATIONS = {
  Ransomware: [
    { severity: 'critical', text: 'Immediately isolate the affected system from all networks to prevent lateral movement and further encryption.' },
    { severity: 'critical', text: 'Do NOT pay the ransom — it does not guarantee file recovery and funds criminal operations.' },
    { severity: 'high',     text: 'Preserve a full forensic image of the memory and disk before any remediation to maintain evidence integrity.' },
    { severity: 'high',     text: 'Identify the ransomware family and check for a public decryptor at nomoreransom.org before formatting.' },
    { severity: 'high',     text: 'Audit all backup systems — ransomware commonly targets and corrupts backups before encrypting primary data.' },
    { severity: 'medium',   text: 'Review Active Directory for compromised accounts; ransomware operators often move laterally via stolen credentials.' },
    { severity: 'medium',   text: 'Identify and patch the initial attack vector (phishing, exposed RDP, unpatched vulnerability) before restoring.' },
    { severity: 'low',      text: 'After recovery, enforce the 3-2-1 backup rule and test restores regularly to minimise future ransomware impact.' },
  ],
  Spyware: [
    { severity: 'critical', text: 'Assume all credentials entered on this system are compromised — rotate passwords and invalidate all active sessions immediately.' },
    { severity: 'critical', text: 'Audit outbound network connections for data exfiltration to command-and-control servers.' },
    { severity: 'high',     text: 'Revoke and reissue any API keys, certificates, or tokens that may have been stored or used on this machine.' },
    { severity: 'high',     text: 'Enable multi-factor authentication on all accounts that were accessible from the infected system.' },
    { severity: 'high',     text: 'Review browser saved passwords, autofill data, and stored payment information — spyware commonly harvests these.' },
    { severity: 'medium',   text: 'Inspect scheduled tasks, startup entries, and registry run keys for persistence mechanisms.' },
    { severity: 'medium',   text: 'Notify affected users and, if regulated data was accessed, consider GDPR/HIPAA breach notification obligations.' },
    { severity: 'low',      text: 'Deploy endpoint DLP (Data Loss Prevention) to detect and block future exfiltration attempts.' },
  ],
  Trojan: [
    { severity: 'critical', text: 'Assume the system has an active backdoor — disconnect from the network and treat all data as potentially exfiltrated.' },
    { severity: 'critical', text: 'Check for additional payloads — Trojans commonly drop secondary malware (ransomware, keyloggers, cryptominers).' },
    { severity: 'high',     text: 'Audit all user accounts on the system for unauthorised privilege escalation or new accounts created by the attacker.' },
    { severity: 'high',     text: 'Examine firewall and proxy logs for outbound C2 communication channels and block identified IOCs at the perimeter.' },
    { severity: 'high',     text: 'Scan all systems that communicated with this host — Trojans are commonly used as a beachhead for network-wide compromise.' },
    { severity: 'medium',   text: 'Review persistence locations: registry Run keys, scheduled tasks, WMI subscriptions, and service installations.' },
    { severity: 'medium',   text: 'Rebuild the system from a known-good image rather than attempting in-place disinfection.' },
    { severity: 'low',      text: 'Implement application whitelisting to prevent unauthorised executable deployment in future incidents.' },
  ],
}

const SEVERITY_COLORS = { critical: RED, high: ORANGE, medium: AMBER, low: BLUE }

function checkPage(doc, y, needed = 20) {
  if (y + needed > doc.internal.pageSize.getHeight() - 20) {
    doc.addPage()
    return 18
  }
  return y
}

function section(doc, y, label) {
  y = checkPage(doc, y, 14)
  // thin rule + label
  doc.setDrawColor(...LIGHT)
  doc.setLineWidth(0.4)
  doc.line(14, y, 196, y)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(7.5)
  doc.setTextColor(...MID)
  doc.text(label.toUpperCase(), 14, y + 6)
  return y + 11
}

function kv(doc, y, label, value, valueColor, note) {
  y = checkPage(doc, y)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8.5)
  doc.setTextColor(...MID)
  doc.text(label, 14, y)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(...(valueColor || DARK))
  doc.text(String(value ?? '—'), 80, y)
  if (note) {
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7.5)
    doc.setTextColor(...MID)
    doc.text(note, 120, y)
  }
  return y + 6.5
}

function barRow(doc, y, label, pct, color) {
  y = checkPage(doc, y)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8.5)
  doc.setTextColor(...DARK)
  doc.text(label, 14, y)
  doc.setFillColor(...LIGHT)
  doc.roundedRect(80, y - 3.5, 90, 4.5, 1, 1, 'F')
  doc.setFillColor(...color)
  doc.roundedRect(80, y - 3.5, Math.max(1, 90 * pct), 4.5, 1, 1, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(8)
  doc.setTextColor(...MID)
  doc.text(`${(pct * 100).toFixed(1)}%`, 174, y)
  return y + 7.5
}

function footer(doc) {
  const H = doc.internal.pageSize.getHeight()
  const W = doc.internal.pageSize.getWidth()
  doc.setDrawColor(...LIGHT)
  doc.setLineWidth(0.3)
  doc.line(14, H - 14, W - 14, H - 14)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.setTextColor(...MID)
  doc.text(`${BRAND} · Forensic Memory Analysis System`, 14, H - 8)
  doc.text('CONFIDENTIAL', W - 14, H - 8, { align: 'right' })
}

export async function downloadReportPdf(dump, fetchDetails) {
  let result = null
  if (fetchDetails) {
    try { result = await fetchDetails(dump.dump_id) } catch (_) {}
  }

  const fd               = result?.feature_data     || null
  const categoryRankings = result?.category_rankings || []
  const familyRankings   = result?.family_rankings   || []
  const malwareFamily    = result?.malware_family    || dump.malware_family    || null
  const malwareCategory  = result?.malware_category  || dump.malware_category  || null
  const familyConf       = result?.family_confidence   ?? dump.family_confidence   ?? null
  const categoryConf     = result?.category_confidence ?? dump.category_confidence ?? null
  const isM              = dump.prediction === 'Malware'

  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const W   = doc.internal.pageSize.getWidth()
  let y     = 18

  // ── Title ────────────────────────────────────────────────────────────────
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(18)
  doc.setTextColor(...DARK)
  doc.text(BRAND, 14, y)

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(...MID)
  doc.text('Forensic Memory Analysis Report', 14, y + 7)
  doc.text(`Generated: ${new Date().toLocaleString()}`, W - 14, y + 7, { align: 'right' })

  // thin rule under title
  y += 12
  doc.setDrawColor(...DARK)
  doc.setLineWidth(0.6)
  doc.line(14, y, W - 14, y)
  y += 10

  // ── Verdict ───────────────────────────────────────────────────────────────
  const conf = dump.confidence != null ? (dump.confidence * 100).toFixed(1) + '%' : '—'
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(22)
  doc.setTextColor(...(isM ? RED : GREEN))
  doc.text(dump.prediction ?? 'PENDING', 14, y)

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(10)
  doc.setTextColor(...MID)
  doc.text(`Confidence: ${conf}`, 14, y + 8)

  if (malwareFamily || malwareCategory) {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(13)
    doc.setTextColor(...DARK)
    doc.text(malwareFamily || malwareCategory, W - 14, y, { align: 'right' })
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8.5)
    doc.setTextColor(...MID)
    const sub = [
      malwareFamily && malwareCategory ? malwareCategory : null,
      familyConf != null ? `${(familyConf * 100).toFixed(1)}% family confidence` : categoryConf != null ? `${(categoryConf * 100).toFixed(1)}% confidence` : null,
    ].filter(Boolean).join(' · ')
    if (sub) doc.text(sub, W - 14, y + 8, { align: 'right' })
  }

  y += 18

  // ── Classification rankings ───────────────────────────────────────────────
  if (isM && (categoryRankings.length > 0 || familyRankings.length > 0)) {
    if (categoryRankings.length > 0) {
      y = section(doc, y, 'Malware Category Probabilities')
      categoryRankings.slice(0, 6).forEach(({ category, confidence }) => {
        y = barRow(doc, y, category, confidence, AMBER)
      })
      y += 3
    }
    if (familyRankings.length > 0) {
      y = section(doc, y, 'Malware Family Probabilities')
      familyRankings.slice(0, 8).forEach(({ family, confidence }) => {
        y = barRow(doc, y, family, confidence, RED)
      })
      y += 3
    }
  }

  // ── File information ──────────────────────────────────────────────────────
  y = section(doc, y, 'File Information')
  y = kv(doc, y, 'Filename',  dump.file_name)
  y = kv(doc, y, 'Dump ID',   dump.dump_id)
  y = kv(doc, y, 'Size',      dump.file_size != null ? (dump.file_size / 1024 / 1024).toFixed(2) + ' MB' : '—')
  y = kv(doc, y, 'Uploaded',  dump.upload_date ? new Date(dump.upload_date).toLocaleString() : '—')
  y = kv(doc, y, 'Analysed',  dump.classification_date ? new Date(dump.classification_date).toLocaleString() : '—')
  y = kv(doc, y, 'SHA-256',   dump.hash_value || '—')
  y += 3

  // ── Forensic breakdown ────────────────────────────────────────────────────
  if (fd) {
    const s      = fd.summary || {}
    const proc   = fd.process_features || {}
    const dlls   = fd.dll_features || {}
    const mem    = fd.memory_region_features || {}
    const hdl    = fd.handle_features || {}
    const beh    = fd.behavioral_indicators || {}
    const errors = fd.errors || []

    const hiddenProc = s.hidden_processes ?? proc.hidden_count ?? 0
    const suspdlls   = s.suspicious_dlls  ?? dlls.suspicious_paths_count ?? 0
    const rwx        = s.rwx_regions      ?? mem.rwx_count ?? 0
    const malfind    = s.malfind_hits     ?? beh.malfind_count ?? 0
    const nsvcs      = s.nservices        ?? 0
    const risk       = s.risk_score       ?? null

    y = section(doc, y, 'Forensic Breakdown')
    y = kv(doc, y, 'Processes (total)',  s.process_count ?? proc.total_count ?? '—')
    y = kv(doc, y, 'Hidden processes',   hiddenProc,
      hiddenProc > 0 ? RED : GREEN,
      hiddenProc > 0 ? 'DKOM — processes unlinked from EPROCESS list' : 'None detected')
    y = kv(doc, y, 'DLLs loaded',        s.dll_count ?? dlls.total_loaded ?? '—')
    y = kv(doc, y, 'Suspicious DLLs',    suspdlls,
      suspdlls > 0 ? RED : GREEN,
      suspdlls > 0 ? 'DLLs loaded from Temp / AppData / Downloads' : 'None detected')
    y = kv(doc, y, 'RWX memory regions', rwx,
      rwx > 100 ? RED : rwx > 0 ? AMBER : GREEN,
      rwx > 0 ? 'Read-Write-Execute — shellcode staging area' : 'None detected')
    y = kv(doc, y, 'Malfind hits',       malfind,
      malfind > 0 ? RED : GREEN,
      malfind > 0 ? 'Code injection confirmed — executable private memory with MZ header' : 'No injection detected')
    y = kv(doc, y, 'Active services',    nsvcs,
      nsvcs > 500 ? AMBER : null,
      nsvcs > 500 ? 'Elevated — review for malicious service installations' : '')
    y = kv(doc, y, 'Total handles',      s.total_handles ?? hdl.total_handles ?? '—')
    y = kv(doc, y, 'Risk score',
      risk != null ? `${risk.toFixed(2)} / 1.00` : '—',
      risk >= 0.7 ? RED : risk >= 0.4 ? AMBER : GREEN,
      risk >= 0.7 ? 'High risk' : risk >= 0.4 ? 'Moderate risk' : 'Low risk')
    y += 3

    y = section(doc, y, 'Plugin Execution Status')
    if (errors.length === 0) {
      y = checkPage(doc, y)
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8.5)
      doc.setTextColor(...GREEN)
      doc.text('All Volatility plugins completed — full feature set used for classification.', 14, y)
      y += 8
    } else {
      errors.forEach(e => {
        y = checkPage(doc, y)
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(8.5)
        doc.setTextColor(...AMBER)
        doc.text(`${e.split(':')[0]} — timed out and skipped`, 14, y)
        y += 5
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(7.5)
        doc.setTextColor(...MID)
        doc.text('Features from this plugin are absent; classification confidence may be lower than expected.', 14, y)
        y += 7
      })
    }
    y += 3
  }

  // ── Security recommendations ──────────────────────────────────────────────
  if (isM) {
    const recs = RECOMMENDATIONS[malwareCategory] || RECOMMENDATIONS['Trojan']
    y = section(doc, y, `Security Recommendations — ${malwareCategory || 'Malware'} Response`)
    recs.forEach(rec => {
      y = checkPage(doc, y, 16)
      const color = SEVERITY_COLORS[rec.severity] || MID
      doc.setFillColor(...color)
      doc.roundedRect(14, y - 3.5, 17, 5, 1, 1, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(6)
      doc.setTextColor(255, 255, 255)
      doc.text(rec.severity.toUpperCase(), 22.5, y, { align: 'center' })
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8.5)
      doc.setTextColor(...DARK)
      const lines = doc.splitTextToSize(rec.text, 148)
      doc.text(lines, 34, y)
      y += lines.length * 5 + 4
    })
  }

  // ── Footer on every page ──────────────────────────────────────────────────
  const total = doc.internal.getNumberOfPages()
  for (let i = 1; i <= total; i++) {
    doc.setPage(i)
    footer(doc)
    if (total > 1) {
      const H = doc.internal.pageSize.getHeight()
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(7)
      doc.setTextColor(...MID)
      doc.text(`Page ${i} of ${total}`, W / 2, H - 8, { align: 'center' })
    }
  }

  doc.save(`memshield-report-${dump.dump_id.slice(0, 8)}.pdf`)
}
