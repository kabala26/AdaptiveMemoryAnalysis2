import { jsPDF } from 'jspdf'

const BRAND   = 'MemShield'
const PRIMARY = [234, 179, 8]   // amber-500
const DARK    = [17,  24,  39]  // gray-900
const MID     = [107, 114, 128] // gray-500
const LIGHT   = [229, 231, 235] // gray-200
const RED     = [239, 68,  68]
const GREEN   = [34,  197, 94]
const AMBER   = [245, 158, 11]

function section(doc, y, label) {
  doc.setFillColor(245, 245, 245)
  doc.rect(14, y, 182, 7, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(8)
  doc.setTextColor(...MID)
  doc.text(label.toUpperCase(), 16, y + 5)
  return y + 12
}

function kv(doc, y, label, value, valueColor) {
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(...MID)
  doc.text(label, 16, y)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(...(valueColor || DARK))
  doc.text(String(value ?? '—'), 82, y)
  return y + 7
}

function barRow(doc, y, label, pct, color) {
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.setTextColor(...DARK)
  doc.text(label, 16, y)
  // background bar
  doc.setFillColor(...LIGHT)
  doc.roundedRect(82, y - 4, 80, 5, 1, 1, 'F')
  // filled bar
  doc.setFillColor(...color)
  doc.roundedRect(82, y - 4, Math.max(1, 80 * pct), 5, 1, 1, 'F')
  // pct label
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(8)
  doc.setTextColor(...MID)
  doc.text(`${(pct * 100).toFixed(1)}%`, 165, y)
  return y + 8
}

export async function downloadReportPdf(dump, fetchDetails) {
  // Fetch full result data (includes rankings + feature_data)
  let result = null
  if (fetchDetails) {
    try {
      result = await fetchDetails(dump.dump_id)
    } catch (_) {}
  }

  const fd              = result?.feature_data || null
  const categoryRankings = result?.category_rankings || []
  const familyRankings   = result?.family_rankings   || []
  const malwareFamily    = result?.malware_family    || dump.malware_family    || null
  const malwareCategory  = result?.malware_category  || dump.malware_category  || null
  const familyConf       = result?.family_confidence != null ? result.family_confidence
                         : dump.family_confidence != null    ? dump.family_confidence : null
  const categoryConf     = result?.category_confidence != null ? result.category_confidence
                         : dump.category_confidence != null    ? dump.category_confidence : null

  const doc  = new jsPDF({ unit: 'mm', format: 'a4' })
  const W    = doc.internal.pageSize.getWidth()
  let y      = 0

  // ── Header bar ──────────────────────────────────────────────────────────
  doc.setFillColor(...PRIMARY)
  doc.rect(0, 0, W, 28, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(18)
  doc.setTextColor(255, 255, 255)
  doc.text(BRAND, 14, 13)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(9)
  doc.setTextColor(255, 255, 220)
  doc.text('Forensic Memory Analysis Report', 14, 21)
  doc.setFontSize(8)
  doc.text(`Generated: ${new Date().toLocaleString()}`, W - 14, 21, { align: 'right' })
  y = 36

  // ── Verdict banner ───────────────────────────────────────────────────────
  const isM  = dump.prediction === 'Malware'
  const conf = dump.confidence != null ? (dump.confidence * 100).toFixed(1) + '%' : '—'
  doc.setFillColor(...(isM ? RED : GREEN))
  doc.roundedRect(14, y, 182, 20, 3, 3, 'F')
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(16)
  doc.setTextColor(255, 255, 255)
  doc.text(dump.prediction ?? 'PENDING', 22, y + 9)
  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.text(`Overall confidence: ${conf}`, 22, y + 16)
  // Family on right
  if (malwareFamily) {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(12)
    doc.text(malwareFamily, W - 20, y + 9, { align: 'right' })
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    const famConfStr = familyConf != null ? `${(familyConf * 100).toFixed(1)}% confidence` : ''
    const catStr     = malwareCategory ? `${malwareCategory}${famConfStr ? ' · ' + famConfStr : ''}` : famConfStr
    if (catStr) doc.text(catStr, W - 20, y + 16, { align: 'right' })
  } else if (malwareCategory) {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(11)
    doc.text(malwareCategory, W - 20, y + 9, { align: 'right' })
    if (categoryConf != null) {
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8)
      doc.text(`${(categoryConf * 100).toFixed(1)}% confidence`, W - 20, y + 16, { align: 'right' })
    }
  }
  y += 28

  // ── Malware family classification ────────────────────────────────────────
  if (isM && (familyRankings.length > 0 || categoryRankings.length > 0)) {
    if (categoryRankings.length > 0) {
      y = section(doc, y, 'Malware Category Probabilities')
      categoryRankings.slice(0, 6).forEach(({ category, confidence }) => {
        y = barRow(doc, y, category, confidence, AMBER)
      })
      y += 2
    }

    if (familyRankings.length > 0) {
      y = section(doc, y, 'Malware Family Probabilities')
      familyRankings.slice(0, 8).forEach(({ family, confidence }) => {
        y = barRow(doc, y, family, confidence, RED)
      })
      y += 2
    }
  }

  // ── File information ─────────────────────────────────────────────────────
  y = section(doc, y, 'File Information')
  y = kv(doc, y, 'Filename',   dump.file_name)
  y = kv(doc, y, 'Dump ID',    dump.dump_id)
  y = kv(doc, y, 'Size',       dump.file_size != null ? (dump.file_size / 1024 / 1024).toFixed(2) + ' MB' : '—')
  y = kv(doc, y, 'Uploaded',   dump.upload_date ? new Date(dump.upload_date).toLocaleString() : '—')
  y = kv(doc, y, 'Analysed',   dump.classification_date ? new Date(dump.classification_date).toLocaleString() : '—')
  y = kv(doc, y, 'SHA-256',    dump.hash_value || '—')
  y += 4

  // ── Forensic metrics ─────────────────────────────────────────────────────
  if (fd) {
    const s    = fd.summary || {}
    const proc = fd.process_features || {}
    const dlls = fd.dll_features || {}
    const mem  = fd.memory_region_features || {}
    const hdl  = fd.handle_features || {}
    const beh  = fd.behavioral_indicators || {}

    y = section(doc, y, 'Forensic Metrics')
    const hiddenProc = s.hidden_processes ?? proc.hidden_count ?? 0
    const suspdlls   = s.suspicious_dlls  ?? dlls.suspicious_paths_count ?? 0
    const rwx        = s.rwx_regions      ?? mem.rwx_count ?? 0
    const malfind    = s.malfind_hits     ?? beh.malfind_count ?? 0

    y = kv(doc, y, 'Processes (total)',   s.process_count ?? proc.total_count)
    y = kv(doc, y, 'Hidden processes',    hiddenProc, hiddenProc ? RED : GREEN)
    y = kv(doc, y, 'DLLs loaded',         s.dll_count ?? dlls.total_loaded)
    y = kv(doc, y, 'Suspicious DLLs',     suspdlls,   suspdlls  ? RED : GREEN)
    y = kv(doc, y, 'RWX memory regions',  rwx,        rwx       ? RED : GREEN)
    y = kv(doc, y, 'Malfind hits',        malfind,    malfind   ? RED : GREEN)
    y = kv(doc, y, 'Total handles',       s.total_handles ?? hdl.total_handles)
    y = kv(doc, y, 'Risk score',          s.risk_score != null ? s.risk_score.toFixed(2) : '—')
    y += 4

    const errors = fd.errors || []
    if (errors.length) {
      y = section(doc, y, 'Skipped Plugins')
      errors.forEach(e => {
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(8)
        doc.setTextColor(...MID)
        doc.text(`• ${e}`, 16, y)
        y += 6
      })
      y += 2
    }
  }

  // ── Footer ───────────────────────────────────────────────────────────────
  const pageH = doc.internal.pageSize.getHeight()
  doc.setDrawColor(...LIGHT)
  doc.setLineWidth(0.3)
  doc.line(14, pageH - 16, W - 14, pageH - 16)
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.setTextColor(...MID)
  doc.text(`${BRAND} · Adaptive Memory Analysis System`, 14, pageH - 10)
  doc.text('CONFIDENTIAL', W - 14, pageH - 10, { align: 'right' })

  doc.save(`memshield-report-${dump.dump_id.slice(0, 8)}.pdf`)
}
