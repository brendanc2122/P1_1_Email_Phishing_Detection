// --- sync threshold slider to labels ---
const thresholdInput = document.getElementById('threshold');
const thresholdValue = document.getElementById('threshold-value');
const resultThreshold = document.getElementById('result-threshold');

function syncThresholdLabels(v) {
  if (thresholdValue) thresholdValue.textContent = v;
  if (resultThreshold) resultThreshold.textContent = v;
}
if (thresholdInput) {
  syncThresholdLabels(thresholdInput.value);
  thresholdInput.addEventListener('input', (e) => syncThresholdLabels(e.target.value));
}

// --- form submit -> call backend /analyze ---
const form = document.querySelector('.email-form');

async function analyzeEmail(e) {
  e.preventDefault();
  const sender = document.getElementById('sender').value;
  const subject = document.getElementById('subject').value;
  const body = document.getElementById('body').value;
  const threshold = Number(document.getElementById('threshold').value);

  const res = await fetch('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender, subject, body, threshold })
  });
  const data = await res.json();

  // Update UI
  const scoreLabel = document.querySelector('.score-label');
  const breakdown = document.querySelector('.breakdown');
  const contribBox = document.querySelector('.score-contribution');

  if (scoreLabel) {
    scoreLabel.textContent =
      `Score: ${data.normalized_score}/100 (raw: ${data.raw_score}) — ${data.label}`;
    scoreLabel.style.fontWeight = 'bold';
    scoreLabel.style.color = (data.label === 'Phishing') ? '#b91c1c' : '#15803d';
  }

  if (breakdown) {
    const items = (data.reasons || []).map(r => `<li>${r}</li>`).join('');
    breakdown.innerHTML = `
      <h4>Breakdown (indicators)</h4>
      <ul>${items || '<li>No indicators</li>'}</ul>
    `;
  }

  if (contribBox) {
    const contrib = data.contrib || {};
    const items = Object.entries(contrib).map(([k, v]) => `<li>${k}: ${v}</li>`).join('');
    contribBox.innerHTML = `
      <h4>Score contribution</h4>
      <ul>${items || '<li>No contributions</li>'}</ul>
    `;
  }

  // reflect the threshold the backend actually used (UI %)
  if (typeof data.threshold_ui === 'number') {
    syncThresholdLabels(data.threshold_ui);
    if (thresholdInput) thresholdInput.value = data.threshold_ui;
  }
}

if (form) form.addEventListener('submit', analyzeEmail);

// --- Preprocess file upload ---
const preprocessForm = document.getElementById('preprocess-form');
if (preprocessForm) {
  preprocessForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    const fileInput = document.getElementById('preprocess-file');
    const statusSpan = document.getElementById('preprocess-status');
    statusSpan.textContent = 'Uploading...';

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
      const response = await fetch('/upload', {
        method: 'POST',
        body: formData
      });
      const result = await response.json();
      if (result.status === 'success') {
        statusSpan.textContent = 'Preprocessing completed!';
      } else {
        statusSpan.textContent = 'Error: ' + (result.message || 'Unknown error');
      }
    } catch (err) {
      statusSpan.textContent = 'Error: ' + err.message;
    }
  });
}

// --- Copy report ---
const copyBtn = document.querySelector('.copy-btn');
if (copyBtn) {
  copyBtn.addEventListener('click', async () => {
    const scoreLabel = document.querySelector('.score-label')?.textContent ?? '';
    const breakdown = document.querySelector('.breakdown')?.innerText ?? '';
    const contrib = document.querySelector('.score-contribution')?.innerText ?? '';
    const text = `${scoreLabel}\n\n${breakdown}\n\n${contrib}`.trim();
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = 'Copied!';
    setTimeout(() => (copyBtn.textContent = 'Copy report'), 1200);
  });
}

// --- Download report ---
const downloadBtn = document.querySelector('.download-btn');
if (downloadBtn) {
  downloadBtn.addEventListener('click', () => {
    const scoreLabel = document.querySelector('.score-label')?.textContent ?? '';
    const breakdown = document.querySelector('.breakdown')?.innerText ?? '';
    const contrib = document.querySelector('.score-contribution')?.innerText ?? '';
    const text = `${scoreLabel}\n\n${breakdown}\n\n${contrib}`.trim();
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: 'phishing_report.txt' });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
}
