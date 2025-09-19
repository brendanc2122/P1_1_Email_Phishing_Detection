// --- Threshold slider: update value in real-time ---
const thresholdInput = document.getElementById('threshold');
const thresholdValue = document.getElementById('threshold-value');
const resultThreshold = document.getElementById('result-threshold');

if (thresholdInput) {
    thresholdInput.addEventListener('input', function() {
        thresholdValue.textContent = this.value;
        if (resultThreshold) resultThreshold.textContent = this.value;
    });
}

// --- Prevent form submission and show demo result ---
const form = document.querySelector('.email-form');
if (form) {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        // Generate a random score for demo purposes
        const score = Math.floor(Math.random() * 100);
        const scoreLabel = document.querySelector('.score-label');
        const breakdown = document.querySelector('.breakdown');
        const scoreContribution = document.querySelector('.score-contribution');
        if (scoreLabel) {
            scoreLabel.textContent = `Score: ${score} — ${score >= thresholdInput.value ? 'Phishy' : 'Likely Legitimate'}`;
            scoreLabel.style.fontWeight = 'bold';
            scoreLabel.style.color = score >= thresholdInput.value ? '#b91c1c' : '#15803d';
        }
        // Show fake breakdown indicators
        if (breakdown) {
            breakdown.innerHTML = `
                <h4>Breakdown (indicators)</h4>
                <ul>
                    <li>Suspicious sender: ${Math.random() > 0.5 ? 'Yes' : 'No'}</li>
                    <li>Urgent language: ${Math.random() > 0.5 ? 'Yes' : 'No'}</li>
                    <li>Links detected: ${Math.floor(Math.random() * 3)}</li>
                </ul>
            `;
        }
        // Show fake score contribution
        if (scoreContribution) {
            scoreContribution.innerHTML = `
                <h4>Score contribution</h4>
                <ul>
                    <li>Sender: ${Math.floor(Math.random() * 30)}</li>
                    <li>Subject: ${Math.floor(Math.random() * 30)}</li>
                    <li>Body: ${Math.floor(Math.random() * 40)}</li>
                </ul>
            `;
        }
    });
}

// --- Copy report to clipboard ---
const copyBtn = document.querySelector('.copy-btn');
if (copyBtn) {
    copyBtn.addEventListener('click', function() {
        const scoreLabel = document.querySelector('.score-label');
        const breakdown = document.querySelector('.breakdown');
        const scoreContribution = document.querySelector('.score-contribution');
        let text = '';
        if (scoreLabel) text += scoreLabel.textContent + '\n';
        if (breakdown) text += breakdown.innerText + '\n';
        if (scoreContribution) text += scoreContribution.innerText + '\n';
        navigator.clipboard.writeText(text.trim());
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy report'; }, 1200);
    });
}

// --- Download report as a text file ---
const downloadBtn = document.querySelector('.download-btn');
if (downloadBtn) {
    downloadBtn.addEventListener('click', function() {
        const scoreLabel = document.querySelector('.score-label');
        const breakdown = document.querySelector('.breakdown');
        const scoreContribution = document.querySelector('.score-contribution');
        let text = '';
        if (scoreLabel) text += scoreLabel.textContent + '\n';
        if (breakdown) text += breakdown.innerText + '\n';
        if (scoreContribution) text += scoreContribution.innerText + '\n';
        const blob = new Blob([text.trim()], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'phishing_report.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
}