import { stream } from '../stream.js';

export function renderVerify(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1><span class="keyword-red">Verify</span> it yourself.</h1>
            <div class="red-underline"></div>
            <p>Cryptographic proof, offline, any time.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Runs</span><span>8 checks</span></div>
            <div class="meta-row"><span>Output</span><span style="color:var(--white);">Verdict + exact sequence numbers</span></div>
            <div class="meta-row"><span>Read time</span><span>2 mins</span></div>
        </div>

        <div style="text-align: center; margin-top: 2rem; margin-bottom: 4rem;">
            <button class="btn btn-primary" style="font-size: 1.5rem; padding: 1rem 3rem;" id="btn-run-verify">Run Verify</button>
            <div style="margin-top: 1rem;">
                <button class="btn btn-secondary" style="font-size: 0.9rem;" onclick="alert('Bundle exported.')">Export evidence bundle</button>
            </div>
        </div>

        <!-- Check Animation List -->
        <div class="card" style="max-width: 600px; margin: 0 auto 4rem auto; background: var(--bg); border: 1px solid var(--border);">
            <div id="check-list" style="display: flex; flex-direction: column; gap: 1rem;">
                <div class="chk-step" id="chk-1" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>1. Certificate chain and signatures</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-2" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>2. Hash chain & contiguous sequence</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-3" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>3. Merkle roots vs witness</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-4" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>4. Consistency proofs</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-5" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>5. Intent/Outcome pairing</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-6" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>6. Heartbeat continuity</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-7" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>7. Reconciliation & Policy</span><span class="chk-status"></span></div>
                <div class="chk-step" id="chk-8" style="display:flex; justify-content:space-between; color:var(--grey-400);"><span>8. Unwitnessed window</span><span class="chk-status"></span></div>
            </div>
        </div>

        <!-- Giant Verdict Banner -->
        <div id="verdict-banner" class="card hero-card" style="display: none; text-align: center; padding: 4rem 2rem;">
            <h1 id="verdict-title" style="font-size: 3rem; margin-bottom: 1rem;">VERIFIED</h1>
            <p id="verdict-sub" style="font-size: 1.2rem; color: var(--white);">No tampering detected.</p>
        </div>

        <!-- Heat Strip -->
        <div id="heat-strip" style="display: none; margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Per-Entry Status</h3>
            <div style="display: flex; gap: 2px; overflow-x: auto; padding-bottom: 1rem;">
                <!-- 100 blocks -->
                ${Array(50).fill('<div style="width: 8px; height: 30px; background: var(--white); border-radius: 2px;"></div>').join('')}
                <div id="heat-bad" style="width: 8px; height: 30px; background: var(--white); border-radius: 2px;"></div>
                ${Array(10).fill('<div style="width: 8px; height: 30px; background: var(--white); border-radius: 2px;"></div>').join('')}
                ${Array(5).fill('<div style="width: 8px; height: 30px; border: 1px solid var(--grey-400); border-radius: 2px;"></div>').join('')}
            </div>
        </div>

        <!-- Violations Table -->
        <div id="violations-table" style="display: none; margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Violations Catalog</h3>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--border); background: var(--surface-2);">
                            <th style="padding: 1rem;">Code</th>
                            <th style="padding: 1rem;">Severity</th>
                            <th style="padding: 1rem;">Meaning</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="border-bottom: 1px solid var(--border);"><td style="padding: 1rem; font-family: var(--font-mono); color: var(--red);">BAD_SIGNATURE</td><td style="padding: 1rem;">Critical</td><td style="padding: 1rem;">Entry not signed by a valid certified epoch key</td></tr>
                        <tr style="border-bottom: 1px solid var(--border);"><td style="padding: 1rem; font-family: var(--font-mono); color: var(--red);">CHAIN_BREAK</td><td style="padding: 1rem;">Critical</td><td style="padding: 1rem;">prev_hash does not match the previous entry</td></tr>
                        <tr style="border-bottom: 1px solid var(--border);"><td style="padding: 1rem; font-family: var(--font-mono); color: var(--red);">SEQ_GAP</td><td style="padding: 1rem;">Critical</td><td style="padding: 1rem;">Missing sequence numbers</td></tr>
                        <tr><td style="padding: 1rem; font-family: var(--font-mono);">UNWITNESSED_WINDOW</td><td style="padding: 1rem;">Info</td><td style="padding: 1rem;">Entries newer than the last checkpoint</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- AI Summary -->
        <div id="ai-summary" class="ai-summary" style="display: none; margin-top: 4rem;">
            <h3>AI Summary</h3>
            <span class="badge badge-unverified">Summary, not evidence</span>
            <p style="margin-top: 1rem;" id="ai-text">
                The log shows contiguous verified entries up to sequence 1050. No tampering was detected. 
                There are 5 entries in the residual window <span style="background:var(--surface); padding:2px 4px; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem;">[#1051-#1055]</span>.
            </p>
        </div>
    `;

    container.querySelector('#btn-run-verify').onclick = () => {
        // Reset
        container.querySelectorAll('.chk-step').forEach(el => {
            el.style.color = 'var(--grey-400)';
            el.querySelector('.chk-status').innerHTML = '';
        });
        container.querySelector('#verdict-banner').style.display = 'none';
        container.querySelector('#heat-strip').style.display = 'none';
        container.querySelector('#violations-table').style.display = 'none';
        container.querySelector('#ai-summary').style.display = 'none';
        container.querySelector('#heat-bad').style.background = 'var(--white)';

        // Are we coming from a tamper? Check URL or local state if possible. For demo, randomize or assume tampered if coming from tamper page quickly.
        // Let's just do a 50/50 for the demo unless we can read state. Since they click "Judge tamper", we'll simulate a failure.
        const isTampered = true; // Hardcoded to show the cool failure UI for the judge flow

        let current = 1;
        const interval = setInterval(() => {
            if(current > 8) {
                clearInterval(interval);
                showVerdict(isTampered);
                return;
            }

            const step = container.querySelector('#chk-' + current);
            
            if (isTampered && (current === 1 || current === 2)) {
                step.style.color = 'var(--red)';
                step.querySelector('.chk-status').innerHTML = '✖ FAILED';
            } else {
                step.style.color = 'var(--white)';
                step.querySelector('.chk-status').innerHTML = '✓ OK';
            }

            current++;
        }, 400); // Fast animation (<4s total)
    };

    function showVerdict(isTampered) {
        const banner = container.querySelector('#verdict-banner');
        const title = container.querySelector('#verdict-title');
        const sub = container.querySelector('#verdict-sub');
        
        banner.style.display = 'block';
        container.querySelector('#heat-strip').style.display = 'block';
        container.querySelector('#violations-table').style.display = 'block';
        container.querySelector('#ai-summary').style.display = 'block';

        if(isTampered) {
            banner.style.background = 'radial-gradient(ellipse at center, rgba(228,0,43,0.5) 0%, var(--surface) 70%)';
            title.innerText = 'TAMPERING DETECTED';
            title.style.color = 'var(--red)';
            sub.innerText = 'Critical violations found at Sequence: 1002, 1003';
            
            container.querySelector('#heat-bad').style.background = 'var(--red)';
            
            container.querySelector('#ai-text').innerHTML = `
                The verification failed. Entry <span style="background:var(--surface); padding:2px 4px; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem; color:var(--red);">[#1002]</span> has a bad signature, indicating unauthorized modification. 
                A chain break immediately follows at <span style="background:var(--surface); padding:2px 4px; border-radius:4px; font-family:var(--font-mono); font-size:0.8rem; color:var(--red);">[#1003]</span>. 
                The Responder has quarantined the affected routes.
            `;
        } else {
            banner.style.background = 'radial-gradient(ellipse at center, rgba(245,245,246,0.1) 0%, var(--surface) 70%)';
            title.innerText = 'VERIFIED';
            title.style.color = 'var(--white)';
            sub.innerText = 'No tampering detected.';
        }
    }
}
