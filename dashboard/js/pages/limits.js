import { stream } from '../stream.js';

export function renderLimits(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>What BlackBox does <span class="keyword-red">not</span> do.</h1>
            <div class="red-underline"></div>
            <p>Honest boundaries. No "unhackable" marketing.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Comparison</span><span>8 Alternatives</span></div>
            <div class="meta-row"><span>Read time</span><span>4 mins</span></div>
        </div>

        <!-- Honest Limits Accordion -->
        <div style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Honest Limits</h3>
            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                <div class="accordion">
                    <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">1. Breach is not prevented. It is made detectable.<span class="accordion-chevron">▼</span></div>
                    <div class="accordion-content"><p>We do not stop 0-days. We ensure that when they happen, the evidence is mathematically guaranteed to survive.</p></div>
                </div>
                <div class="accordion">
                    <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">2. A rooted gateway can forge new entries.<span class="accordion-chevron">▼</span></div>
                    <div class="accordion-content"><p>If the gateway is taken over, the attacker holds the current epoch key. They can forge new logs, but cannot alter the past. The forgery will be caught later during Reconciliation.</p></div>
                </div>
                <div class="accordion">
                    <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">3. Only sees traffic that goes through it.<span class="accordion-chevron">▼</span></div>
                    <div class="accordion-content"><p>Direct database edits via SSH, or side-channel exfiltration, bypass the gateway entirely. BlackBox only guarantees the integrity of its own boundary.</p></div>
                </div>
                <!-- Simulating the remaining limits... -->
                <div style="padding: 1rem; color: var(--grey-400); font-style: italic;">...and 12 more limits documented in the full specification.</div>
            </div>
        </div>

        <!-- Where BlackBox is NOT better -->
        <div style="margin-top: 4rem;">
            <div class="card" style="border: 1px solid var(--red); background: rgba(228,0,43,0.05);">
                <h3 style="color: var(--red); margin-bottom: 1rem;">Where BlackBox is worse</h3>
                <ul style="color: var(--grey-400); font-size: 0.9rem; line-height: 1.6; margin-left: 1.5rem;">
                    <li><strong>Latency:</strong> Cryptographic sealing adds ~5ms p50 latency to every request.</li>
                    <li><strong>Overhead:</strong> Storage bloats quickly due to hashes, signatures, and full payload retention.</li>
                    <li><strong>Complexity:</strong> Requires a trusted, independent Witness server to be run on separate infrastructure.</li>
                    <li><strong>False positives:</strong> Auto-banning rules can accidentally quarantine legitimate power users.</li>
                </ul>
            </div>
        </div>

        <!-- Fair Comparison Table -->
        <div style="margin-top: 4rem; overflow-x: auto;">
            <h3 style="margin-bottom: 0.5rem;">Fair Comparison</h3>
            <div style="font-size: 0.8rem; color: var(--red); margin-bottom: 1rem; font-family: var(--font-mono);">WARNING: Verify every cell before presenting.</div>
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; min-width: 800px;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border); background: var(--surface-2);">
                        <th style="padding: 1rem;">System</th>
                        <th style="padding: 1rem;">Forward-Secure</th>
                        <th style="padding: 1rem;">Cryptographic Proof</th>
                        <th style="padding: 1rem;">Active Intercept</th>
                        <th style="padding: 1rem;">Agent Brokering</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 1rem;">SIEM / Remote Syslog</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No (can drop UDP)</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 1rem;">S3 Object Lock</td>
                        <td style="padding: 1rem; color:var(--white);">Yes (Append-only)</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 1rem;">journald FSS</td>
                        <td style="padding: 1rem; color:var(--white);">Yes</td>
                        <td style="padding: 1rem; color:var(--white);">Yes (Sealed)</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 1rem;">immudb</td>
                        <td style="padding: 1rem; color:var(--white);">Yes</td>
                        <td style="padding: 1rem; color:var(--white);">Yes</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 1rem;">Trillian / CT-style</td>
                        <td style="padding: 1rem; color:var(--white);">Yes</td>
                        <td style="padding: 1rem; color:var(--white);">Yes (Merkle)</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                        <td style="padding: 1rem; color:var(--grey-400);">No</td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--border); background: rgba(255,255,255,0.05);">
                        <td style="padding: 1rem; font-weight:700;">BlackBox</td>
                        <td style="padding: 1rem; color:var(--red); font-weight:700;">Yes</td>
                        <td style="padding: 1rem; color:var(--red); font-weight:700;">Yes</td>
                        <td style="padding: 1rem; color:var(--red); font-weight:700;">Yes</td>
                        <td style="padding: 1rem; color:var(--red); font-weight:700;">Yes</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Numbers Card -->
        <div style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">The Numbers</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                <div class="card" style="padding: 1.5rem; text-align: center;">
                    <div style="font-size: 2rem; color: var(--white); font-weight: 700;">5ms</div>
                    <div style="color: var(--grey-400); font-size: 0.9rem;">p50 overhead latency</div>
                </div>
                <div class="card" style="padding: 1.5rem; text-align: center;">
                    <div style="font-size: 2rem; color: var(--white); font-weight: 700;">12ms</div>
                    <div style="color: var(--grey-400); font-size: 0.9rem;">p95 overhead latency</div>
                </div>
                <div class="card" style="padding: 1.5rem; text-align: center;">
                    <div style="font-size: 2rem; color: var(--white); font-weight: 700;">2k</div>
                    <div style="color: var(--grey-400); font-size: 0.9rem;">req/sec max throughput</div>
                </div>
                <div class="card" style="padding: 1.5rem; text-align: center;">
                    <div style="font-size: 2rem; color: var(--red); font-weight: 700;">~5s</div>
                    <div style="color: var(--grey-400); font-size: 0.9rem;">Residual (unwitnessed) window</div>
                </div>
            </div>
        </div>

        <!-- Roadmap -->
        <div style="margin-top: 4rem; margin-bottom: 4rem;">
            <h3 style="margin-bottom: 1rem;">Roadmap</h3>
            <div style="display: flex; gap: 1rem; overflow-x: auto; padding-bottom: 1rem;">
                <div style="min-width: 200px; padding: 1rem; background: var(--surface-2); border-radius: 4px; border: 1px solid var(--border);">Witness quorum</div>
                <div style="min-width: 200px; padding: 1rem; background: var(--surface-2); border-radius: 4px; border: 1px solid var(--border);">External timestamp anchoring</div>
                <div style="min-width: 200px; padding: 1rem; background: var(--surface-2); border-radius: 4px; border: 1px solid var(--border);">Anomaly model</div>
                <div style="min-width: 200px; padding: 1rem; background: var(--surface-2); border-radius: 4px; border: 1px solid var(--border);">Host-level capture (eBPF)</div>
            </div>
        </div>
    `;
}
