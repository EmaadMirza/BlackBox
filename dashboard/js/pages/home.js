export function renderHome(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>When a server is compromised, the evidence is <span class="keyword-red">erased</span>. Not anymore.</h1>
            <div class="red-underline"></div>
            <p>Tamper-evident logging for web apps and AI agents</p>
            
            <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                <button class="btn btn-primary" onclick="window.location.hash='#demo'">Start guided demo</button>
                <button class="btn btn-secondary" onclick="window.location.hash='#architecture'">See the architecture</button>
            </div>

            <div class="swatch-stack-container" style="position: absolute; right: 40px; top: 40px;">
                <div class="swatch-card">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Gateway</div>
                </div>
                <div class="swatch-card raised">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Ledger</div>
                </div>
                <div class="swatch-card">
                    <div class="swatch-band swatch-band-1"></div>
                    <div class="swatch-band swatch-band-2"></div>
                    <div class="swatch-band swatch-band-3"></div>
                    <div class="swatch-band swatch-band-4"></div>
                    <div class="swatch-band swatch-band-5"></div>
                    <div class="swatch-band swatch-band-6"></div>
                    <div style="font-size: 10px; text-align: center; color: var(--grey-400); padding-top: 4px;">Witness</div>
                </div>
            </div>

            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Track</span><span>Cybersecurity and Defense</span></div>
            <div class="meta-row"><span>Built for</span><span>web apps and AI agents</span></div>
            <div class="meta-row"><span>Read time</span><span>2 mins</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#summary">AI Summary</a></li>
                    <li><a href="#arch">Architecture</a></li>
                    <li><a href="#phases">Before / During / After Attack</a></li>
                    <li><a href="#features">Not just logs</a></li>
                    <li><a href="#limits">What BlackBox does NOT claim</a></li>
                </ul>
            </div>
        </div>

        <div id="summary" class="ai-summary">
            <h3>AI Summary</h3>
            <span class="badge badge-unverified">Summary, not evidence</span>
            <p>BlackBox is a gateway that intercepts all traffic to your app. It writes a cryptographically sealed, tamper-evident diary entry for every request. If an attacker breaches the server and alters logs, a separate Witness detects the change immediately. This guarantees that you always have an intact record of how they got in and what they touched.</p>
        </div>

        <div id="arch" style="margin-top: 4rem;">
            <h3>Architecture Strip</h3>
            <div style="display:flex; justify-content: space-between; align-items: center; padding: 2rem; background: var(--surface); border-radius: 12px; margin-top: 1rem;">
                <div style="text-align:center;">Client</div>
                <div style="color:var(--red);">→</div>
                <div style="text-align:center; border:1px dashed var(--red); padding:1rem; border-radius:8px;">Gateway</div>
                <div style="color:var(--red);">→</div>
                <div style="text-align:center;">Origin</div>
                
                <div style="margin-left: 4rem; text-align:center; border:1px solid #26262C; padding:1rem; border-radius:8px;">Ledger</div>
                <div style="color:var(--white);">→</div>
                <div style="text-align:center; border:1px solid #F5F5F6; padding:1rem; border-radius:8px; box-shadow: 0 0 10px rgba(122,12,26,0.5);">Witness</div>
            </div>
        </div>

        <div id="phases" style="margin-top: 4rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem;">
            <div class="card">
                <h4 style="margin-bottom:1rem;">Before attack</h4>
                <p>Verifies request signatures, enforces rules, drops known bad patterns.</p>
            </div>
            <div class="card">
                <h4 style="margin-bottom:1rem;">During attack</h4>
                <p>Auto-bans attackers, quarantines routes, halts sensitive AI actions.</p>
            </div>
            <div class="card">
                <h4 style="margin-bottom:1rem;">After attack</h4>
                <p>Generates blast-radius reports, highlights missing logs, replays good writes.</p>
            </div>
        </div>

        <div id="features" style="margin-top: 4rem;">
            <h3>Not just logs</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-top: 1.5rem;">
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Verified requests</h4><p>Signatures on everything.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Sealed log</h4><p>Forward-secure Merkle chains.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Independent witness</h4><p>Completeness guaranteed.</p></div>
                <div class="card"><h4 style="margin-bottom:0.5rem; color:var(--red);">Recovery</h4><p>Write-journal replay.</p></div>
            </div>
        </div>

        <div id="limits" class="card" style="margin-top: 4rem; border: 1px solid var(--border);">
            <h3 style="margin-bottom: 1rem;">What BlackBox does NOT claim</h3>
            <ul style="color: var(--text-2); margin-left: 1.5rem;">
                <li style="margin-bottom: 0.5rem;">Breach is not prevented. It is made detectable and provable.</li>
                <li style="margin-bottom: 0.5rem;">A rooted gateway can forge new entries (caught later, not stopped).</li>
                <li style="margin-bottom: 0.5rem;">Only sees traffic that goes through the gateway.</li>
            </ul>
        </div>

        <div style="margin-top: 4rem; display:flex; gap: 2rem; border-top: 1px solid var(--border); padding-top: 2rem;">
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-req">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Requests seen</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-blk">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Attacks blocked</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-sl">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Entries sealed</div>
            </div>
            <div>
                <div style="font-size: 2rem; font-weight: 700; color: var(--white);" id="counter-chk">0</div>
                <div style="font-size: 0.9rem; color: var(--text-2);">Checkpoints witnessed</div>
            </div>
        </div>
    `;

    // Hook up some dummy counter increments just to feel alive
    let req=0, blk=0, sl=0, chk=0;
    setInterval(() => {
        req += Math.floor(Math.random() * 5);
        if(Math.random()>0.8) blk++;
        sl = req;
        if(req % 10 === 0) chk++;
        
        const elReq = document.getElementById('counter-req');
        if(elReq) {
            elReq.innerText = req;
            document.getElementById('counter-blk').innerText = blk;
            document.getElementById('counter-sl').innerText = sl;
            document.getElementById('counter-chk').innerText = chk;
        }
    }, 2000);
}
