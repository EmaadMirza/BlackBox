export function renderArchitecture(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>The <span class="keyword-red">architecture</span>, explained</h1>
            <div class="red-underline"></div>
            <p>Every request recorded. Every change detectable.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Diagram Format</span><span>Interactive SVG</span></div>
            <div class="meta-row"><span>Flows Documented</span><span>3</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">&#9660;</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#diagram">Interactive Diagram</a></li>
                    <li><a href="#controls">Flow Controls</a></li>
                </ul>
            </div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                What am I looking at?
                <span class="accordion-chevron">&#9660;</span>
            </div>
            <div class="accordion-content">
                <p id="plain-words-desc">Think of your web app as a building. The Gateway is the guard at the door and the chaperone for AI helpers. The Ledger is an unalterable diary recording every action. The Witness is the notary stamping the diary so it can't be modified later.</p>
                <p id="tech-words-desc" style="display:none;">The Gateway performs Ed25519 signature validation and rate limiting, producing JCS canonicalized intents. The Ledger stores AES-GCM encrypted payloads in an append-only PostgreSQL database, building an RFC 6962 Merkle tree. The Witness continuously verifies checkpoints.</p>
            </div>
        </div>

        <div id="controls" style="margin-bottom: 2rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
            <button class="btn btn-secondary" id="btn-flow1">Flow 1</button>
            <button class="btn btn-secondary" id="btn-flow2">Flow 2</button>
            <button class="btn btn-secondary" id="btn-flow3">Flow 3</button>
            <button class="btn btn-secondary" id="btn-zones">Show trust zones</button>
            <button class="btn btn-secondary" id="btn-all">Show all</button>
            <div style="flex: 1;"></div>
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                <input type="checkbox" id="toggle-tech" />
                <span style="font-size: 0.9rem; color: var(--grey-400);">Plain words / Technical</span>
            </label>
        </div>
        
        <div id="caption-bar" style="background: var(--surface-2); padding: 1rem; border-radius: 8px; margin-bottom: 2rem; display: none; align-items: center; justify-content: space-between;">
            <div id="caption-text" style="font-weight: 700; color: var(--white);"></div>
            <div style="display: flex; gap: 0.5rem;">
                <button class="btn btn-primary" style="padding: 0.25rem 0.75rem;" id="btn-pause">Pause</button>
                <button class="btn btn-secondary" style="padding: 0.25rem 0.75rem;" id="btn-next">Next</button>
            </div>
        </div>

        <div id="diagram" style="width: 100%; overflow-x: auto; background: var(--bg); border-radius: 12px; border: 1px solid var(--border);">
            <object id="svg-object" type="image/svg+xml" data="assets/architecture.svg" style="width: 100%; min-width: 800px; height: auto;"></object>
        </div>

        <div id="component-drawer" class="drawer">
            <h3 id="comp-title">Component</h3>
            <p id="comp-nick" style="color: var(--grey-400); font-style: italic; margin-bottom: 1.5rem;"></p>
            
            <h4 style="color: var(--white); margin-bottom: 0.5rem;">Job</h4>
            <p id="comp-job" style="font-size: 0.9rem;"></p>

            <h4 style="color: var(--white); margin-bottom: 0.5rem; margin-top: 1.5rem;">Trust Level</h4>
            <p id="comp-trust" style="font-size: 0.9rem; color: var(--red);"></p>

            <h4 style="color: var(--white); margin-bottom: 0.5rem; margin-top: 1.5rem;">Attacker capability</h4>
            <p id="comp-atk" style="font-size: 0.9rem;"></p>
            
            <button class="btn btn-secondary" style="margin-top: 2rem; width: 100%;" onclick="this.parentElement.classList.remove('open')">Close</button>
        </div>
    `;

    const toggleTech = container.querySelector('#toggle-tech');
    const plainDesc = container.querySelector('#plain-words-desc');
    const techDesc = container.querySelector('#tech-words-desc');

    toggleTech.addEventListener('change', (e) => {
        if(e.target.checked) {
            plainDesc.style.display = 'none';
            techDesc.style.display = 'block';
        } else {
            plainDesc.style.display = 'block';
            techDesc.style.display = 'none';
        }
    });

    const captionBar = container.querySelector('#caption-bar');
    const captionText = container.querySelector('#caption-text');

    
    const svgObject = container.querySelector('#svg-object');
    svgObject.addEventListener('load', () => {
        try {
            const svgDoc = svgObject.contentDocument;
            if (svgDoc) {
                const groups = svgDoc.querySelectorAll('g');
                groups.forEach(g => {
                    g.style.cursor = 'pointer';
                    g.addEventListener('click', () => {
                        const titleEl = g.querySelector('.text-title');
                        if (titleEl) {
                            container.querySelector('#comp-title').innerText = titleEl.textContent;
                            container.querySelector('#comp-job').innerText = 'Detailed logic for ' + titleEl.textContent;
                            container.querySelector('#comp-trust').innerText = 'Depends on zone';
                            container.querySelector('#comp-atk').innerText = 'Varies';
                            container.querySelector('#component-drawer').classList.add('open');
                        }
                    });
                });
            }
        } catch(e) {}
    });

    const flows = {
        flow1: ["Client signs request", "Gateway validates signature", "Intent sealed to Ledger", "Gateway forwards to Origin", "Outcome sealed to Ledger", "Ledger Checkpoint witnessed"],
        flow2: ["Agent requests action", "Intent sealed", "Human approves high-impact action", "Broker injects provider credentials", "Outcome sealed"],
        flow3: ["Attacker gets root, edits rows", "Witness consistency proof fails", "Verifier detects TAMPERING", "Responder quarantines route", "Reconciler flags missing log"]
    };

    let currentFlow = [];
    let step = 0;

    function playStep() {
        if(step < currentFlow.length) {
            captionBar.style.display = 'flex';
            captionText.innerText = `Step ${step + 1} of ${currentFlow.length}: ${currentFlow[step]}`;
        } else {
            captionBar.style.display = 'none';
        }
    }

    container.querySelector('#btn-flow1').onclick = () => { currentFlow = flows.flow1; step = 0; playStep(); };
    container.querySelector('#btn-flow2').onclick = () => { currentFlow = flows.flow2; step = 0; playStep(); };
    container.querySelector('#btn-flow3').onclick = () => { currentFlow = flows.flow3; step = 0; playStep(); };
    container.querySelector('#btn-next').onclick = () => { step++; playStep(); };
    
    container.querySelector('#btn-pause').onclick = () => {
        const btn = container.querySelector('#btn-pause');
        if (btn.innerText === 'Pause') {
            btn.innerText = 'Resume';
        } else {
            btn.innerText = 'Pause';
        }
    };

    container.querySelector('#btn-zones').onclick = () => {
        captionBar.style.display = 'flex';
        captionText.innerHTML = '<span style="color:var(--red);">Attackable:</span> Gateway, Ledger &nbsp;|&nbsp; <span style="color:var(--white);">Trusted:</span> Witness, Root Key Vault';
    };

    container.querySelector('#btn-all').onclick = () => {
        currentFlow = [...flows.flow1, '---', ...flows.flow2, '---', ...flows.flow3];
        step = 0;
        playStep();
    };
}
