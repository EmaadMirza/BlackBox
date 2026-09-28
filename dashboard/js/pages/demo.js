import { stream } from '../stream.js';

export function renderDemo(container) {
    container.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 9999; pointer-events: none;">
            <div id="demo-overlay-card" class="card" style="position: absolute; bottom: 40px; right: 40px; width: 350px; background: var(--bg); border: 2px solid var(--red); pointer-events: auto; box-shadow: 0 10px 30px rgba(0,0,0,0.8);">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1rem;">
                    <h3 style="font-size: 1.1rem;">Guided Demo</h3>
                    <span id="demo-progress" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--grey-400);">Step 1 / 12</span>
                </div>
                
                <p id="demo-caption" style="font-size: 0.95rem; color: var(--white); margin-bottom: 1.5rem; line-height: 1.5;"></p>
                
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-secondary" style="flex: 1;" id="demo-prev">Prev</button>
                    <button class="btn btn-primary" style="flex: 2;" id="demo-next">Next (→)</button>
                </div>
                
                <div style="margin-top: 1rem; text-align: center;">
                    <button class="btn btn-secondary" style="font-size: 0.7rem; color: var(--grey-400); background: transparent; border: none; text-decoration: underline;" id="demo-close">Exit Demo</button>
                    <button class="btn btn-secondary" style="font-size: 0.7rem; color: var(--red); background: transparent; border: none; text-decoration: underline; margin-left: 1rem;" onclick="stream.reset()">Reset Engine</button>
                </div>
            </div>
            <div id="spotlight-overlay" style="position: absolute; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.5); z-index: -1; display: none;"></div>
        </div>
    `;

    const steps = [
        { page: '#home', caption: "Welcome to BlackBox. When a server is compromised, attackers erase the evidence. We fix that." },
        { page: '#architecture', caption: "Flow 1: Every request is signed and evaluated. The Gateway acts as the guard. Let's look at the live pipeline." },
        { page: '#gateway', caption: "Here is the Live Gateway. I'll launch a Path Traversal attack. Notice it's blocked instantly." },
        { page: '#gateway', caption: "Now watch the 'Compare' feature below. A bare app gets exposed, BlackBox blocks it and writes a sealed entry." },
        { page: '#agents', caption: "Let's move to the Agent Lane. The agent asks for an action, the Gateway executes it. If the agent tries a poisoned invoice (A11), it gets held for human approval." },
        { page: '#tamper', caption: "Now, the worst happens. The attacker gets root. They go into the database and edit an entry. In a normal plain log, no one would notice." },
        { page: '#tamper', caption: "But BlackBox's chain is broken. The cryptography reveals exactly what they altered." },
        { page: '#verify', caption: "Let's run the offline Verifier. It checks all signatures, sequence gaps, and checkpoints." },
        { page: '#verify', caption: "VERIFIED TAMPERING. We have exact sequence numbers and the policy engine instantly quarantines the route." },
        { page: '#recovery', caption: "Recovery is no longer blind. We have a Blast-Radius report and know exactly which 4 minutes of logs to discard. We replay the good writes." },
        { page: '#recovery', caption: "Even the AI Narrator works safely, stripping out prompt injections natively because it reads strict structured data." },
        { page: '#limits', caption: "We don't sell snake oil. We have honest limits. We don't prevent breaches, we make them cryptographically detectable." }
    ];

    let current = 0;
    const progress = container.querySelector('#demo-progress');
    const caption = container.querySelector('#demo-caption');
    
    function renderStep() {
        progress.innerText = `Step ${current + 1} / ${steps.length}`;
        caption.innerText = steps[current].caption;
        window.location.hash = steps[current].page;
        
        // Trigger mock actions based on step
        if(current === 2) setTimeout(() => stream.triggerAttack('A2'), 500);
        if(current === 3) setTimeout(() => stream.triggerAttack('A1'), 500);
        if(current === 4) setTimeout(() => stream.triggerAgentAction('A11'), 500);
        if(current === 6) setTimeout(() => stream.triggerTamper('T1'), 500);
        if(current === 8) setTimeout(() => { const btn = document.getElementById('btn-run-verify'); if(btn) btn.click(); }, 1000);
    }

    container.querySelector('#demo-next').onclick = () => {
        if(current < steps.length - 1) { current++; renderStep(); }
    };
    
    container.querySelector('#demo-prev').onclick = () => {
        if(current > 0) { current--; renderStep(); }
    };

    container.querySelector('#demo-close').onclick = () => {
        container.innerHTML = ''; // Remove overlay
    };

    document.addEventListener('keydown', (e) => {
        if(e.key === 'ArrowRight') container.querySelector('#demo-next')?.click();
        if(e.key === 'ArrowLeft') container.querySelector('#demo-prev')?.click();
        if(e.key === 'Escape') container.querySelector('#demo-close')?.click();
    });

    renderStep();
}
