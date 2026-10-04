import { stream } from '../stream.js';

export function renderAgents(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>The agent never holds the <span class="keyword-red">keys</span>.</h1>
            <div class="red-underline"></div>
            <p>Complete evidence capture for AI actions.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Component</span><span>Gateway agent lane (the chaperone)</span></div>
            <div class="meta-row"><span>Demo agent</span><span>refund-bot</span></div>
            <div class="meta-row"><span>Read time</span><span>3 mins</span></div>
        </div>

        <!-- Animated Explainer -->
        <div class="card hero-card" style="display: flex; align-items: center; justify-content: space-around; padding: 3rem; flex-wrap: wrap; gap: 1rem;">
            <div style="text-align: center;">
                <div style="font-size: 2.5rem; color: var(--grey-400);">🤖</div>
                <div style="font-size: 1.1rem; font-weight: 600;">AI Agent</div>
                <div style="font-size: 0.95rem; color: var(--grey-400);">(Empty hand)</div>
            </div>
            <div style="text-align: center; color: var(--red); font-size: 1.2rem; font-weight: 700;">→ asks →</div>
            <div style="text-align: center; border: 1px solid var(--border); padding: 1.5rem; border-radius: 8px;">
                <div style="font-size: 2.5rem;">🛡️🔑</div>
                <div style="font-size: 1.1rem; font-weight: 600;">Chaperone</div>
            </div>
            <div style="text-align: center; color: var(--white); font-size: 1.2rem; font-weight: 700;">→ executes →</div>
            <div style="text-align: center;">
                <div style="font-size: 2.5rem;">🏦</div>
                <div style="font-size: 1.1rem; font-weight: 600;">Provider</div>
            </div>
        </div>
        <p style="text-align: center; color: var(--text-2); margin-top: -1rem; margin-bottom: 3rem; font-size: 1.1rem;">The agent never carries a key. It asks. The chaperone writes it down first.</p>

        <!-- Actions & Queue -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
            
            <div>
                <h3 style="margin-bottom: 1rem;">Run Agent Scenarios</h3>
                <div class="card" style="display: flex; flex-direction: column; gap: 1rem;">
                    <button class="btn btn-secondary" style="font-size: 1rem; padding: 0.8rem 1rem; text-align: left;" onclick="document.dispatchEvent(new CustomEvent('agt-normal'))">Run normal action</button>
                    <button class="btn btn-primary" style="font-size: 1rem; padding: 0.8rem 1rem; text-align: left;" onclick="document.dispatchEvent(new CustomEvent('agt-poison'))">⚠ Run poisoned invoice attack (A11)</button>
                    <button class="btn btn-secondary" style="font-size: 1rem; padding: 0.8rem 1rem; text-align: left;" onclick="document.dispatchEvent(new CustomEvent('agt-bypass'))">Agent calls provider directly (A12)</button>
                    <button class="btn btn-secondary" style="font-size: 1rem; padding: 0.8rem 1rem; text-align: left;" onclick="document.dispatchEvent(new CustomEvent('agt-tool'))">Tool definition change (A13)</button>
                </div>
            </div>

            <div>
                <h3 style="margin-bottom: 1rem;">Approval Queue</h3>
                <div class="card" id="approval-queue" style="min-height: 200px;">
                    <div style="color: var(--grey-400); text-align: center; margin-top: 2rem; font-size: 1.05rem;">No pending approvals</div>
                </div>
                <div style="font-size: 0.95rem; color: var(--grey-400); text-align: center; margin-top: 0.5rem;">Automatic tiers run inside safety rails; high-impact actions wait for a human.</div>
            </div>
        </div>

        <!-- Agent Action Timeline -->
        <div style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Agent Action Timeline</h3>
            <div class="card" style="background: var(--bg); border: 1px solid var(--border);" id="agent-timeline">
                <div style="color: var(--grey-400); text-align: center; margin-top: 2rem; margin-bottom: 2rem;">Awaiting actions...</div>
            </div>
        </div>

        <!-- Reconciliation -->
        <div style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Reconciliation (2nd Source of Truth)</h3>
            <div class="card" style="padding: 0;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border);">
                    <div style="padding: 1rem; border-right: 1px solid var(--border); font-weight: 700;">Ledger says</div>
                    <div style="padding: 1rem; font-weight: 700;">Payment provider says</div>
                </div>
                <div id="recon-list" style="display: flex; flex-direction: column;">
                    <!-- Filled dynamically -->
                </div>
                <div style="padding: 1rem; text-align: center; border-top: 1px solid var(--border);">
                    <button class="btn btn-secondary" style="font-size: 1rem; padding: 0.7rem 1.5rem;" onclick="document.dispatchEvent(new CustomEvent('agt-delete-log'))">Simulate deleted log entry</button>
                </div>
            </div>
        </div>
    `;

    // Use named handlers to prevent listener stacking on repeat visits
    const agtNormal = () => { if(container.querySelector('#agent-timeline')) stream.triggerAgentAction('NORMAL'); };
    const agtPoison = () => { if(container.querySelector('#agent-timeline')) stream.triggerAgentAction('A11'); };
    const agtBypass = () => { if(container.querySelector('#agent-timeline')) stream.triggerAgentAction('A12'); };
    const agtTool   = () => { if(container.querySelector('#agent-timeline')) stream.triggerAgentAction('A13'); };
    
    // Remove previous listeners (safe even if none exist)
    document.removeEventListener('agt-normal', window.__agtNormal);
    document.removeEventListener('agt-poison', window.__agtPoison);
    document.removeEventListener('agt-bypass', window.__agtBypass);
    document.removeEventListener('agt-tool',   window.__agtTool);
    
    // Store references globally so they can be cleaned up next time
    window.__agtNormal = agtNormal;
    window.__agtPoison = agtPoison;
    window.__agtBypass = agtBypass;
    window.__agtTool   = agtTool;
    
    document.addEventListener('agt-normal', agtNormal);
    document.addEventListener('agt-poison', agtPoison);
    document.addEventListener('agt-bypass', agtBypass);
    document.addEventListener('agt-tool',   agtTool);

    const timeline = container.querySelector('#agent-timeline');
    const reconList = container.querySelector('#recon-list');
    const queue = container.querySelector('#approval-queue');

    let intents = {};

    const handleEvent = (evt) => {
        if(evt.lane !== 'agent') return;

        if (timeline.querySelector('div[style*="text-align: center"]')) timeline.innerHTML = '';
        if (queue.querySelector('div[style*="text-align: center"]')) queue.innerHTML = '';

        if(evt.type === 'action_intent') {
            intents[evt.id] = evt;
            const div = document.createElement('div');
            div.id = 'tl-' + evt.id;
            div.style.cssText = 'padding: 1rem; border-left: 2px solid var(--grey-400); margin-left: 1rem; margin-bottom: 1rem; position: relative;';
            div.innerHTML = `
                <div style="position: absolute; left: -9px; top: 15px; width: 16px; height: 16px; border-radius: 50%; background: var(--surface-2); border: 2px solid var(--grey-400);"></div>
                <div style="font-family: var(--font-mono); font-size: 0.95rem; color: var(--grey-400);">INTENT ${evt.ts.split('T')[1]}</div>
                <div style="font-size: 1.05rem;"><strong>Tool:</strong> ${evt.payload.tool}</div>
                <div style="margin-top: 0.5rem;"><span class="badge badge-unverified" style="font-size: 0.95rem;">Policy: ${evt.payload.status}</span></div>
            `;
            timeline.prepend(div);

            if(evt.payload.status === 'HOLD') {
                const qDiv = document.createElement('div');
                qDiv.style.cssText = 'background: var(--surface-2); padding: 1rem; border-radius: 8px; margin-bottom: 0.5rem; border: 1px solid var(--red);';
                qDiv.innerHTML = `
                    <div style="font-weight: 700; margin-bottom: 0.5rem;">Large Refund Requested: $${evt.payload.amt}</div>
                    <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--red); margin-bottom: 1rem; word-break: break-all;">Input: "${evt.payload.input}"</div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn btn-primary" onclick="this.parentElement.parentElement.remove()">Approve</button>
                        <button class="btn btn-secondary" onclick="this.parentElement.parentElement.remove()">Deny</button>
                    </div>
                `;
                queue.appendChild(qDiv);
            }
        } 
        else if(evt.type === 'action_outcome') {
            const ref = evt.payload.ref;
            const tl = container.querySelector('#tl-' + ref);
            if(tl) {
                const out = document.createElement('div');
                out.style.cssText = 'margin-top: 1rem; padding: 1rem; background: var(--surface-2); border-radius: 8px; border-left: 4px solid var(--white);';
                out.innerHTML = `
                    <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--white);">OUTCOME ${evt.ts.split('T')[1]}</div>
                    <div>${evt.payload.status}</div>
                `;
                tl.appendChild(out);

                // Add to reconciliation
                const rDiv = document.createElement('div');
                rDiv.style.cssText = 'display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border); align-items: center;';
                rDiv.innerHTML = `
                    <div style="padding: 1rem; border-right: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-2);">Ledger: OUTCOME ${ref}</div>
                    <div style="padding: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-2); display: flex; justify-content: space-between;">
                        <span>Provider: Event processed</span>
                        <span style="color: var(--white);">🔗</span>
                    </div>
                `;
                reconList.prepend(rDiv);
            }
        }
        else if(evt.type === 'bypass' || evt.type === 'tool_def_change') {
            const rDiv = document.createElement('div');
            rDiv.style.cssText = 'display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border); align-items: center; background: rgba(228,0,43,0.1);';
            rDiv.innerHTML = `
                <div style="padding: 1rem; border-right: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.8rem; color: var(--red);">[NO LEDGER ENTRY]</div>
                <div style="padding: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--red);">
                    Provider: ${evt.payload.desc || 'Unexpected action'} <span class="badge badge-tampered">UNRECORDED_ACTION</span>
                </div>
            `;
            reconList.prepend(rDiv);
        }
    };

    stream.subscribe(handleEvent);

    document.removeEventListener('agt-delete-log', window.__agtDeleteLog);
    const deleteLogHandler = () => {
        if (!container.querySelector('#recon-list')) return;
        const rDiv = document.createElement('div');
        rDiv.style.cssText = 'display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border); align-items: center; background: rgba(228,0,43,0.1);';
        rDiv.innerHTML = `
            <div style="padding: 1rem; border-right: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.8rem; color: var(--red);">[MISSING IN LEDGER]</div>
            <div style="padding: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--red);">
                Provider: Refund $50 <span class="badge badge-tampered">UNRECORDED_ACTION</span>
            </div>
        `;
        reconList.prepend(rDiv);
    };
    window.__agtDeleteLog = deleteLogHandler;
    document.addEventListener('agt-delete-log', deleteLogHandler);
}
