import { stream } from '../stream.js';

export function renderGateway(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>Every request, <span class="keyword-red">decided</span> in the open.</h1>
            <div class="red-underline"></div>
            <p>See the gateway intercept traffic live.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Component</span><span>Gateway (the guard)</span></div>
            <div class="meta-row"><span>Trust level</span><span style="color:var(--red);">Assumed attackable</span></div>
            <div class="meta-row"><span>Read time</span><span>2 mins</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#attack-launcher">Attack Launcher</a></li>
                    <li><a href="#live-feed">Live Request Feed</a></li>
                    <li><a href="#response">Threat & Response</a></li>
                    <li><a href="#compare">Compare: Bare vs BlackBox</a></li>
                </ul>
            </div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                What am I looking at?
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <p>This is the Live Gateway. Every request passes through a strict pipeline before reaching your app. You can launch common attacks here to see how BlackBox blocks them and responds in real-time, all while leaving an unalterable trail of evidence.</p>
            </div>
        </div>

        <!-- Desktop 3 Columns Layout -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin-top: 3rem;">
            
            <!-- LEFT: Attack Launcher -->
            <div id="attack-launcher">
                <h3 style="margin-bottom: 1rem;">Attack Launcher</h3>
                <div class="card" style="display: flex; flex-direction: column; gap: 0.5rem; padding: 1.5rem;">
                    <button class="btn btn-secondary atk-btn" data-type="A1">SQL Injection (/api/search)</button>
                    <button class="btn btn-secondary atk-btn" data-type="A2">Path Traversal</button>
                    <button class="btn btn-secondary atk-btn" data-type="A3">XSS</button>
                    <button class="btn btn-secondary atk-btn" data-type="A4">Credential stuffing (/login)</button>
                    <button class="btn btn-secondary atk-btn" data-type="A5">Replay signed request</button>
                    <button class="btn btn-secondary atk-btn" data-type="A6">Altered body</button>
                    <button class="btn btn-secondary atk-btn" data-type="A7">Unsigned request</button>
                    <button class="btn btn-secondary atk-btn" data-type="A8">Probe /.env honeytoken</button>
                    <button class="btn btn-secondary atk-btn" data-type="A9">Direct-to-origin bypass</button>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                        <button class="btn btn-primary" style="flex: 1;" onclick="Array.from(document.querySelectorAll('.atk-btn')).forEach((b,i)=>setTimeout(()=>b.click(), i*500))">Run all</button>
                        <button class="btn btn-secondary" style="flex: 1;" onclick="document.dispatchEvent(new CustomEvent('bb-reset'))">Reset demo</button>
                    </div>
                </div>
            </div>

            <!-- CENTER: Live Request Feed -->
            <div id="live-feed">
                <h3 style="margin-bottom: 1rem;">Live Request Feed</h3>
                <div class="card" style="padding: 1rem; background: var(--bg); border: 1px solid var(--border);">
                    <div id="feed-list" style="display: flex; flex-direction: column; gap: 0.5rem; height: 500px; overflow-y: auto;">
                        <div style="color: var(--grey-400); text-align: center; margin-top: 2rem;">Waiting for traffic...</div>
                    </div>
                </div>
            </div>

            <!-- RIGHT: Threat & Response -->
            <div id="response">
                <h3 style="margin-bottom: 1rem;">Threat & Response</h3>
                <div class="card" style="padding: 1.5rem;">
                    <h4 style="margin-bottom: 1rem;">Response Tiers</h4>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;" id="tiers-list">
                        <div style="border-left: 3px solid var(--grey-400); padding-left: 0.5rem; color: var(--grey-400);" id="tier-1">1: Alert</div>
                        <div style="border-left: 3px solid var(--grey-400); padding-left: 0.5rem; color: var(--grey-400);" id="tier-2">2: Rate limit</div>
                        <div style="border-left: 3px solid var(--grey-400); padding-left: 0.5rem; color: var(--grey-400);" id="tier-3">3: Block key/account (auto-expiry)</div>
                        <div style="border-left: 3px solid var(--grey-400); padding-left: 0.5rem; color: var(--grey-400);" id="tier-4">4: Quarantine route (tamper/honeytoken)</div>
                    </div>
                </div>
                <div class="card" style="padding: 1.5rem; margin-top: 1rem;">
                    <h4 style="margin-bottom: 1rem;">Safety Rails</h4>
                    <p style="font-size: 0.9rem;">To prevent locking out real users, bans auto-expire, respect an allowlist, and can be run in dry-run mode.</p>
                </div>
            </div>
        </div>

        <!-- KILLER FEATURE: Compare -->
        <div id="compare" style="margin-top: 4rem;">
            <div class="card hero-card" style="display: flex; flex-direction: column;">
                <h2 style="margin-bottom: 1rem;">Compare: bare app vs BlackBox</h2>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <div style="background: var(--bg); padding: 1.5rem; border: 1px solid var(--border); border-radius: 8px;">
                        <h3 style="color: var(--grey-400);">Without BlackBox</h3>
                        <div id="bare-status" style="margin-top: 1rem; color: var(--red); font-weight: 700;">EXPOSED</div>
                        <div id="bare-data" style="margin-top: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--red); display:none;">
                            [LEAKED DATA] id:1, hash:8x9a...
                        </div>
                    </div>
                    <div style="background: var(--bg); padding: 1.5rem; border: 1px solid var(--red); border-radius: 8px; box-shadow: inset 0 0 20px rgba(228,0,43,0.1);">
                        <h3 style="color: var(--white);">With BlackBox</h3>
                        <div id="bb-status" style="margin-top: 1rem; color: var(--white); font-weight: 700;">PROTECTED</div>
                        <div id="bb-rule" style="margin-top: 1rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--grey-400);">
                            Awaiting attack...
                        </div>
                    </div>
                </div>
                <div style="margin-top: 2rem; font-size: 1.5rem;">
                    Attacks that got through: <span id="comp-bare" class="keyword-red" style="font-weight: 700;">0</span> vs <span id="comp-bb" class="keyword-red" style="font-weight: 700;">0</span>
                </div>
            </div>
        </div>

        <!-- Request Details Drawer -->
        <div id="req-drawer" class="drawer">
            <h3 style="margin-bottom: 0.5rem;">Why was this decided?</h3>
            <p id="req-drawer-id" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--grey-400); margin-bottom: 2rem;"></p>
            
            <div id="req-drawer-pipeline" style="display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 2rem;">
                <!-- Filled dynamically -->
            </div>

            <div id="req-drawer-details" style="display: none; background: var(--bg); padding: 1rem; border: 1px solid var(--border); border-radius: 8px;">
                <div style="color: var(--red); font-family: var(--font-mono); font-size: 0.9rem;" id="req-drawer-rule"></div>
                <div style="color: var(--text-2); font-family: var(--font-mono); font-size: 0.8rem; margin-top: 0.5rem; word-break: break-all;" id="req-drawer-payload"></div>
            </div>

            <button class="btn btn-secondary" style="margin-top: 2rem; width: 100%;" onclick="this.parentElement.classList.remove('open')">Close</button>
        </div>
    `;

    const feedList = container.querySelector('#feed-list');
    let bareHits = 0;
    
    // Wire up attack buttons
    container.querySelectorAll('.atk-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const type = e.target.getAttribute('data-type');
            stream.triggerAttack(type);
            
            // Update Compare section
            bareHits++;
            container.querySelector('#comp-bare').innerText = bareHits;
            container.querySelector('#bare-data').style.display = 'block';
            if(type === 'A1') container.querySelector('#bb-rule').innerText = "BLOCKED: SQLI-001";
            else container.querySelector('#bb-rule').innerText = "BLOCKED: " + type;
        });
    });

    document.addEventListener('bb-reset', () => {
        bareHits = 0;
        container.querySelector('#comp-bare').innerText = 0;
        container.querySelector('#bare-data').style.display = 'none';
        container.querySelector('#bb-rule').innerText = "Awaiting attack...";
        feedList.innerHTML = '<div style="color: var(--grey-400); text-align: center; margin-top: 2rem;">Waiting for traffic...</div>';
        
        [1,2,3,4].forEach(i => {
            const el = container.querySelector('#tier-'+i);
            if(el) {
                el.style.borderColor = 'var(--grey-400)';
                el.style.color = 'var(--grey-400)';
            }
        });
        stream.reset();
    });

    const handleEvent = (evt) => {
        if (evt.type === 'request') {
            if (feedList.querySelector('div[style*="text-align: center"]')) feedList.innerHTML = '';
            
            const div = document.createElement('div');
            const isBlocked = evt.payload.status === 'BLOCKED' || evt.payload.status === 'HONEYTOKEN';
            
            div.style.cssText = `
                padding: 0.75rem; 
                background: var(--surface); 
                border-radius: 4px; 
                cursor: pointer;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-left: 4px solid ${isBlocked ? 'var(--red)' : 'var(--grey-400)'};
                box-shadow: ${isBlocked ? '0 0 10px rgba(228,0,43,0.2)' : 'none'};
                margin-bottom: 0.5rem;
            `;
            
            div.innerHTML = `
                <div style="font-family: var(--font-mono); font-size: 0.85rem;">${evt.payload.method} ${evt.payload.path}</div>
                <div style="display:flex; gap: 1rem; align-items:center;">
                    <span class="badge ${isBlocked ? 'badge-tampered' : 'badge-verified'}">${evt.payload.status}</span>
                </div>
            `;
            
            div.onclick = () => showDrawer(evt);
            
            feedList.prepend(div);
            if (feedList.children.length > 50) feedList.lastChild.remove();
        } else if (evt.type === 'response_action') {
            const t = evt.payload.tier;
            const el = container.querySelector('#tier-'+t);
            if(el) {
                el.style.borderColor = 'var(--red)';
                el.style.color = 'var(--white)';
            }
        }
    };

    stream.subscribe(handleEvent);

    function showDrawer(evt) {
        const drawer = container.querySelector('#req-drawer');
        const p = evt.payload;
        container.querySelector('#req-drawer-id').innerText = evt.id;
        
        const steps = ['Sanity', 'Signature', 'Rate limit', 'Rules', 'Honeytoken', 'Policy'];
        let html = '';
        let failedAt = p.failStep || 99;
        
        steps.forEach((s, idx) => {
            const isFail = (idx + 1) === failedAt;
            const isSkip = (idx + 1) > failedAt;
            let color = isSkip ? 'var(--grey-400)' : (isFail ? 'var(--red)' : 'var(--white)');
            let icon = isSkip ? '○' : (isFail ? '✖' : '✓');
            html += `<div style="color: ${color}; display:flex; gap: 0.5rem;"><span>${icon}</span> ${s}</div>`;
        });
        
        container.querySelector('#req-drawer-pipeline').innerHTML = html;
        
        const details = container.querySelector('#req-drawer-details');
        if (p.rule) {
            details.style.display = 'block';
            container.querySelector('#req-drawer-rule').innerText = "Matched: " + p.rule;
            container.querySelector('#req-drawer-payload').innerText = "Payload: " + (p.payloadMatch || '');
        } else {
            details.style.display = 'none';
        }
        
        drawer.classList.add('open');
    }
}
