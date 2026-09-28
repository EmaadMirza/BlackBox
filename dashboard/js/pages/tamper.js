import { stream } from '../stream.js';

export function renderTamper(container) {
    container.innerHTML = `
        <div class="card hero-card">
            <h1>The attacker gets <span class="keyword-red">root</span>. Now what?</h1>
            <div class="red-underline"></div>
            <p>They can edit the database. They cannot forge the cryptographic proof.</p>
            <div class="card-credit">BlackBox · ASYNC'26</div>
        </div>

        <div class="meta-rows">
            <div class="meta-row"><span>Scenarios</span><span>T1 to T11</span></div>
            <div class="meta-row"><span>Expected outcome</span><span style="color:var(--red);">Detected, with exact sequence numbers</span></div>
            <div class="meta-row"><span>Read time</span><span>3 mins</span></div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="this.parentElement.classList.toggle('open')">
                Table of Contents
                <span class="accordion-chevron">▼</span>
            </div>
            <div class="accordion-content">
                <ul>
                    <li><a href="#lab">Tamper Lab Scenarios</a></li>
                    <li><a href="#view">Log vs Chain Comparison</a></li>
                    <li><a href="#judge">Let a judge tamper</a></li>
                </ul>
            </div>
        </div>

        <div id="lab" style="margin-top: 4rem;">
            <h3 style="margin-bottom: 1rem;">Tamper Lab Scenarios</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem;">
                <!-- T1 to T11 buttons -->
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T1">T1: Edit one entry</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: TAMPERED (BAD_SIGNATURE or CHAIN_BREAK)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T2">T2: Delete from middle</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: MISSING (SEQ_GAP)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T3">T3: Delete the tail</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: Checkpoint size mismatch</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T4">T4: Swap two entries</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: TAMPERED (chain and AAD break)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T5">T5: Insert forged entry</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: TAMPERED or sequence gap</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T6">T6: Rewrite history & recompute</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: CONSISTENCY_FAILURE (witness refuses)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T7">T7: Roll back to snapshot</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: Witness has larger tree size</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T8">T8: Stop logging but run app</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: HEARTBEAT_GAP</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T9">T9: Replay old checkpoint</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: Rejected (not an extension)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T10">T10: Steal key to read past</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: Fails (older keys deleted)</div>
                </div>
                <div class="card" style="padding: 1rem;">
                    <button class="btn btn-secondary t-btn" style="width: 100%; margin-bottom: 0.5rem;" data-id="T11">T11: Forge with stolen key</button>
                    <div style="font-size: 0.8rem; color: var(--grey-400);">Expected: Detected later via reconciliation</div>
                </div>
            </div>
        </div>

        <div id="view" style="margin-top: 4rem;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
                
                <!-- Plain Log -->
                <div>
                    <h3 style="margin-bottom: 1rem;">Plain Log (Database View)</h3>
                    <div class="card" style="background: var(--bg); border: 1px solid var(--border); font-family: var(--font-mono); font-size: 0.85rem; padding: 1rem;">
                        <div style="color: var(--grey-400); margin-bottom: 0.5rem;">[ID: 1001] POST /login SUCCESS</div>
                        <div id="plain-edit" style="color: var(--white); margin-bottom: 0.5rem;">[ID: 1002] POST /api/orders SUCCESS</div>
                        <div id="plain-del" style="color: var(--grey-400); margin-bottom: 0.5rem;">[ID: 1003] GET /api/search SUCCESS</div>
                        <div style="color: var(--grey-400); margin-bottom: 0.5rem;">[ID: 1004] POST /logout SUCCESS</div>
                    </div>
                </div>

                <!-- BlackBox Chain -->
                <div>
                    <h3 style="margin-bottom: 1rem;">BlackBox Chain</h3>
                    <div class="card" style="background: var(--bg); border: 1px solid var(--border); padding: 1rem; display: flex; flex-direction: column; gap: 0.5rem;" id="bb-chain">
                        <div style="padding: 0.5rem; background: var(--surface-2); border-radius: 4px; display: flex; align-items: center; justify-content: space-between;">
                            <span style="font-family: var(--font-mono); font-size: 0.8rem;">Seq 1001: a1b2...</span>
                            <span class="badge badge-verified">VERIFIED</span>
                        </div>
                        <div id="bb-edit" style="padding: 0.5rem; background: var(--surface-2); border-radius: 4px; display: flex; align-items: center; justify-content: space-between; transition: all 0.3s;">
                            <span style="font-family: var(--font-mono); font-size: 0.8rem;">Seq 1002: c3d4...</span>
                            <span class="badge badge-verified">VERIFIED</span>
                        </div>
                        <div id="bb-del" style="padding: 0.5rem; background: var(--surface-2); border-radius: 4px; display: flex; align-items: center; justify-content: space-between; transition: all 0.3s;">
                            <span style="font-family: var(--font-mono); font-size: 0.8rem;">Seq 1003: e5f6...</span>
                            <span class="badge badge-verified">VERIFIED</span>
                        </div>
                        <div id="bb-brk" style="text-align: center; color: var(--border); transition: color 0.3s;">↓ link ↓</div>
                        <div style="padding: 0.5rem; background: var(--surface-2); border-radius: 4px; display: flex; align-items: center; justify-content: space-between;">
                            <span style="font-family: var(--font-mono); font-size: 0.8rem;">Seq 1004: g7h8...</span>
                            <span class="badge badge-verified">VERIFIED</span>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <div id="judge" style="margin-top: 4rem; text-align: center;">
            <button class="btn btn-primary" style="font-size: 1.2rem; padding: 1rem 2rem;" onclick="document.getElementById('judge-modal').style.display='flex'">Let a judge tamper</button>
        </div>

        <!-- Judge Modal -->
        <div id="judge-modal" style="display: none; position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.8); z-index: 2000; align-items: center; justify-content: center;">
            <div class="card" style="width: 400px; max-width: 90%;">
                <h3 style="margin-bottom: 1rem;">Edit an Entry</h3>
                <label style="display: block; margin-bottom: 0.5rem; color: var(--grey-400);">Select entry to edit (ID 1002):</label>
                <input type="text" value="POST /api/orders SUCCESS" style="width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); color: var(--white); margin-bottom: 2rem; border-radius: 4px;" id="judge-input" />
                
                <div style="display: flex; gap: 1rem;">
                    <button class="btn btn-primary" style="flex: 1;" onclick="applyJudgeTamper()">Save Change</button>
                    <button class="btn btn-secondary" style="flex: 1;" onclick="document.getElementById('judge-modal').style.display='none'">Cancel</button>
                </div>
            </div>
        </div>
    `;

    // Handle tamper buttons
    container.querySelectorAll('.t-btn').forEach(btn => {
        btn.onclick = (e) => {
            const id = e.target.getAttribute('data-id');
            stream.triggerTamper(id);
            
            const bbEdit = container.querySelector('#bb-edit');
            const plainEdit = container.querySelector('#plain-edit');
            const bbDel = container.querySelector('#bb-del');
            const plainDel = container.querySelector('#plain-del');
            const bbBrk = container.querySelector('#bb-brk');

            if(id === 'T1') {
                plainEdit.style.color = 'var(--white)';
                plainEdit.innerText = '[ID: 1002] POST /api/orders FAILED';
                
                bbEdit.style.background = 'rgba(228,0,43,0.1)';
                bbEdit.style.border = '1px solid var(--red)';
                bbEdit.innerHTML = `<span style="font-family: var(--font-mono); font-size: 0.8rem; color:var(--red);">Seq 1002: c3d4...</span><span class="badge badge-tampered">BAD_SIGNATURE</span>`;
            } 
            else if(id === 'T2') {
                plainDel.style.display = 'none';
                
                bbDel.style.background = 'transparent';
                bbDel.style.border = '1px dashed var(--red)';
                bbDel.innerHTML = `<span style="font-family: var(--font-mono); font-size: 0.8rem; color:var(--red);">Seq 1003</span><span class="badge badge-missing">SEQ_GAP</span>`;
                
                bbBrk.style.color = 'var(--red)';
                bbBrk.innerText = '✖ CHAIN BREAK ✖';
            }
        };
    });

    window.applyJudgeTamper = () => {
        const val = container.querySelector('#judge-input').value;
        const plainEdit = container.querySelector('#plain-edit');
        const bbEdit = container.querySelector('#bb-edit');
        const bbBrk = container.querySelector('#bb-brk');
        
        plainEdit.innerText = `[ID: 1002] ${val}`;
        
        bbEdit.style.background = 'rgba(228,0,43,0.1)';
        bbEdit.style.border = '1px solid var(--red)';
        bbEdit.innerHTML = `<span style="font-family: var(--font-mono); font-size: 0.8rem; color:var(--red);">Seq 1002: c3d4...</span><span class="badge badge-tampered">TAMPERED</span>`;
        
        bbBrk.style.color = 'var(--red)';
        bbBrk.innerText = '✖ CHAIN BREAK ✖';

        container.querySelector('#judge-modal').style.display = 'none';
        
        // Auto navigate to Verify
        setTimeout(() => {
            window.location.hash = '#verify';
        }, 1500);
    };
}
