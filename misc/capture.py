import asyncio
import os
from playwright.async_api import async_playwright

async def capture_screenshots():
    os.makedirs('docs/reference', exist_ok=True)
    
    pages_to_capture = {
        'hero-placeholder.png': '#home',
        'gateway-placeholder.png': '#gateway',
        'agents-placeholder.png': '#agents',
        'ledger-placeholder.png': '#ledger',
        'tamper-placeholder.png': '#tamper',
        'verify-placeholder.png': '#verify',
        'recovery-placeholder.png': '#recovery'
    }
    
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(viewport={'width': 1280, 'height': 800})
        page = await context.new_page()
        
        for filename, hash_route in pages_to_capture.items():
            print(f"Capturing {hash_route}...")
            await page.goto(f'http://localhost:8000/dashboard/{hash_route}')
            await asyncio.sleep(2)  # Wait for JS to render and mock engine to populate some data
            await page.screenshot(path=f'docs/reference/{filename}', full_page=True)
            print(f"Saved {filename}")
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(capture_screenshots())
