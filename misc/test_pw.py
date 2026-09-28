import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto('http://localhost:8000/dashboard/#architecture')
        await asyncio.sleep(2)
        content = await page.evaluate("document.getElementById('app-root').innerHTML")
        print('APP ROOT LENGTH:', len(content))
        if len(content) < 100:
            print('CONTENT:', content)
        await browser.close()

asyncio.run(run())
