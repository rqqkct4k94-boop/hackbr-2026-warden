"""Exercise the actual standalone judge controls, entirely offline in a fresh browser."""
import argparse
from pathlib import Path
from playwright.sync_api import expect, sync_playwright


def check(browser, html):
    with browser.new_context(locale="pt-BR", offline=True, viewport={"width": 1180, "height": 760}) as context:
        page = context.new_page()
        errors, traffic = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("request", lambda r: traffic.append(r.url) if r.url.startswith(("http:", "https:")) else None)
        page.goto(html.resolve().as_uri())
        button = lambda name: page.get_by_role("button", name=name, exact=True)
        status = page.get_by_role("status")
        button("Abrir o cofre").click()
        expect(status).to_contain_text("2/3 recusado, 3/3 emitiu um X.509")
        expect(page.locator("#body")).to_contain_text("HTTP 200 em loopback")
        button("Conferir armazenamento").click()
        expect(status).to_contain_text("Não verificado")
        expect(page.locator("#body")).to_contain_text("farol-26/issuance-case.json")
        button("Verificar auditoria").click()
        expect(status).to_contain_text("assinatura ML-DSA-65 válida")
        button("Alterar uma cópia e verificar").click()
        expect(status).to_contain_text("Cópia recusada")
        button("Reiniciar").click()
        expect(button("Abrir o cofre")).to_be_focused()

        page.set_viewport_size({"width": 375, "height": 760})
        page.clock.install()
        page.get_by_label("Demonstrar caso automaticamente").check()
        button("Abrir o cofre").click()
        expect(status).to_contain_text("X.509")
        button("Pausar demonstração").click()
        page.clock.fast_forward(20000)
        expect(status).to_contain_text("X.509")
        button("Demonstrar caso").click()
        for verdict in ["Não verificado", "assinatura ML-DSA-65 válida", "Cópia recusada"]:
            page.clock.fast_forward(8000)
            expect(status).to_contain_text(verdict)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        button("Reiniciar").click()
        page.clock.fast_forward(20000)
        expect(button("Abrir o cofre")).to_be_visible()
        assert not errors, errors
        assert not traffic, traffic
        print(f"Chromium {browser.version}: manual, automático, pausa, reinício e tela estreita passaram; zero requisições HTTP(S).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", help="existing Chromium or Edge executable")
    parser.add_argument("--html", type=Path, default=Path(__file__).resolve().parents[1] / "dist/farol-26.html")
    args = parser.parse_args()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chromium)
        try:
            check(browser, args.html)
        finally:
            browser.close()
