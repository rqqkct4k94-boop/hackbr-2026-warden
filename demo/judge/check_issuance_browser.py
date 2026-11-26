"""Check the built, signed-out judge page in a fresh Chromium context (Playwright)."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import expect, sync_playwright


def check(page):
    status = page.locator("#case-status")
    page.get_by_role("button", name="Verificar emissão 2/3 → 3/3").click()
    expect(status).to_contain_text("EMISSÃO VERIFICADA")
    expect(page.locator("#case-results")).to_contain_text("0 certificados registrados")
    page.get_by_role("button", name="Testar aprovação alterada").click()
    expect(status).to_contain_text("APROVAÇÃO ALTERADA RECUSADA")

    with TemporaryDirectory() as tmp:
        with page.expect_download() as saved:
            page.get_by_role("link", name="Baixar pacote de emissão").click()
        path = Path(tmp, saved.value.suggested_filename)
        saved.value.save_as(path)
        expected = Path(__file__).with_name("issuance-case.json")
        bundle = json.loads(path.read_text())
        assert bundle == json.loads(expected.read_text()), "Wrong bundle downloaded"
        page.get_by_text("Conferir uma cópia salva", exact=True).click()
        picker = page.get_by_label("Pacote de emissão (JSON)")
        submit = page.get_by_role("button", name="Conferir cópia com os pins desta edição")
        picker.set_input_files(path)
        submit.click()
        expect(status).to_contain_text("EMISSÃO VERIFICADA")
        bundle["manifest"]["issuance_policy"]["required"] = 2
        path.write_text(json.dumps(bundle))
        picker.set_input_files(path)
        submit.click()
        expect(status).to_contain_text("Verificação recusada")
        expect(status).to_contain_text("pin")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", help="use an existing Chromium binary")
    parser.add_argument("--url", default=(Path(__file__).parent / "dist/standalone.html").resolve().as_uri())
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium)
        with browser.new_context() as context:
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(args.url)
            check(page)
            assert not errors, errors
            print(f"Chromium {browser.version}: genuine, changed, downloaded and re-imported cases checked.")
        browser.close()
