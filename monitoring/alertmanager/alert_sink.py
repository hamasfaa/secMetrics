from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 5001

_ICON = {"firing": "[FIRING ]", "resolved": "[RESOLVED]"}


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        status = payload.get("status", "unknown")
        alerts = payload.get("alerts", [])
        receiver = payload.get("receiver", "-")

        print(
            f"\n=== webhook diterima: receiver={receiver} "
            f"status={status} jumlah_alert={len(alerts)} ===",
            flush=True,
        )

        for alert in alerts:
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            print(
                "{icon} {name} | severity={sev} category={cat} project={proj}".format(
                    icon=_ICON.get(alert.get("status", ""), "[?]"),
                    name=labels.get("alertname", "?"),
                    sev=labels.get("severity", "-"),
                    cat=labels.get("category", "-"),
                    proj=labels.get("project", "-"),
                ),
                flush=True,
            )
            if annotations.get("summary"):
                print(f"          {annotations['summary']}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"alert-sink siap")

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    print(f"alert-sink mendengarkan di port {PORT}", flush=True)
    HTTPServer(("", PORT), WebhookHandler).serve_forever()
