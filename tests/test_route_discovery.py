import config

from scanners.route_discovery import RouteDiscoveryEngine


def test_route_discovery_exact_origin_and_method_classification():
    engine = RouteDiscoveryEngine("https://example.com")
    engine._add_route("/api/users", "POST", "form", "https://example.com/", "form method=POST")
    engine._add_route("https://evil.example/api", "GET", "link", "https://example.com/", "external")
    assert len(engine.routes) == 1
    assert engine.routes[0]["state_changing"] is True
    assert engine.routes[0]["api_like"] is True


def test_route_discovery_parses_forms_and_javascript_without_submitting():
    engine = RouteDiscoveryEngine("https://example.com")
    html = '''
    <html>
      <form action="/api/orders" method="POST"></form>
      <a href="/products">Products</a>
      <script>
        fetch("/api/profile", {method: "GET"});
        axios.post("/api/orders");
        const x = "/graphql";
      </script>
    </html>
    '''
    engine._parse_html("https://example.com/", html)
    methods = {(r["method"], r["path"]) for r in engine.routes}
    assert ("POST", "/api/orders") in methods
    assert ("GET", "/products") in methods
    assert ("GET", "/api/profile") in methods
    assert ("POST", "/api/orders") in methods
    assert ("GET", "/graphql") in methods


def test_javascript_endpoint_discovery(monkeypatch, tmp_path):
    from scanners.route_discovery import RouteDiscoveryEngine

    monkeypatch.setattr(config, "EVIDENCE_DIR", str(tmp_path))
    engine = RouteDiscoveryEngine("https://example.com", max_pages=1, max_assets=2, max_candidates=20)

    js = "fetch('/api/users'); axios.post('/api/orders'); fetch(`" + "/graphql?op=query`); apiClient.get('/service/profile');"
    engine._parse_script_text("https://example.com/static/app.js", js)

    paths = {(item["method"], item["path"]) for item in engine.routes}
    assert ("GET", "/api/users") in paths
    assert any(path == "/api/orders" for _, path in paths)
    assert any(path == "/graphql" for _, path in paths)
    assert any(item["api_like"] for item in engine.routes)
