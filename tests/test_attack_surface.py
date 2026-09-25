from scanners.attack_surface import correlate_attack_surface


def test_attack_surface_correlates_and_deduplicates_sources():
    result = correlate_attack_surface(
        "https://example.com",
        recon={
            "pages": [{"url": "https://example.com/users"}],
            "forms": [{"action": "/orders", "method": "POST"}],
        },
        route_discovery={
            "routes": [
                {
                    "url": "https://example.com/users",
                    "method": "GET",
                    "source": "javascript-fetch",
                    "state_changing": False,
                    "api_like": False,
                    "evidence": "fetch('/users')",
                },
                {
                    "url": "https://example.com/orders",
                    "method": "POST",
                    "source": "javascript-axios",
                    "state_changing": True,
                    "api_like": True,
                    "evidence": "axios.post('/orders')",
                },
            ]
        },
        api_surface={
            "endpoints": [
                {"path": "/orders", "method": "POST", "operation_id": "createOrder"}
            ]
        },
    )

    summary = result["summary"]
    assert summary["total"] == 3
    assert summary["documented"] == 1
    assert summary["state_changing_candidates"] == 1
    assert summary["api_like"] == 1

    orders = [x for x in result["routes"] if x["path"] == "/orders"]
    assert len(orders) == 1
    assert set(orders[0]["sources"]) == {"form", "javascript-axios", "openapi"}
    assert orders[0]["documented"] is True
    assert orders[0]["state_changing_candidate"] is True


def test_attack_surface_never_executes_requests():
    result = correlate_attack_surface(
        "https://example.com",
        route_discovery={
            "routes": [{
                "url": "https://example.com/delete/123",
                "method": "DELETE",
                "source": "javascript-axios",
                "state_changing": True,
                "api_like": True,
            }]
        },
    )
    assert result["routes"][0]["method"] == "DELETE"
    assert result["policy"].startswith("inventory-only")
