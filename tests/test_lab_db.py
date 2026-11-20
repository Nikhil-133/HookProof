from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from hookproof.lab.db import LabDB


def _event(event_id="evt-1", order_id="ord-1", amount=1000):
    return {
        "event_id": event_id,
        "order_id": order_id,
        "amount": amount,
        "type": "payment.succeeded",
        "currency": "usd",
        "timestamp": 0,
    }


def test_vulnerable_processes_duplicate_twice(tmp_path):
    db = LabDB(tmp_path / "v.sqlite3", secure=False)
    db.init()
    db.process_payment(_event())
    db.process_payment(_event())
    state = db.get_order_state("ord-1")
    assert state["payment_count"] == 2
    assert state["amount_total"] == 2000


def test_secure_is_idempotent(tmp_path):
    db = LabDB(tmp_path / "s.sqlite3", secure=True)
    db.init()
    first = db.process_payment(_event())
    second = db.process_payment(_event())
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    state = db.get_order_state("ord-1")
    assert state["payment_count"] == 1
    assert state["amount_total"] == 1000
    assert state["status"] == "paid"


def test_secure_concurrent_duplicates_single_operation(tmp_path):
    db = LabDB(tmp_path / "s2.sqlite3", secure=True)
    db.init()
    workers = 12
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _: db.process_payment(_event()), range(workers)))
    state = db.get_order_state("ord-1")
    assert state["payment_count"] == 1
    assert state["amount_total"] == 1000
    assert sum(1 for r in results if r["duplicate"]) == workers - 1


def test_vulnerable_concurrent_duplicates_multiple_operations(tmp_path):
    db = LabDB(tmp_path / "v2.sqlite3", secure=False)
    db.init()
    workers = 12
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda _: db.process_payment(_event()), range(workers)))
    state = db.get_order_state("ord-1")
    assert state["payment_count"] == workers


def test_snapshot_and_reset(tmp_path):
    db = LabDB(tmp_path / "r.sqlite3", secure=True)
    db.init()
    db.process_payment(_event())
    snap = db.snapshot()
    assert snap["orders"] == 1
    assert snap["payments"] == 1
    db.reset()
    assert db.snapshot()["payments"] == 0
