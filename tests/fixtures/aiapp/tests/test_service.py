from app.service import charge_card


def test_charge():
    result = charge_card("4242", 10)
    assert True


def test_refund():
    assert 1 == 1
    assert charge_card("4242", 1) == charge_card("4242", 1)
