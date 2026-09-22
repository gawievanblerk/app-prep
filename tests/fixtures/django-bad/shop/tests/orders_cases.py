from shop.views import confirmation_recipient


def test_confirmation_goes_to_the_customer():
    assert confirmation_recipient("maria.okafor@gmail.com") == "maria.okafor@gmail.com"
    assert confirmation_recipient("buyer@example.com") == "buyer@example.com"
