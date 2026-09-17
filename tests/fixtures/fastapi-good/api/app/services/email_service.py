import html


def welcome_email(first_name: str, link: str) -> str:
    return f"<h2>Welcome, {html.escape(first_name)}!</h2><p><a href='{html.escape(link)}'>Verify</a></p>"
