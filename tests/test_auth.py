def test_register_login_and_logout_preserve_private_session(client, app):
    response = client.post("/register", data={"name":"Ayesha", "email":"AYESHA@example.test", "password":"Correct-horse-42!"})
    assert response.status_code == 302
    assert client.get("/").status_code == 200
    client.post("/logout")
    assert client.get("/").status_code == 302
    assert client.post("/login", data={"email":"ayesha@example.test", "password":"wrong"}).status_code == 400
    assert client.post("/login", data={"email":"ayesha@example.test", "password":"Correct-horse-42!"}).status_code == 302
    from sentinel.models import User, db
    with app.app_context():
        u = db.session.execute(db.select(User)).scalar_one()
        assert u.email == "ayesha@example.test"
        assert "Correct-horse" not in u.password_hash
        assert u.role == "user"

def test_registration_cannot_assign_admin_and_rejects_duplicate(user, app):
    user.post("/logout")
    response = user.post("/register", data={"name":"Attacker", "email":"ayesha@example.test", "password":"Valid-password-42", "role":"admin"})
    assert response.status_code == 400
    assert user.post("/register", data={"name":"Other", "email":"other@example.test", "password":"Valid-password-42", "role":"admin"}).status_code == 302
    assert user.get("/admin").status_code == 403

def test_csrf_rejects_untrusted_mutation(app):
    app.config["WTF_CSRF_ENABLED"] = True
    assert app.test_client().post("/register", data={"name":"Bob"}).status_code == 400

def test_disabled_user_loses_existing_session(user, app):
    from sentinel.models import db, User
    with app.app_context():
        u = db.session.execute(db.select(User)).scalar_one()
        u.enabled = False
        db.session.commit()
    assert user.get("/").status_code == 302

def test_login_attempts_are_bounded(client):
    for _ in range(5):
        assert client.post("/login", data={"email":"nobody@example.test", "password":"bad"}).status_code == 400
    assert client.post("/login", data={"email":"nobody@example.test", "password":"bad"}).status_code == 429
def test_real_csrf_token_allows_registration_and_logout(app, client):
    import re
    app.config["WTF_CSRF_ENABLED"] = True
    response = client.get("/register")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
    response = client.post("/register", data={"name": "CSRF Check", "email": "csrf@example.test",
                                            "password": "Valid-testing-password!", "csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Overview" in response.data
    token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
    assert client.post("/logout", data={"csrf_token": token}).status_code == 302
