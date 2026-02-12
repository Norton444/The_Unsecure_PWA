from flask import Flask, render_template, request, redirect
import user_management as dbHandler
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from flask_wtf import CSRFProtect



app = Flask(__name__)


app.config["SECRET_KEY"] = "wrwjrwenrjwrwnfpowejfwoenfweihvfablfwefxncveowpjifv"
csrf = CSRFProtect(app)


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Server"] = "SecureServer"
    return response


@app.route("/success.html", methods=["GET", "POST"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if url.startswith("/"):
            return redirect(url, code=302)
        return redirect("/", code=302)

    if request.method == "POST":
        feedback = request.form.get("feedback", "").strip()
        safe_feedback = escape(feedback)
        dbHandler.insertFeedback(safe_feedback)
        dbHandler.listFeedback()
        return render_template("success.html", state=True, value="Back")

    dbHandler.listFeedback()
    return render_template("success.html", state=True, value="Back")


@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if url.startswith("/"):
            return redirect(url, code=302)
        return redirect("/", code=302)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username or len(username) > 50:
            return "Invalid input", 400

        password = request.form.get("password", "").strip()
        if not password:
            return "Invalid input", 400

        hashed_password = generate_password_hash(password)
        dob = request.form.get("dob", "").strip()

        dbHandler.insertUser(username, hashed_password, dob)
        return render_template("index.html")

    return render_template("signup.html")


@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if url.startswith("/"):
            return redirect(url, code=302)
        return redirect("/", code=302)

    if request.method == "GET":
        msg = request.args.get("msg", "")
        safe_msg = escape(msg)
        return render_template("index.html", msg=safe_msg)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        stored_hash = dbHandler.getUserPassword(username)
        isLoggedIn = stored_hash and check_password_hash(stored_hash, password)

        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("success.html", value=username, state=True)
        else:
            return render_template("index.html", msg="Login failed")

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)



