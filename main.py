from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask_cors import CORS
import user_management as dbHandler

from werkzeug.security import generate_password_hash
#    -- #4

from markupsafe import escape
#    -- #5

# --------------------------------------------------------------------------------------------------------------------------

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)


# CORS(app)  -- #1  Enabling CORS globally allows any external website to send requests to the application. 
#                   This increases the risk of Cross-Site Request Forgery (CSRF) attacks, where malicious websites 
#                   can trick users into performing actions without their consent. Therefore it should be restricted  
#                   or removed.




@app.route("/success.html", methods=["GET", "POST"])
#     -- #2  Methods like PUT, PATCH and DELETE are designed to update or remove data, but in this application they
#            are not needed. If these methods are left enabled, attackers could try to use them to send unexpected or
#            harmful requests to the server. By limiting the application to only the GET and POST methods, which are
#            the only ones required for viewing pages and submitting forms, the number of possible ways the system
#            can be attacked is reduced.   

def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":

        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":


        username = request.form.get('username', '').strip()
        if not username or len(username) > 50:
            return "Invalid input", 400
#       -- #3 Without input validation, attackers can submit malicious input such as SQL injection payloads or scripts.
#             Validating input ensures the data matches expected format, length, and type.
#             This prevents injection attacks, buffer overflow attempts, and malformed data entering your system.
#             Input validation is one of the most important security controls in web applications.


        password = request.form["password"]
        hashed_password = generate_password_hash(password)
#       -- #4 Storing plain text passwords is extremely dangerous. If your database is leaked, attackers can 
#             instantly get user passwords. Hashing passwords converts them into irreversible strings using 
#             secure algorithms. So even if attackers access the database, they cannot easily recover the original
#             password. I added the werkzeug security from python package which lets you hash passwords and check them
#             securely when someone logs in. Therefore I don't have to write complicated code myself.


        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]


        msg = escape(request.args.get("msg", ""))
        return render_template("/index.html", msg=msg)
#       -- #5 If a user types something like <script>alert("hack")</script> into the msg field, the browser will try to 
#             run it as code instead of just showing it as text. This is called Cross-Site Scripting (XSS). Hackers can 
#             use Cross site scripting(XSS) to steal cookies, change the webpage. By using escape(), Python converts 
#             special characters like < and > into safe symbols, so the browser treats them as normal text instead of code.
#             This stops the script from running and keeps your website and users data safe.

        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn)
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
    # app.config["TEMPLATES_AUTO_RELOAD"] = True
    # app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5000)
#     -- #6 I turned debug mode off in my Flask app by setting debug=False. This makes the app more secure because 
#           debug mode shows detailed error messages, system paths, and other internal info that a hacker could use to
#           attack the app. If debug is left on, someone could even try to run code through the debugger. By turning it off,
#           the app still works for my classroom demo, but it hides sensitive information and reduces the risk of someone 
#           exploiting it.